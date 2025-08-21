"""Approximate Nearest Neighbor service using hnswlib (replaces faiss to avoid native build issues).
Endpoints:
- POST /build-index    -> build HNSW index from ClickHouse embeddings
- POST /search         -> search the in-memory index with a vector or text
- POST /add-embedding  -> add a single embedding to the index (and optionally persist)
- GET  /health         -> health check

Usage:
  python -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  uvicorn app:app --reload --port 8001

Environment variables:
  CLICKHOUSE_URL (default: http://localhost:8123)
  INDEX_PATH (file path for hnsw index, default: ./hnsw_index.bin)
  META_PATH  (file path for metadata, default: ./hnsw_meta.pkl)

This service uses hnswlib (lightweight ANN), sentence-transformers for text->vector encoding.
"""
from typing import List, Optional, Dict, Any
import os
import json
import time
import pickle

import requests
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# lazy import for heavy deps
try:
    import hnswlib
except Exception:
    hnswlib = None

try:
    from sentence_transformers import SentenceTransformer
except Exception:
    SentenceTransformer = None

CLICKHOUSE_URL = os.environ.get('CLICKHOUSE_URL', 'http://localhost:8123')
INDEX_PATH = os.environ.get('INDEX_PATH', './hnsw_index.bin')
META_PATH = os.environ.get('META_PATH', './hnsw_meta.pkl')

app = FastAPI(title='HNSW Similarity Service')

# In-memory index and metadata
_index = None
_meta: List[Dict[str, Any]] = []
_dimension = None
_encoder = None


class BuildRequest(BaseModel):
    limit: Optional[int] = 10000
    rebuild: Optional[bool] = True


class SearchRequest(BaseModel):
    vector: Optional[List[float]] = None
    text: Optional[str] = None
    top_k: int = 10


class AddEmbeddingRequest(BaseModel):
    alpha_id: str
    alert_id: str
    embedding_id: Optional[str]
    vector: List[float]


def fetch_embeddings_from_clickhouse(limit=10000) -> List[Dict[str, Any]]:
    sql = f"SELECT alpha_id, alert_id, embedding_id, vector, dimension, created_at FROM alerts_embeddings ORDER BY created_at DESC LIMIT {limit} FORMAT JSONEachRow"
    try:
        res = requests.post(CLICKHOUSE_URL, data=sql, timeout=30)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"ClickHouse request failed: {e}")

    if res.status_code != 200:
        raise HTTPException(status_code=502, detail=f"ClickHouse responded {res.status_code}: {res.text}")

    text = res.text.strip()
    if not text:
        return []

    rows = []
    for line in text.split('\n'):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            rows.append(obj)
        except Exception:
            continue
    return rows


def _ensure_hnsw_available():
    if hnswlib is None:
        raise HTTPException(status_code=500, detail='hnswlib not installed (pip install hnswlib)')


def _normalize_vectors(v: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(v, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return v / norms


@app.post('/build-index')
def build_index(req: BuildRequest):
    global _index, _meta, _dimension
    _ensure_hnsw_available()

    rows = fetch_embeddings_from_clickhouse(limit=req.limit)
    if not rows:
        return {'ok': True, 'count': 0, 'message': 'no embeddings found'}

    vectors = []
    meta = []
    for r in rows:
        vec = r.get('vector')
        if not vec:
            continue
        vectors.append(vec)
        meta.append({'alpha_id': r.get('alpha_id'), 'alert_id': r.get('alert_id'), 'embedding_id': r.get('embedding_id'), 'created_at': r.get('created_at')})

    arr = np.array(vectors, dtype='float32')
    if arr.ndim != 2:
        raise HTTPException(status_code=500, detail='unexpected vector shape')

    # normalize to unit length so inner product equals cosine
    arr = _normalize_vectors(arr)
    d = arr.shape[1]
    _dimension = d

    # build hnswlib index using inner product (ip) on normalized vectors
    p = hnswlib.Index(space='ip', dim=d)
    # choose M and ef_construction conservatively for good recall
    M = 16
    ef_construction = 200
    p.init_index(max_elements=len(arr), ef_construction=ef_construction, M=M)
    labels = np.arange(len(arr), dtype=np.int32)
    p.add_items(arr, labels)
    p.set_ef(50)  # ef for query time

    _index = p
    _meta = meta

    # persist
    try:
        p.save_index(INDEX_PATH)
        with open(META_PATH, 'wb') as fh:
            pickle.dump(_meta, fh)
    except Exception as e:
        return {'ok': True, 'count': len(meta), 'warning': f'index built but failed to persist: {e}'}

    return {'ok': True, 'count': len(meta)}


@app.post('/search')
def search(req: SearchRequest):
    global _index, _meta, _encoder, _dimension
    _ensure_hnsw_available()

    if _index is None:
        # try to load from disk
        if os.path.exists(INDEX_PATH) and os.path.exists(META_PATH):
            try:
                # load meta
                with open(META_PATH, 'rb') as fh:
                    _meta = pickle.load(fh)
                # load index
                # we need dimension to init a placeholder index for loading
                # hnswlib can read index and expose dim after reading
                p = hnswlib.Index(space='ip', dim=1)  # temporary dim
                p.load_index(INDEX_PATH)
                _index = p
                _dimension = p.get_max_elements() and p.get_dim() if hasattr(p, 'get_dim') else None
            except Exception as e:
                raise HTTPException(status_code=500, detail=f'failed to load persisted index: {e}')
        else:
            raise HTTPException(status_code=404, detail='index not built')

    query_vec = None
    if req.vector:
        query_vec = np.array(req.vector, dtype='float32')
    elif req.text:
        if SentenceTransformer is None:
            raise HTTPException(status_code=500, detail='sentence-transformers not installed')
        if _encoder is None:
            _encoder = SentenceTransformer('all-MiniLM-L6-v2')
        q = _encoder.encode(req.text, convert_to_numpy=True)
        query_vec = np.array(q, dtype='float32')

    if query_vec is None:
        raise HTTPException(status_code=400, detail='provide vector or text')

    if query_vec.ndim == 1:
        query_vec = query_vec.reshape(1, -1)

    if _dimension and query_vec.shape[1] != _dimension:
        # allow query even if dimension unknown or mismatch handled
        pass

    # normalize
    query_vec = _normalize_vectors(query_vec)

    labels, distances = _index.knn_query(query_vec, k=req.top_k)
    results = []
    for score, idx in zip(distances[0].tolist(), labels[0].tolist()):
        if idx < 0 or idx >= len(_meta):
            continue
        # using 'ip' on normalized vectors, distance is inner product (higher better)
        m = _meta[idx]
        results.append({'score': float(score), 'meta': m})

    return {'ok': True, 'results': results}


@app.post('/add-embedding')
def add_embedding(req: AddEmbeddingRequest):
    global _index, _meta, _dimension
    _ensure_hnsw_available()

    vec = np.array(req.vector, dtype='float32')
    if vec.ndim == 1:
        vec = vec.reshape(1, -1)

    if _index is None:
        # create index lazily
        _dimension = vec.shape[1]
        p = hnswlib.Index(space='ip', dim=_dimension)
        p.init_index(max_elements=1000000, ef_construction=200, M=16)
        p.set_ef(50)
        _index = p
        _meta = []

    if vec.shape[1] != _index.dim:
        # hnswlib index exposes dim via attribute 'dim'
        try:
            dim = _index.dim
        except Exception:
            dim = None
        if dim and vec.shape[1] != dim:
            raise HTTPException(status_code=400, detail=f'vector dimension mismatch: expected {dim}, got {vec.shape[1]}')

    vec = _normalize_vectors(vec)
    label = len(_meta)
    _index.add_items(vec, np.array([label], dtype=np.int32))
    _meta.append({'alpha_id': req.alpha_id, 'alert_id': req.alert_id, 'embedding_id': req.embedding_id or f"local-{len(_meta)+1}", 'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ')})

    # persist to disk
    try:
        _index.save_index(INDEX_PATH)
        with open(META_PATH, 'wb') as fh:
            pickle.dump(_meta, fh)
    except Exception:
        pass

    return {'ok': True, 'count': len(_meta)}


@app.get('/health')
def health():
    return {'ok': True, 'index_present': _index is not None, 'meta_count': len(_meta) if _meta else 0}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('app:app', host='0.0.0.0', port=8001, reload=True)
