// MinIO helper using AWS SDK v3 (S3 compatible)
// Exports: uploadRawAlert, uploadEnrichedAlert, listByAlphaId, getObject

const { S3Client, PutObjectCommand, ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');

const streamToString = async (stream) => {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf8');
};

const s3 = new S3Client({
  endpoint: process.env.MINIO_ENDPOINT || 'http://localhost:9000',
  region: process.env.MINIO_REGION || 'us-east-1',
  credentials: {
    accessKeyId: process.env.MINIO_ACCESS_KEY || 'minioadmin',
    secretAccessKey: process.env.MINIO_SECRET_KEY || 'minioadmin'
  },
  forcePathStyle: true
});

const DEFAULT_BUCKET = process.env.MINIO_BUCKET || 'alerts-raw';

async function uploadRawAlert({ bucket = DEFAULT_BUCKET, alphaId, rawPayload }) {
  if (!alphaId) throw new Error('alphaId is required');
  const id = uuidv4();
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const key = `${alphaId}/raw/${ts}-${id}.json`;
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: JSON.stringify(rawPayload || {}), ContentType: 'application/json' }));
  return { id, key, bucket };
}

/**
 * Upload an enriched alert to the specified bucket in MinIO.
 * @param {{ bucket?: string, alphaId: string, enrichedPayload: object }} options
 * @returns {Promise<{ id: string, key: string, bucket: string }>}
 */
async function uploadEnrichedAlert({ bucket = DEFAULT_BUCKET, alphaId, enrichedPayload }) {
  if (!alphaId) throw new Error('alphaId is required');
  const id = uuidv4();
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const key = `${alphaId}/enriched/${ts}-${id}.json`;
  await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: JSON.stringify(enrichedPayload || {}), ContentType: 'application/json' }));
  return { id, key, bucket };
}

/**
 * List objects in the specified bucket with the given alphaId prefix.
 * @param {{ bucket?: string, alphaId: string, maxKeys?: number }} options
 * @returns {Promise<Array<{ Key: string, Size: number, LastModified: Date }>>}
 */
async function listByAlphaId({ bucket = DEFAULT_BUCKET, alphaId, maxKeys = 1000 }) {
  if (!alphaId) throw new Error('alphaId is required');
  const prefix = `${alphaId}/`;
  const res = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: prefix, MaxKeys: maxKeys }));
  return (res.Contents || []).map(o => ({ Key: o.Key, Size: o.Size, LastModified: new Date(o.LastModified) }));
}

async function getObject({ bucket = DEFAULT_BUCKET, key }) {
  const res = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
  return await streamToString(res.Body);
}

module.exports = { uploadRawAlert, uploadEnrichedAlert, listByAlphaId, getObject };
