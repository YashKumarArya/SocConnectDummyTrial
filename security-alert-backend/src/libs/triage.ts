// Robust triage poster used by normalization flow

async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  // dynamic import so node-fetch is optional in some environments
  const nf: any = await import('node-fetch');
  return (nf && (nf.default || nf)) as any;
}

import { generateAlphaId } from './alpha_id';

// Simple async semaphore to limit concurrent outbound triage requests
class Semaphore {
  private max: number;
  private current = 0;
  private queue: Array<() => void> = [];
  constructor(max: number) {
    this.max = Math.max(1, max || 5);
  }
  async acquire(): Promise<() => void> {
    if (this.current < this.max) {
      this.current += 1;
      return () => this.release();
    }
    return await new Promise(resolve => {
      this.queue.push(() => {
        this.current += 1;
        resolve(() => this.release());
      });
    });
  }
  private release() {
    this.current = Math.max(0, this.current - 1);
    if (this.queue.length > 0) {
      const fn = this.queue.shift();
      if (fn) fn();
    }
  }
}

const TRIAGE_CONCURRENCY = Number(process.env.TRIAGE_CONCURRENCY || '5');
const triageSemaphore = new Semaphore(TRIAGE_CONCURRENCY);

export async function postTriage(payload: any): Promise<any | null> {
  const requestId = `${String(generateAlphaId(payload))}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2,8)}`;
  const maxRetries = Number(process.env.TRIAGE_MAX_RETRIES || '3');
  const baseBackoffMs = Number(process.env.TRIAGE_BACKOFF_MS || '250');
  const perRequestTimeoutMs = Number(process.env.TRIAGE_TIMEOUT_MS || '10000'); // default 10s

  const release = await triageSemaphore.acquire();
  try {
    const fetchFn = await getFetch();
    const url = process.env.TRIAGE_URL || 'https://043cebff3dba.ngrok-free.app/triage';

    // Build file bytes
    let fileBuffer: Buffer | undefined = undefined;
    if (payload && payload.triage_file_path) {
      try {
        const { readFileSync } = await import('fs');
        fileBuffer = readFileSync(String(payload.triage_file_path));
      } catch (e: any) {
        console.error(`[${requestId}] postTriage: failed to read triage_file_path`, e?.message || e);
      }
    }
    if (fileBuffer === undefined && payload && payload.triage_file_content !== undefined) {
      const val = payload.triage_file_content;
      // If caller provided a Buffer, use it directly
      if (Buffer.isBuffer(val)) {
        fileBuffer = val;
      } else if (typeof val === 'string') {
        fileBuffer = Buffer.from(val);
      } else if (typeof val === 'object') {
        // pretty-print JSON so uploaded file closely matches saved JSON files like 1.json
        fileBuffer = Buffer.from(JSON.stringify(val, null, 2));
      } else {
        fileBuffer = Buffer.from(String(val));
      }
    }
    if (fileBuffer === undefined) {
      fileBuffer = Buffer.from(JSON.stringify(payload || {}));
    }

    // Debug write (best-effort)
    try {
      const { writeFileSync } = await import('fs');
      const idForFile = String(generateAlphaId(payload));
      const outBinPath = `/tmp/triage-out-${idForFile}.bin`;
      const outJsonPath = `/tmp/triage-out-${idForFile}.json`;
      writeFileSync(outBinPath, fileBuffer as Buffer);
      try {
        const text = (fileBuffer as Buffer).toString('utf8');
        JSON.parse(text);
        writeFileSync(outJsonPath, text);
      } catch (e) { /* not JSON, ignore */ }
      console.log(`[${requestId}] postTriage debug: wrote fileBuffer to`, outBinPath, 'byteLength=', Buffer.byteLength(fileBuffer as Buffer));
    } catch (e: any) {
      console.warn(`[${requestId}] postTriage debug: could not write debug files`, e?.message || e);
    }

    // Build multipart using form-data
    const FormDataPkg: any = await import('form-data');
    const FormData = FormDataPkg.default || FormDataPkg;
    const fd = new FormData();
    fd.append('file', fileBuffer as Buffer, {
      filename: payload?.triage_file_name || 'file.json',
      contentType: payload?.triage_file_content_type || 'application/json'
    });

    const includeScalars = process.env.TRIAGE_INCLUDE_SCALARS === '1';
    if (includeScalars) {
      const scalarFields = ['id','alpha_id','file_name','sha256','sha1','file_path','severity_id','threat_name','source_vendor','source_product','event_time'];
      for (const k of scalarFields) {
        const v = (payload as any)[k];
        if (v !== undefined && v !== null) fd.append(k, String(v));
      }
    }

    const headers: any = fd.getHeaders ? fd.getHeaders() : { 'Content-Type': 'multipart/form-data' };
    if (typeof (fd as any).getLength === 'function') {
      try {
        const len: any = await new Promise((resolve, reject) => (fd as any).getLength((err: any, length: any) => (err ? reject(err) : resolve(length))));
        if (len) headers['Content-Length'] = String(len);
      } catch (e: any) {
        console.warn(`[${requestId}] postTriage: could not compute Content-Length for multipart body`, e?.message || e);
      }
    }

    // Helper to perform a single submit attempt with ability to abort on timeout
    async function singleSubmitAttempt(timeoutMs: number): Promise<any> {
      return await new Promise((resolve, reject) => {
        let timedOut = false;
        let req: any = null;
        const onError = (err: any) => {
          if (timedOut) return; // ignore after timeout
          reject(err);
        };

        try {
          req = (fd as any).submit(url, (err: any, resp: any) => {
            if (err) return onError(err);
            const chunks: any[] = [];
            resp.on('data', (c: any) => chunks.push(c));
            resp.on('end', async () => {
              if (timedOut) return; // ignore late response
              const bodyText = Buffer.concat(chunks).toString('utf8');
              try {
                const parsed = JSON.parse(bodyText);
                return resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, bodyText, json: parsed });
              } catch (e) {
                return resolve({ ok: resp.statusCode >= 200 && resp.statusCode < 300, status: resp.statusCode, bodyText, json: null });
              }
            });
            resp.on('error', onError);
          });
        } catch (e) {
          return reject(e);
        }

        // enforce timeout by aborting request
        const to = setTimeout(() => {
          timedOut = true;
          try { if (req && typeof req.abort === 'function') req.abort(); } catch (e) {}
          reject(new Error(`triage request timeout after ${timeoutMs}ms`));
        }, timeoutMs);

        // ensure cleanup when promise settles
        const cleanup = () => clearTimeout(to);
        // attach resolution handlers to clear timeout
        (async () => {
          try {
            const val = await new Promise((res2, rej2) => {});
          } catch (e) {
            // noop: this scaffolding won't run; cleanup handled in callbacks above
          }
          cleanup();
        })();
      });
    }

    // Retry loop with exponential backoff + jitter
    let lastErr: any = null;
    for (let attempt = 0; attempt < Math.max(1, maxRetries); attempt++) {
      const attemptIdx = attempt + 1;
      const attemptTimeout = perRequestTimeoutMs;
      try {
        console.log(`[${requestId}] postTriage attempt ${attemptIdx}/${maxRetries} to ${url}`);
        const res = await Promise.race([
          singleSubmitAttempt(attemptTimeout),
          new Promise((_, rej) => setTimeout(() => rej(new Error('postTriage overall timeout exceeded')), attemptTimeout + 50))
        ]);

        if (!res || !res.ok) {
          const txt = res ? (res.bodyText || '<no body>') : '<no response>';
          lastErr = new Error(`postTriage failed status=${res ? res.status : 'no-resp'} body=${String(txt).slice(0,200)}`);
          console.error(`[${requestId}] ${lastErr.message}`);
        } else {
          // parse response (res.json already if parsed)
          if (res.json) {
            console.log(`[${requestId}] postTriage succeeded`);
            return res.json;
          }
          try {
            const parsed = JSON.parse(res.bodyText || '{}');
            console.log(`[${requestId}] postTriage succeeded (parsed)`);
            return parsed;
          } catch (e) {
            console.warn(`[${requestId}] postTriage: response not JSON`);
            return null;
          }
        }
      } catch (err: any) {
        lastErr = err;
        console.warn(`[${requestId}] postTriage attempt ${attemptIdx} error:`, err?.message || err);
      }

      // backoff before next attempt (if any)
      if (attempt < maxRetries - 1) {
        const jitter = Math.random() * 100;
        const backoff = Math.pow(2, attempt) * baseBackoffMs + jitter;
        await new Promise((r) => setTimeout(r, backoff));
      }
    }

    console.error(`[${requestId}] postTriage all attempts failed:`, lastErr?.message || lastErr);
    return null;
  } catch (err: any) {
    console.error(`[${String(generateAlphaId(payload))}] postTriage fatal error`, err?.message || err);
    return null;
  } finally {
    release();
  }
}
