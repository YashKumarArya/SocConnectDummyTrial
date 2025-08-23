import fs from 'fs';
import path from 'path';

const DLQ_FILE = process.env.WEBHOOK_DLQ_FILE || path.join(process.cwd(), 'webhook-dlq.jsonl');

export async function getFetch() {
  if (typeof fetch !== 'undefined') return (globalThis as any).fetch.bind(globalThis);
  try {
    // @ts-ignore
    const nf: any = await import('node-fetch');
    return (nf && (nf.default || nf)) as any;
  } catch (err) {
    throw new Error('fetch is not available. Please run on Node 18+ or install node-fetch');
  }
}

async function tryPost(url: string, body: any, headers: Record<string, string> = {}, retries = 2) {
  const fetchFn = await getFetch();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const txt = await res.text();
      throw new Error(`webhook ${url} failed ${res.status}: ${txt}`);
    }
    return true;
  } catch (err: any) {
    clearTimeout(timeout);
    if (retries > 0) {
      await new Promise((r) => setTimeout(r, 200 * (3 - retries)));
      return tryPost(url, body, headers, retries - 1);
    }
    throw err;
  }
}

async function appendToDLQ(entry: any) {
  try {
    const line = JSON.stringify(entry) + '\n';
    await fs.promises.appendFile(DLQ_FILE, line, { encoding: 'utf8' });
  } catch (err: any) {
    console.error('failed to append webhook dlq', err?.message || err);
  }
}

export async function sendRawWebhook(payload: any) {
  const url = process.env.OUTBOUND_WEBHOOK_RAW || process.env.OUTBOUND_WEBHOOK_URL;
  if (!url) return false;
  const auth = process.env.OUTBOUND_WEBHOOK_AUTH || undefined;
  const headers: any = {};
  if (auth) headers.Authorization = auth.replace(/^'+|'+$/g, '');
  try {
    await tryPost(url, payload, headers);
    return true;
  } catch (err: any) {
    console.error('sendRawWebhook failed, writing to dlq', err?.message || err);
    await appendToDLQ({ type: 'raw', url, headers, payload, attempts: 0, last_attempt: new Date().toISOString(), next_retry_at: Date.now() });
    return false;
  }
}

export async function sendNormalizedWebhook(payload: any) {
  const url = process.env.OUTBOUND_WEBHOOK_NORMALIZED || process.env.OUTBOUND_WEBHOOK_URL;
  if (!url) return false;
  const auth = process.env.OUTBOUND_WEBHOOK_AUTH || undefined;
  const headers: any = {};
  if (auth) headers.Authorization = auth.replace(/^'+|'+$/g, '');
  try {
    await tryPost(url, payload, headers);
    return true;
  } catch (err: any) {
    console.error('sendNormalizedWebhook failed, writing to dlq', err?.message || err);
    await appendToDLQ({ type: 'normalized', url, headers, payload, attempts: 0, last_attempt: new Date().toISOString(), next_retry_at: Date.now() });
    return false;
  }
}

export { tryPost };

export default { sendRawWebhook, sendNormalizedWebhook };