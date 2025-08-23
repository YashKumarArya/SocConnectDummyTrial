import fs from 'fs';
import path from 'path';
import { tryPost } from '../libs/webhook';

const DLQ_FILE = process.env.WEBHOOK_DLQ_FILE || path.join(process.cwd(), 'webhook-dlq.jsonl');
const POLL_INTERVAL_MS = Number(process.env.WEBHOOK_DLQ_POLL_INTERVAL_MS || 15000);
const MAX_ATTEMPTS = Number(process.env.WEBHOOK_DLQ_MAX_ATTEMPTS || 5);
const BASE_BACKOFF_MS = Number(process.env.WEBHOOK_DLQ_BACKOFF_MS || 2000);

let processing = false;

async function readDLQLines(): Promise<string[]> {
  try {
    const txt = await fs.promises.readFile(DLQ_FILE, { encoding: 'utf8' });
    return txt.split('\n').map((l) => l.trim()).filter(Boolean);
  } catch (err: any) {
    if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) return [];
    console.error('readDLQLines error', err?.message || err);
    return [];
  }
}

async function writeDLQLines(lines: string[]) {
  if (!lines || lines.length === 0) {
    try {
      await fs.promises.unlink(DLQ_FILE);
    } catch (err: any) {
      if (err && err.code !== 'ENOENT') console.error('failed to remove DLQ file', err?.message || err);
    }
    return;
  }
  const body = lines.join('\n') + '\n';
  try {
    await fs.promises.writeFile(DLQ_FILE, body, { encoding: 'utf8' });
  } catch (err: any) {
    console.error('writeDLQLines error', err?.message || err);
  }
}

async function processDLQOnce() {
  const lines = await readDLQLines();
  if (lines.length === 0) return;

  const remaining: string[] = [];

  for (const line of lines) {
    let entry: any;
    try {
      entry = JSON.parse(line);
    } catch (err: any) {
      console.error('invalid dlq line, skipping', err?.message || err);
      // keep the bad line so operator can inspect
      remaining.push(line);
      continue;
    }

    const now = Date.now();
    if (entry.next_retry_at && Number(entry.next_retry_at) > now) {
      remaining.push(JSON.stringify(entry));
      continue;
    }

    try {
      // tryPost(url, body, headers)
      await tryPost(entry.url, entry.payload, entry.headers || {});
      console.log('webhook dlq: delivered', entry.type || 'unknown', entry.url);
    } catch (err: any) {
      entry.attempts = (entry.attempts || 0) + 1;
      entry.last_attempt = new Date().toISOString();
      if (entry.attempts >= MAX_ATTEMPTS) {
        console.error('webhook dlq: giving up after max attempts', entry.url, entry.attempts);
        // Optionally, write to a permanent dead-letter file or notify operator. We'll keep it out of rotation.
        continue;
      }
      const backoff = Math.pow(entry.attempts, 2) * BASE_BACKOFF_MS;
      entry.next_retry_at = Date.now() + backoff;
      console.warn('webhook dlq: retry scheduled', entry.url, 'attempts=', entry.attempts, 'next_in_ms=', backoff);
      remaining.push(JSON.stringify(entry));
    }
  }

  await writeDLQLines(remaining);
}

export async function startWebhookDlqWorker() {
  if (processing) return;
  processing = true;
  console.log('webhook dlq worker starting, poll interval ms=', POLL_INTERVAL_MS, 'dlqFile=', DLQ_FILE);

  // run once immediately
  processDLQOnce().catch((err) => console.error('webhook dlq initial run failed', err?.message || err));

  // schedule periodic runs but avoid overlapping executions
  setInterval(async () => {
    try {
      await processDLQOnce();
    } catch (err) {
      console.error('webhook dlq worker run failed', err);
    }
  }, POLL_INTERVAL_MS);
}
