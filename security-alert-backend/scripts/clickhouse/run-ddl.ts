import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';

dotenv.config();

const { CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD } = process.env;
if (!CLICKHOUSE_URL || !CLICKHOUSE_USER || !CLICKHOUSE_PASSWORD) {
  console.error('Missing CLICKHOUSE_URL / CLICKHOUSE_USER / CLICKHOUSE_PASSWORD in environment');
  process.exit(1);
}

// Resolve DDL path: prefer explicit argv[2], otherwise resolve relative to this script file
const ddlPath = process.argv[2]
  ? path.resolve(process.cwd(), process.argv[2])
  : path.resolve(__dirname, 'ddl_edr_ocsf.sql');
if (!fs.existsSync(ddlPath)) {
  console.error('DDL file not found:', ddlPath);
  process.exit(1);
}

const sql = fs.readFileSync(ddlPath, 'utf8');
// Split into statements on semicolons followed by line-break or EOF. This is simple but works for our DDL file.
const statements = sql
  .split(/;\s*(?=(?:\r?\n|$))/)
  .map(s => s.trim())
  .filter(Boolean);

async function runWithClient() {
  const { ClickHouseClient } = await import('@clickhouse/client');
  // some @clickhouse/client versions use different option names; cast to any to avoid TS type issues
  const client = new ClickHouseClient({
    url: CLICKHOUSE_URL,
    username: CLICKHOUSE_USER,
    password: CLICKHOUSE_PASSWORD
  } as any);

  for (const stmt of statements) {
    console.log('Executing statement:', stmt.split('\n')[0].slice(0,200));
    await client.exec({ query: stmt });
  }
}

async function runWithHttp() {
  const fetchMod = await import('node-fetch');
  const fetch = (fetchMod.default || fetchMod) as any;
  const auth = 'Basic ' + Buffer.from(`${CLICKHOUSE_USER}:${CLICKHOUSE_PASSWORD}`).toString('base64');

  for (const stmt of statements) {
    console.log('POSTing statement:', stmt.split('\n')[0].slice(0,200));
    const res = await fetch(CLICKHOUSE_URL, {
      method: 'POST',
      headers: { 'Authorization': auth, 'Content-Type': 'text/plain' },
      body: stmt
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${text}`);
    }
  }
}

async function main() {
  try {
    console.log('Attempting to run DDL using @clickhouse/client...');
    await runWithClient();
    console.log('DDL applied successfully via @clickhouse/client');
    process.exit(0);
  } catch (err: any) {
    console.warn('@clickhouse/client failed or not installed, falling back to HTTP POST. Reason:', err?.message || err);
    try {
      await runWithHttp();
      console.log('DDL applied successfully via HTTP POST');
      process.exit(0);
    } catch (err2: any) {
      console.error('Failed to apply DDL via HTTP POST:', err2?.message || err2);
      process.exit(1);
    }
  }
}

main().catch(err => { console.error(err); process.exit(1); });
