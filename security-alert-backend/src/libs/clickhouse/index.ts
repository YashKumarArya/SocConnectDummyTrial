export const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL || 'http://localhost:8123';

export const CLICKHOUSE_TIMEOUT_MS = Number(process.env.CLICKHOUSE_TIMEOUT_MS || 30_000);

export default {
  url: CLICKHOUSE_URL,
  timeoutMs: CLICKHOUSE_TIMEOUT_MS
};
