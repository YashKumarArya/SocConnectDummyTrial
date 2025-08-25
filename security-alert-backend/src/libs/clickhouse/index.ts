export const CLICKHOUSE_URL = process.env.CLICKHOUSE_URL ;

export const CLICKHOUSE_TIMEOUT_MS = Number(process.env.CLICKHOUSE_TIMEOUT_MS || 30_000);

export const CLICKHOUSE_USER = process.env.CLICKHOUSE_USER ;
export const CLICKHOUSE_PASSWORD = process.env.CLICKHOUSE_PASSWORD ;

export default {
  url: CLICKHOUSE_URL,
  user: CLICKHOUSE_USER,
  password: CLICKHOUSE_PASSWORD,
  timeoutMs: CLICKHOUSE_TIMEOUT_MS
};
