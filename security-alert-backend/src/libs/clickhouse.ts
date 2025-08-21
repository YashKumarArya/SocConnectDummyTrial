// ClickHouse client helpers (stub)
import { config } from '../config';

export async function queryClickhouse(sql: string) {
  // implement query logic (e.g. use @clickhouse/client)
  console.log('QUERY CH (stub):', sql, 'using', config.clickhouseUrl);
  return Promise.resolve([]);
}
