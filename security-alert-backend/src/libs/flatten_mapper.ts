import { readFileSync } from 'fs';
import path from 'path';

// Build a mapping from dot-path (as used in raw flattened alerts) to ClickHouse column name
export function buildDotToColumnMap(): Record<string, string> {
  try {
    const ddlPath = path.join(process.cwd(), 'scripts', 'ddl', '02_alerts_normalized.sql');
    const txt = readFileSync(ddlPath, 'utf8');
    const map: Record<string, string> = {};
    // match lines like: file_path Nullable(String) COMMENT 'dot: file.path',
    const re = /^(\s*)([A-Za-z0-9_]+)\s+[^\n]*COMMENT\s+'dot:\s*([^']+)'/gm;
    let m: RegExpExecArray | null;
    while ((m = re.exec(txt)) !== null) {
      const col = m[2];
      const dot = m[3];
      if (col && dot) map[dot.trim()] = col.trim();
    }
    return map;
  } catch (e) {
    // best-effort: return empty mapping if DDL not present
    return {};
  }
}

export function mapFlatToSnake(flat: Record<string, any>): Record<string, any> {
  const dotToCol = buildDotToColumnMap();
  const out: Record<string, any> = {};
  for (const [k, v] of Object.entries(flat)) {
    // prefer explicit mapping from DDL comments
    if (k in dotToCol) {
      out[dotToCol[k]] = v;
      continue;
    }

    // fallback: convert dot notation to snake_case-like key
    let key = String(k);
    // convert indices: enrichments[1] -> enrichments_1
    key = key.replace(/\[(\d+)\]/g, '_$1');
    // replace dots and dashes with underscores
    key = key.replace(/[.\-]/g, '_');
    // collapse multiple underscores
    key = key.replace(/__+/g, '_');
    // trim leading/trailing underscores
    key = key.replace(/^_+|_+$/g, '');
    key = key.toLowerCase();

    out[key] = v;
  }
  return out;
}
