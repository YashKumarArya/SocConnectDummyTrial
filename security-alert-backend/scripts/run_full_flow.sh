#!/usr/bin/env zsh
set -euo pipefail

# Usage: ./scripts/run_full_flow.sh [alert_json_file]
# Environment:
#  - BASE_URL (default http://localhost:3000)
#  - CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD
# Example: BASE_URL=http://localhost:3000 CLICKHOUSE_URL=http://127.0.0.1:8123 CLICKHOUSE_USER=default CLICKHOUSE_PASSWORD= pass ./scripts/run_full_flow.sh

ALERT_FILE=${1:-$(dirname "$0")/sample_alert.json}
BASE_URL=${BASE_URL:-http://localhost:3000}
CH_URL=${CLICKHOUSE_URL:-http://127.0.0.1:8123}
CH_USER=${CLICKHOUSE_USER:-default}
CH_PASS=${CLICKHOUSE_PASSWORD:-}

if [[ ! -f "$ALERT_FILE" ]]; then
  echo "Alert file not found: $ALERT_FILE"
  exit 2
fi

echo "Using alert file: $ALERT_FILE"
echo "Server base URL: $BASE_URL"
echo "ClickHouse URL: $CH_URL"

# 1) POST raw alert
echo "\n==> Posting raw alert to $BASE_URL/api/ingestion/raw"
resp=$(curl -s -X POST "$BASE_URL/api/ingestion/raw" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: run_full_flow_$(date +%s)" \
  --data-binary "@$ALERT_FILE")

if [[ -z "$resp" ]]; then
  echo "No response from ingestion endpoint. Exiting."
  exit 3
fi

echo "Ingestion response: $resp"

# Try to extract alpha_id from common fields
alpha_id=$(echo "$resp" | jq -r '.alpha_id // .id // .data.alpha_id // .alphaId // empty')
if [[ -z "$alpha_id" || "$alpha_id" == "null" ]]; then
  echo "Failed to extract alpha_id from ingestion response. Please inspect response above." 
  exit 4
fi

echo "Extracted alpha_id: $alpha_id"

# 2) Trigger normalization
echo "\n==> Triggering normalization: POST $BASE_URL/api/normalization/normalize/trigger/$alpha_id"
trigger_resp=$(curl -s -X POST "$BASE_URL/api/normalization/normalize/trigger/$alpha_id")
echo "Trigger response: $trigger_resp"

# 3) Poll ClickHouse for normalized row
echo "\n==> Polling ClickHouse for normalized row (soc.edr_alerts_ocsf) for alpha_id=$alpha_id"
max_retries=20
attempt=0
found=0

while [[ $attempt -lt $max_retries ]]; do
  attempt=$((attempt+1))
  echo "Attempt $attempt/$max_retries..."
  sql_count="SELECT count() FROM soc.edr_alerts_ocsf WHERE alpha_id='${alpha_id}'"

  if [[ -n "$CH_PASS" ]]; then
    count=$(curl -s -u "$CH_USER:$CH_PASS" -d "$sql_count" "$CH_URL" | tr -d '\n')
  else
    count=$(curl -s -u "$CH_USER:" -d "$sql_count" "$CH_URL" | tr -d '\n')
  fi

  # clickhouse may return a number or an error message; try to extract integer
  count_num=$(echo "$count" | tr -cd '[0-9]')
  if [[ -n "$count_num" && "$count_num" != "" && "$count_num" != "0" ]]; then
    echo "Found $count_num rows in ClickHouse for alpha_id=$alpha_id"
    found=1
    break
  fi

  echo "Not found yet. Sleeping 3s..."
  sleep 3
done

if [[ $found -eq 0 ]]; then
  echo "Timed out waiting for normalized row to appear in ClickHouse. Last ClickHouse response: $count"
  exit 5
fi

# 4) Fetch the normalized row
echo "\n==> Fetching normalized row from ClickHouse"
sql_fetch="SELECT * FROM soc.edr_alerts_ocsf WHERE alpha_id='${alpha_id}' LIMIT 1 FORMAT JSONEachRow"
if [[ -n "$CH_PASS" ]]; then
  row=$(curl -s -u "$CH_USER:$CH_PASS" -d "$sql_fetch" "$CH_URL")
else
  row=$(curl -s -u "$CH_USER:" -d "$sql_fetch" "$CH_URL")
fi

echo "Normalized row:\n$row"

echo "\n==> Done"
exit 0
