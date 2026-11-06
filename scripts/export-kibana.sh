#!/usr/bin/env sh
# Re-exports the Sentinel dashboard and its dependencies from a running Kibana (round-trip proof of re-importability).
#   sh scripts/export-kibana.sh [http://localhost:5601] [output.ndjson]
set -eu
KIBANA_URL="${1:-http://localhost:5601}"
OUT="${2:-ingestion/kibana/sentinel-dashboard.exported.ndjson}"
curl -fsS -X POST "${KIBANA_URL}/api/saved_objects/_export" \
  -H 'kbn-xsrf: campusguard-export' -H 'Content-Type: application/json' \
  -d '{"objects":[{"type":"dashboard","id":"sentinel-security-overview"}],"includeReferencesDeep":true}' -o "${OUT}"
echo "Exported to ${OUT}"
