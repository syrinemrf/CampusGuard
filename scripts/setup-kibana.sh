#!/usr/bin/env sh
set -eu

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
DATA_VIEW_FILE="${DATA_VIEW_FILE:-/setup/kibana-data-view.json}"

curl -fsS -X POST "${KIBANA_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: campusguard-setup' \
  -H 'Content-Type: application/json' \
  --data-binary "@${DATA_VIEW_FILE}"
printf '\nKibana data view installed.\n'
