#!/usr/bin/env sh
# Installs the Kibana data view, then imports the Sentinel dashboard (3 visualizations + 1 metric + dashboard).
# The data view is mandatory (fails the container); the dashboard import is reported loudly but does not block the stack,
# and scripts/verify_s3.py fails if the objects are missing.
set -eu

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
DATA_VIEW_FILE="${DATA_VIEW_FILE:-/setup/kibana-data-view.json}"
OBJECTS_FILE="${OBJECTS_FILE:-/setup/sentinel-dashboard.ndjson}"

curl -fsS -X POST "${KIBANA_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: campusguard-setup' \
  -H 'Content-Type: application/json' \
  --data-binary "@${DATA_VIEW_FILE}"
printf '\nKibana data view installed.\n'

if [ -f "${OBJECTS_FILE}" ]; then
  RESULT="$(curl -sS -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H 'kbn-xsrf: campusguard-setup' -F "file=@${OBJECTS_FILE}" || true)"
  printf '%s\n' "${RESULT}"
  case "${RESULT}" in
    *'"success":true'*) printf 'Kibana dashboard imported.\n' ;;
    *) printf 'WARNING: KIBANA IMPORT FAILED - run scripts/verify_s3.py and check the message above.\n' ;;
  esac
fi
