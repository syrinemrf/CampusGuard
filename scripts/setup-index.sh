#!/usr/bin/env sh
set -eu

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
TEMPLATE_FILE="${TEMPLATE_FILE:-ingestion/elasticsearch/logs-template.json}"

curl -fsS -X PUT "${ELASTICSEARCH_URL}/_index_template/campusguard-logs" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE_FILE}"
printf '\nTemplate installed.\n'

# Keep indices created before a template update aligned with the strict schema.
curl -fsS -X PUT \
  "${ELASTICSEARCH_URL}/logs-*/_mapping?allow_no_indices=true&ignore_unavailable=true" \
  -H 'Content-Type: application/json' \
  --data-binary '{"dynamic":false}'
printf '\nExisting logs-* mappings updated.\n'
