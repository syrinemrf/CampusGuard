#!/usr/bin/env sh
set -eu

ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://localhost:9200}"
TEMPLATE_FILE="${TEMPLATE_FILE:-ingestion/elasticsearch/logs-template.json}"
ALERTS_TEMPLATE_FILE="${ALERTS_TEMPLATE_FILE:-ingestion/elasticsearch/alerts-template.json}"

curl -fsS -X PUT "${ELASTICSEARCH_URL}/_index_template/campusguard-logs" \
  -H 'Content-Type: application/json' \
  --data-binary "@${TEMPLATE_FILE}"
printf '\nTemplate installed.\n'

# S4: alerts raised by the alerting worker (sentinel-alerts-*), read by the Kibana dashboard.
if [ -f "${ALERTS_TEMPLATE_FILE}" ]; then
  curl -fsS -X PUT "${ELASTICSEARCH_URL}/_index_template/campusguard-alerts" \
    -H 'Content-Type: application/json' \
    --data-binary "@${ALERTS_TEMPLATE_FILE}"
  printf '\nAlerts template installed.\n'
fi

# Keep indices created before a template update aligned with the strict schema.
curl -fsS -X PUT \
  "${ELASTICSEARCH_URL}/logs-*/_mapping?allow_no_indices=true&ignore_unavailable=true" \
  -H 'Content-Type: application/json' \
  --data-binary '{"dynamic":false}'
printf '\nExisting logs-* mappings updated.\n'
