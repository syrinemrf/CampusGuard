#!/usr/bin/env bash
set -euo pipefail
curl -fsS -X PUT "http://localhost:9200/_index_template/campusguard-logs" -H 'Content-Type: application/json' --data-binary @ingestion/elasticsearch/logs-template.json
printf '\nTemplate installed.\n'
