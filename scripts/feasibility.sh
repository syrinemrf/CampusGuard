#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
echo "Date UTC: $STAMP" | tee "reports/feasibility-$STAMP.txt"
echo "Host memory:" | tee -a "reports/feasibility-$STAMP.txt"
free -h | tee -a "reports/feasibility-$STAMP.txt"
echo "Docker containers:" | tee -a "reports/feasibility-$STAMP.txt"
docker compose ps | tee -a "reports/feasibility-$STAMP.txt"
echo "Container resource usage:" | tee -a "reports/feasibility-$STAMP.txt"
docker stats --no-stream --format 'table {{.Name}}\t{{.MemUsage}}\t{{.CPUPerc}}' | tee -a "reports/feasibility-$STAMP.txt"
echo "Optional Kafka feasibility: docker compose --profile stream up -d kafka" | tee -a "reports/feasibility-$STAMP.txt"
echo "NOTE: this script records measurements; human verification of host RAM and 80% threshold is mandatory." | tee -a "reports/feasibility-$STAMP.txt"
