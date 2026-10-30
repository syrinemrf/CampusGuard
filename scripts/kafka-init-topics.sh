#!/usr/bin/env bash
set -euo pipefail
for topic in logs.honeypot logs.auth logs.sim logs.firewall alerts; do
  docker compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server kafka:9092 --create --if-not-exists --topic "$topic" --partitions 1 --replication-factor 1
 done
