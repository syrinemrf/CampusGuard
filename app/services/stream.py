"""État mesuré de la chaîne temps réel, maillon par maillon (page « Sources & chaîne temps réel »).

    sshd (fichier) → Filebeat → Kafka (topic logs.auth) → Logstash (pipeline stream-security)
    → Elasticsearch (logs-ssh-*) → Redis Pub/Sub → WebSocket → navigateur

Chaque maillon est interrogé séparément : quand l'écran « Temps réel » reste vide, cette page dit où la chaîne casse.
Kafka et Filebeat appartiennent au profil Docker « stream » : s'ils ne sont pas lancés, c'est indiqué comme tel.
"""
import json
import socket

import requests

from app import live

STREAM_PIPELINE = 'stream-security'
STREAM_INDEX = 'logs-ssh-*'


def _tcp_open(hostport, timeout=1.0):
    host, _, port = hostport.rpartition(':')
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


class StreamStatus:
    def __init__(self, stores, config, http=None, tcp_open=_tcp_open):
        self.redis, self.es, self.cfg = stores.redis, stores.es, config
        self.http = http or requests
        self.tcp_open = tcp_open

    def filebeat(self):
        try:
            r = self.http.get(f'{self.cfg.filebeat_api_url}/stats', timeout=2)
            r.raise_for_status()
            data = r.json()
        except (requests.RequestException, ValueError):
            return {'status': 'absent', 'detail': 'non lancé (profil stream) ou injoignable'}
        events = data.get('libbeat', {}).get('output', {}).get('events', {})
        return {'status': 'ok', 'published': events.get('acked', 0), 'failed': events.get('failed', 0),
                'detail': f"{events.get('acked', 0)} ligne(s) remises à Kafka"}

    def kafka(self):
        if self.tcp_open(self.cfg.kafka_bootstrap):
            return {'status': 'ok', 'detail': f'{self.cfg.kafka_bootstrap} joignable, topic logs.auth'}
        return {'status': 'absent', 'detail': 'non lancé : docker compose --profile stream up -d'}

    def logstash(self):
        try:
            r = self.http.get(f'{self.cfg.logstash_api_url}/_node/stats/pipelines/{STREAM_PIPELINE}', timeout=2)
            r.raise_for_status()
            p = r.json().get('pipelines', {}).get(STREAM_PIPELINE, {})
        except (requests.RequestException, ValueError):
            return {'status': 'error', 'detail': 'API Logstash injoignable'}
        ev = p.get('events', {})
        inputs = {pl.get('id'): pl.get('events', {}).get('out', 0) for pl in p.get('plugins', {}).get('inputs', [])}
        return {'status': 'ok', 'in': ev.get('in', 0), 'out': ev.get('out', 0),
                'kafka_in': inputs.get('kafka_logs_auth', 0), 'tcp_in': inputs.get('tcp_raw_syslog', 0),
                'detail': f"{ev.get('out', 0)} événement(s) écrits (Kafka {inputs.get('kafka_logs_auth', 0)}, "
                          f"TCP {inputs.get('tcp_raw_syslog', 0)})"}

    def elasticsearch(self):
        try:
            raw = self.es.search(STREAM_INDEX, {'size': 0, 'track_total_hits': True, 'aggs': {
                'newest': {'max': {'field': '@timestamp'}},
                'last5m': {'filter': {'range': {'@timestamp': {'gte': 'now-5m'}}}}}})
        except Exception:  # noqa: BLE001 - index absent ou ES arrêté
            return {'status': 'error', 'detail': 'index logs-ssh-* absent ou Elasticsearch injoignable'}
        total = raw.get('hits', {}).get('total', {})
        total = total.get('value', 0) if isinstance(total, dict) else int(total or 0)
        aggs = raw.get('aggregations', {})
        return {'status': 'ok' if total else 'idle', 'documents': total,
                'last5m': aggs.get('last5m', {}).get('doc_count', 0),
                'newest': aggs.get('newest', {}).get('value_as_string'),
                'detail': f"{total} document(s), {aggs.get('last5m', {}).get('doc_count', 0)} ces 5 dernières minutes"}

    def redis_bus(self):
        try:
            subs = dict(self.redis.pubsub_numsub(live.LOGS_CHANNEL, live.ALERTS_CHANNEL))
            subs = {(k.decode() if isinstance(k, bytes) else k): int(v) for k, v in subs.items()}
            lat = [int(x) for x in self.redis.lrange(live.LATENCY_KEY, 0, 999)]
        except Exception:  # noqa: BLE001
            return {'status': 'error', 'detail': 'Redis injoignable'}, []
        n = subs.get(live.LOGS_CHANNEL, 0)
        return {'status': 'ok', 'subscribers': n, 'detail': f'{n} abonné(s) au canal des logs'}, lat

    def build(self):
        bus, lat = self.redis_bus()
        chain = [
            {'key': 'filebeat', 'label': 'Filebeat', 'role': 'lit le journal sshd (tail -f)', **self.filebeat()},
            {'key': 'kafka', 'label': 'Kafka', 'role': 'tampon durable entre collecte et traitement', **self.kafka()},
            {'key': 'logstash', 'label': 'Logstash', 'role': 'parse, classe, géolocalise', **self.logstash()},
            {'key': 'elasticsearch', 'label': 'Elasticsearch', 'role': 'indexe (logs-ssh-*)', **self.elasticsearch()},
            {'key': 'redis', 'label': 'Redis Pub/Sub', 'role': 'diffuse aux écrans ouverts', **bus},
        ]
        metrics = live.platform_metrics(self.redis)
        latency = {'samples': len(lat), 'p50_ms': live.percentile(lat, .5), 'p95_ms': live.percentile(lat, .95),
                   'max_ms': max(lat) if lat else None, 'under_1s_pct': round(100 * sum(1 for x in lat if x < 1000) / len(lat), 1) if lat else None}
        return {'chain': chain, 'latency': latency, 'metrics': metrics,
                'kafka_mode': chain[1]['status'] == 'ok'}


def to_json(data):
    return json.dumps(data, ensure_ascii=False)
