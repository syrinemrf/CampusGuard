"""CampusGuard minimal health/readiness service. Feature endpoints land in S2."""
import os
from contextlib import closing
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify
from pymongo import MongoClient
from redis import Redis

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'local-only-secret')


@app.get('/')
def index():
    return jsonify(application='CampusGuard', engine='Sentinel', phase='S1', status='foundation')


@app.get('/health')
def health():
    return jsonify(status='ok', timestamp=datetime.now(timezone.utc).isoformat())


@app.get('/ready')
def ready():
    status = {}
    try:
        elasticsearch_url = os.getenv(
            'ELASTICSEARCH_URL', 'http://elasticsearch:9200'
        ).rstrip('/')
        response = requests.get(
            f'{elasticsearch_url}/_cluster/health',
            params={
                'wait_for_status': 'yellow',
                'timeout': '2s',
                'master_timeout': '2s',
            },
            timeout=3,
        )
        response.raise_for_status()
        cluster_health = response.json()
        if not isinstance(cluster_health, dict):
            raise ValueError('Invalid Elasticsearch cluster health response')
        if (
                cluster_health.get('status') not in {'yellow', 'green'}
                or cluster_health.get('timed_out') is not False
        ):
            raise ValueError('Elasticsearch cluster is not ready')
        status['elasticsearch'] = 'ok'
    except (requests.RequestException, ValueError):
        status['elasticsearch'] = 'error'
    try:
        with closing(MongoClient(
                os.getenv('MONGO_URI', 'mongodb://mongodb:27017/'),
                serverSelectionTimeoutMS=3000,
        )) as client:
            client.admin.command('ping')
        status['mongodb'] = 'ok'
    except Exception:
        status['mongodb'] = 'error'
    try:
        with closing(Redis.from_url(
                os.getenv('REDIS_URL', 'redis://redis:6379/0'),
                socket_timeout=3,
        )) as client:
            client.ping()
        status['redis'] = 'ok'
    except Exception:
        status['redis'] = 'error'
    healthy = all(v == 'ok' for v in status.values())
    return jsonify(status='ready' if healthy else 'degraded', services=status), (200 if healthy else 503)
