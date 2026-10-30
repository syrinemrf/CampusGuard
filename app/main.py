"""CampusGuard minimal health/readiness service. Feature endpoints land in S2."""
import os
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
        response = requests.get(os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200'), timeout=3)
        response.raise_for_status()
        status['elasticsearch'] = 'ok'
    except (requests.RequestException, ValueError):
        status['elasticsearch'] = 'error'
    try:
        client = MongoClient(os.getenv('MONGO_URI', 'mongodb://mongodb:27017/'), serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
        client.close()
        status['mongodb'] = 'ok'
    except Exception:
        status['mongodb'] = 'error'
    try:
        client = Redis.from_url(os.getenv('REDIS_URL', 'redis://redis:6379/0'), socket_timeout=3)
        client.ping()
        client.close()
        status['redis'] = 'ok'
    except Exception:
        status['redis'] = 'error'
    healthy = all(v == 'ok' for v in status.values())
    return jsonify(status='ready' if healthy else 'degraded', services=status), (200 if healthy else 503)
