"""Connections to MongoDB, Redis and Elasticsearch (lazy: nothing connects at import)."""
import logging
from dataclasses import dataclass
from typing import Any

import requests
from pymongo import ASCENDING, DESCENDING, MongoClient
from redis import Redis

log = logging.getLogger('sentinel.stores')


class ElasticError(Exception):
    """Elasticsearch could not answer; ``status`` is the HTTP status to expose."""

    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


class ElasticClient:
    """Tiny Elasticsearch HTTP client (search, count, ids lookup)."""

    def __init__(self, base_url, timeout=10, http=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.http = http or requests

    def _post(self, path, body):
        try:
            response = self.http.post(
                f'{self.base_url}{path}',
                params={'ignore_unavailable': 'true', 'allow_no_indices': 'true'},
                json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ElasticError(f'Elasticsearch injoignable : {exc.__class__.__name__}') from exc
        if response.status_code == 400:
            raise ElasticError('Requête de recherche refusée par Elasticsearch.', status=400)
        if response.status_code >= 400:
            raise ElasticError(f'Elasticsearch a répondu HTTP {response.status_code}.')
        try:
            return response.json()
        except ValueError as exc:
            raise ElasticError('Réponse Elasticsearch illisible.') from exc

    def search(self, index, body):
        return self._post(f'/{index}/_search', body)

    def count(self, index, query):
        return int(self._post(f'/{index}/_count', {'query': query}).get('count', 0))


@dataclass
class Stores:
    db: Any
    redis: Any
    es: Any


def build_stores(config):
    client = MongoClient(config.mongo_uri, serverSelectionTimeoutMS=3000)
    return Stores(
        db=client[config.mongo_db],
        redis=Redis.from_url(config.redis_url, socket_timeout=3, decode_responses=True),
        es=ElasticClient(config.elasticsearch_url),
    )


def ensure_indexes(db):
    """Create the MongoDB indexes documented in docs/ARCHITECTURE.md (idempotent)."""
    db.users.create_index([('username', ASCENDING)], unique=True)
    db.uploaded_files.create_index([('uploaded_by', ASCENDING), ('created_at', DESCENDING)])
    db.uploaded_files.create_index([('sha256', ASCENDING)])
    db.saved_searches.create_index([('user_id', ASCENDING), ('created_at', DESCENDING)])
    db.audit_actions.create_index([('actor', ASCENDING), ('timestamp', DESCENDING)])
    db.audit_actions.create_index([('action', ASCENDING), ('timestamp', DESCENDING)])
    db.dashboard_prefs.create_index([('username', ASCENDING)], unique=True)
