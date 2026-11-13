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


def _reason(response):
    """Short, useful cause of an Elasticsearch 400 (e.g. a syntax error in the user's query)."""
    try:
        error = response.json().get('error', {})
        causes = error.get('root_cause') or [error]
        reason = causes[0].get('reason') or ''
        caused = (error.get('caused_by') or {}).get('reason') or ''
        text = caused if caused and caused not in reason else reason
        return f' : {text[:300]}' if text else ''
    except (ValueError, AttributeError, IndexError, TypeError):
        return ''


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
            raise ElasticError('Requête refusée par Elasticsearch' + _reason(response) + '.', status=400)
        if response.status_code >= 400:
            raise ElasticError(f'Elasticsearch a répondu HTTP {response.status_code}.')
        try:
            return response.json()
        except ValueError as exc:
            raise ElasticError('Réponse Elasticsearch illisible.') from exc

    def search(self, index, body):
        return self._post(f'/{index}/_search', body)

    def index(self, index, doc_id, doc):
        """Create or replace one document (used for the S4 alerts index ``sentinel-alerts-*``)."""
        try:
            response = self.http.put(f'{self.base_url}/{index}/_doc/{doc_id}', json=doc, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ElasticError(f'Elasticsearch injoignable : {exc.__class__.__name__}') from exc
        if response.status_code >= 400:
            raise ElasticError(f'Indexation refusée par Elasticsearch (HTTP {response.status_code}).')
        return True

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
    # S4 — alerting
    db.alerts.create_index([('fingerprint', ASCENDING), ('status', ASCENDING)])
    db.alerts.create_index([('status', ASCENDING), ('triggered_at', DESCENDING)])
    db.alerts.create_index([('rule_id', ASCENDING), ('triggered_at', DESCENDING)])
    db.ip_blocks.create_index([('ip', ASCENDING), ('at', DESCENDING)])
