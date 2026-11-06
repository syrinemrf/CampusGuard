"""Shared fixtures for the S2 tests: in-memory MongoDB (mongomock), Redis (fakeredis), fake Elasticsearch."""
import fakeredis
import mongomock
import pytest

from app.config import Config
from app.main import create_app
from app.security import ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR
from app.services.users import UserStore
from app.stores import ElasticError, Stores

PASSWORD = 'correct horse battery'


class FakeES:
    """Records calls and answers from canned data. Never talks to the network."""

    def __init__(self):
        self.searches = []
        self.counts = []
        self.count_value = 0
        self.down = False
        self.response = {'took': 3, 'hits': {'total': {'value': 0, 'relation': 'eq'}, 'hits': []}}
        self.responses = None  # optional list consumed one per search call

    def search(self, index, body):
        if self.down:
            raise ElasticError('Elasticsearch injoignable')
        self.searches.append((index, body))
        if self.responses:
            return self.responses.pop(0)
        return self.response

    def count(self, index, query):
        if self.down:
            raise ElasticError('Elasticsearch injoignable')
        self.counts.append((index, query))
        return self.count_value


def make_hit(i, **over):
    src = {'@timestamp': f'2026-10-30T13:{i % 60:02d}:00.000Z', 'log': {'level': 'WARNING'},
           'service': {'name': 'authentication'}, 'source': {'ip': '203.0.113.50'}, 'user': {'name': 'user_4'},
           'event': {'action': 'login', 'outcome': 'failure', 'category': 'authentication'},
           'message': f'Simulated failed login {i}', 'labels': {'upload_id': 'a' * 32}}
    src.update(over)
    return {'_id': f'doc{i:06d}abc', '_index': 'logs-upload-2026.10.30', '_source': src}


@pytest.fixture
def config(tmp_path):
    return Config(testing=True, secret_key='test-secret', upload_dir=str(tmp_path / 'uploads'),
                  rejected_dir=str(tmp_path / 'rejected'), max_upload_mb=1, search_cache_ttl=30, export_max_rows=2500)


@pytest.fixture
def stores():
    db = mongomock.MongoClient()['sentinel_test']
    return Stores(db=db, redis=fakeredis.FakeRedis(decode_responses=True), es=FakeES())


@pytest.fixture
def app(config, stores):
    return create_app(config, stores)


@pytest.fixture
def users(stores):
    store = UserStore(stores.db)
    store.create('admin', PASSWORD, ROLE_ADMIN)
    store.create('analyste', PASSWORD, ROLE_ANALYST)
    store.create('auditeur', PASSWORD, ROLE_AUDITOR)
    return store


class Session:
    """Thin test client wrapper that logs in through the JSON API and sends the CSRF header."""

    def __init__(self, app, username=None):
        self.client = app.test_client()
        self.csrf = None
        if username:
            self.login(username)

    def login(self, username, password=PASSWORD):
        res = self.client.post('/api/auth/login', json={'username': username, 'password': password})
        if res.status_code == 200:
            self.csrf = res.get_json()['csrf_token']
        return res

    def _h(self, extra=None):
        h = {'X-CSRF-Token': self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def get(self, url, **kw):
        return self.client.get(url, **kw)

    def post(self, url, **kw):
        kw['headers'] = self._h(kw.get('headers'))
        return self.client.post(url, **kw)

    def delete(self, url, **kw):
        kw['headers'] = self._h(kw.get('headers'))
        return self.client.delete(url, **kw)


@pytest.fixture
def make_session(app, users):
    return lambda username=None: Session(app, username)


@pytest.fixture
def analyst(make_session):
    return make_session('analyste')


@pytest.fixture
def admin(make_session):
    return make_session('admin')


@pytest.fixture
def auditor(make_session):
    return make_session('auditeur')
