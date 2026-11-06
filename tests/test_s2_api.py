"""/api/v1 aliases, OpenAPI consistency with the routing table, rate limiting."""
import json

from conftest import make_hit
from app.openapi import build_spec


def spec_routes():
    out = set()
    for path, item in build_spec()['paths'].items():
        for method in item:
            if method in {'get', 'post', 'delete', 'put', 'patch'}:
                out.add((method.upper(), path.replace('{upload_id}', '<upload_id>').replace('{event_id}', '<event_id>')))
    return out


def test_openapi_matches_flask_routing_table(app):
    flask_routes = set()
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith('/api/') and rule.rule != '/api/docs':
            for method in rule.methods - {'HEAD', 'OPTIONS'}:
                flask_routes.add((method, rule.rule))
    documented = spec_routes()
    assert flask_routes - documented == {('GET', '/api/openapi.json')}, 'undocumented API routes'
    assert documented - flask_routes == set(), 'documented routes that do not exist'


def test_openapi_json_is_served_and_structurally_valid(analyst):
    body = analyst.get('/api/openapi.json').get_json()
    assert body['openapi'].startswith('3.') and body['info']['title'] and body['paths']
    for path, item in body['paths'].items():
        for method, op in item.items():
            if method == 'parameters':
                continue
            assert op['responses'], (method, path)
    refs = json.dumps(body).count('#/components/schemas/')
    for name in ('Error', 'SearchResult', 'Stats', 'Hit'):
        assert name in body['components']['schemas']
    assert refs > 0


def test_docs_page_and_assets_are_self_hosted(analyst):
    html = analyst.get('/api/docs').get_data(as_text=True)
    assert '/static/vendor/swagger-ui/swagger-ui-bundle.js' in html and 'cdn' not in html.lower()
    assert analyst.get('/static/js/swagger-init.js').status_code == 200
    assert analyst.get('/static/vendor/swagger-ui/swagger-ui-bundle.js').status_code == 200


def test_v1_logs_files_stats_aliases(analyst, stores):
    stores.es.response = {'took': 2, 'hits': {'total': {'value': 1}, 'hits': [make_hit(1)]}, 'aggregations': {
        'levels': {'buckets': []}, 'services': {'buckets': []}, 'today': {'doc_count': 0}, 'errors': {'doc_count': 0}, 'timeline': {'buckets': []}}}
    logs = analyst.get('/api/v1/logs?level=warning&size=10').get_json()
    assert logs['total'] == 1 and logs['hits'][0]['id'] == 'doc000001abc' and logs['size'] == 10
    assert analyst.get('/api/v1/logs/doc000001abc').get_json()['id'] == 'doc000001abc'
    assert 'uploads' in analyst.get('/api/v1/files').get_json()
    assert 'total' in analyst.get('/api/v1/stats').get_json()
    assert analyst.get('/api/v1/logs?level=LOUD').status_code == 400          # same validation as /api/search


def test_v1_requires_authentication(app):
    for url in ('/api/v1/logs', '/api/v1/files', '/api/v1/stats', '/api/openapi.json'):
        assert app.test_client().get(url).status_code == 401


def test_api_rate_limit_per_user_returns_429_with_retry_after(analyst, config, stores):
    config.api_rate_limit = 5
    stores.es.response = {'hits': {'total': {'value': 0}, 'hits': []}}
    codes = [analyst.get('/api/search?record=0').status_code for _ in range(7)]
    assert codes[:5] == [200] * 5 and codes[5:] == [429, 429]
    res = analyst.get('/api/search?record=0')
    assert res.get_json()['error'] == 'rate_limited' and int(res.headers['Retry-After']) > 0
    assert any(k.startswith('sentinel:ratelimit:user:') for k in stores.redis.keys('*'))


def test_rate_limit_is_independent_per_user_and_skips_pages(make_session, config, stores):
    config.api_rate_limit = 3
    a, b = make_session('analyste'), make_session('admin')
    for _ in range(4):
        a.get('/api/auth/me')
    assert a.get('/api/auth/me').status_code == 429
    assert b.get('/api/auth/me').status_code == 200
    assert a.get('/upload').status_code == 200                                  # HTML pages are not API calls
