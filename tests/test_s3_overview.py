"""Centre de pilotage (home page): KPI comparison, priority IPs, platform health, freshness, dead letters."""
from datetime import datetime, timezone

import pytest
import requests

from app.main import sparkline_points
from app.services import overview as O


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status
        self.ok = status < 400

    def json(self):
        return self.payload

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(str(self.status_code))


class FakeHTTP:
    def __init__(self, down=False):
        self.down, self.calls = down, []

    def get(self, url, timeout=None):
        self.calls.append(url)
        if self.down:
            raise requests.ConnectionError('down')
        if url.endswith('/_node/stats/pipelines'):
            return FakeResponse({'pipelines': {'csv-security': {'events': {'in': 100, 'out': 100, 'filtered': 100}},
                                               '.monitoring-logstash': {'events': {}},
                                               'upload-security': {'events': {'in': 12, 'out': 11, 'filtered': 12}}}})
        return FakeResponse({'status': {'overall': {'level': 'available'}}})


AUTH = {'hits': {'total': {'value': 70}}, 'aggregations': {
    'cur': {'doc_count': 50, 'outcomes': {'buckets': [{'key': 'success', 'doc_count': 30}, {'key': 'failure', 'doc_count': 20}]},
            'failures': {'doc_count': 20, 'ips': {'value': 3}, 'users': {'value': 6},
                         'top_ips': {'buckets': [
                             {'key': '203.0.113.50', 'doc_count': 15, 'users': {'value': 5},
                              'last': {'value_as_string': '2026-11-13T10:00:00.000Z'}, 'country': {'buckets': []}},
                             {'key': '8.8.8.8', 'doc_count': 5, 'users': {'value': 1},
                              'last': {'value_as_string': '2026-11-13T09:00:00.000Z'}, 'country': {'buckets': [{'key': 'US', 'doc_count': 5}]}}]},
                         'spark': {'buckets': [{'doc_count': n} for n in (0, 2, 5, 13)]}}},
    'prev': {'doc_count': 20, 'outcomes': {'buckets': [{'key': 'success', 'doc_count': 10}, {'key': 'failure', 'doc_count': 10}]},
             'failures': {'doc_count': 10, 'ips': {'value': 3}, 'users': {'value': 2}}}}}

FRESH = {'hits': {'total': {'value': 200}}, 'aggregations': {
    'newest': {'value_as_string': '2026-11-13T11:00:00.000Z'},
    'by_index': {'buckets': [
        {'key': 'logs-auth-2026.11.13', 'doc_count': 40, 'newest': {'value_as_string': '2026-11-13T11:00:00.000Z'},
         'ingested': {'value_as_string': '2026-11-13T11:00:05.000Z'}, 'last24h': {'doc_count': 40}},
        {'key': 'logs-auth-2026.10.30', 'doc_count': 100, 'newest': {'value_as_string': '2026-10-30T13:49:30.000Z'},
         'ingested': {}, 'last24h': {'doc_count': 0}},
        {'key': 'logs-firewall-2026.10.30', 'doc_count': 60, 'newest': {'value_as_string': '2026-10-30T13:49:30.000Z'},
         'ingested': {}, 'last24h': {'doc_count': 0}}]}}}


@pytest.fixture
def http(app):
    fake = FakeHTTP()
    app.extensions['sentinel_http'] = fake
    return fake


def test_auth_query_compares_the_current_and_previous_windows():
    q = O.build_auth_query('7d')
    assert q['query']['range']['@timestamp']['gte'] == 'now-7d-7d'
    assert q['aggs']['cur']['filter']['range']['@timestamp'] == {'gte': 'now-7d'}
    assert q['aggs']['prev']['filter']['range']['@timestamp'] == {'gte': 'now-7d-7d', 'lt': 'now-7d'}
    fails = q['aggs']['cur']['aggs']['failures']
    assert fails['filter'] == {'term': {'event.outcome': 'failure'}}
    assert fails['aggs']['top_ips']['terms'] == {'field': 'source.ip', 'size': 5}


def test_shape_auth_computes_rates_and_deltas():
    data = O.shape_auth(AUTH, '24h')
    k = data['kpis']
    assert k['failures'] == {'value': 20, 'previous': 10, 'delta_pct': 100}
    assert k['success_rate'] == {'value': 60.0, 'previous': 50.0, 'attempts': 50}
    assert k['failing_ips']['delta_pct'] == 0 and k['targeted_users']['delta_pct'] == 200
    assert data['top_ips'][0] == {'ip': '203.0.113.50', 'failures': 15, 'users': 5, 'last': '2026-11-13T10:00:00.000Z', 'country': None}
    assert data['top_ips'][1]['country'] == 'US' and data['spark'] == [0, 2, 5, 13]


def test_no_previous_data_means_no_fake_comparison():
    empty = {'aggregations': {'cur': {'doc_count': 0}, 'prev': {'doc_count': 0}}}
    k = O.shape_auth(empty, '24h')['kpis']
    assert k['failures']['delta_pct'] is None and k['success_rate']['value'] is None


def test_freshness_groups_daily_indices_by_source_and_prefers_ingestion_time():
    now = datetime(2026, 11, 13, 11, 10, 5, tzinfo=timezone.utc)
    data = O.shape_freshness(FRESH, now)
    auth = next(s for s in data['sources'] if s['source'] == 'logs-auth')
    assert auth['documents'] == 140 and auth['last24h'] == 40 and auth['age_seconds'] == 600
    fw = next(s for s in data['sources'] if s['source'] == 'logs-firewall')
    assert fw['label'] == 'Pare-feu (CSV)' and fw['age_seconds'] > 86400 * 13
    assert data['newest_age_seconds'] == 605


def test_dead_letters_are_counted_line_by_line(tmp_path):
    (tmp_path / 'json-dead-letter.jsonl').write_text('{"a":1}\n\n{"b":2}\n', encoding='utf-8')
    (tmp_path / '.gitkeep').write_text('', encoding='utf-8')
    rows = O.count_rejected(str(tmp_path))
    assert [(r['file'], r['lines']) for r in rows] == [('json-dead-letter.jsonl', 2)]
    assert O.count_rejected(str(tmp_path / 'missing')) == []


def test_fmt_age_and_sparkline():
    assert [O.fmt_age(s) for s in (None, 30, 600, 7200, 259200)] == ['—', '30 s', '10 min', '2 h', '3 j']
    pts = sparkline_points([0, 5, 10])
    assert pts.split(' ')[0] == '3.0,31.0' and pts.split(' ')[-1] == '117.0,3.0'
    assert sparkline_points([4]) == ''


def test_overview_api_measures_health_and_uses_the_saved_period(analyst, stores, http):
    stores.es.responses = [AUTH, FRESH]
    analyst.client.put('/api/dashboard/prefs', json={'period': '7d'}, headers={'X-CSRF-Token': analyst.csrf})
    body = analyst.get('/api/overview').get_json()
    assert body['period'] == '7d' and body['auth']['kpis']['failures']['value'] == 20
    assert stores.es.searches[0][1]['aggs']['cur']['filter']['range']['@timestamp']['gte'] == 'now-7d'
    assert body['health']['services'] == {'elasticsearch': 'ok', 'mongodb': 'ok', 'logstash': 'ok', 'kibana': 'ok', 'redis': 'ok'}
    assert [p['name'] for p in body['health']['pipelines']] == ['csv-security', 'upload-security']   # internal pipelines hidden
    assert any(u.endswith('/_node/stats/pipelines') for u in http.calls)


def test_overview_is_cached_30_seconds(analyst, stores, http):
    stores.es.responses = [AUTH, FRESH]
    analyst.get('/api/overview?period=24h')
    analyst.get('/api/overview?period=24h')
    assert len(stores.es.searches) == 2          # second call served from Redis
    assert 0 < stores.redis.ttl('sentinel:cache:overview:auth:24h') <= 30


def test_unknown_period_falls_back_to_24h(analyst, stores, http):
    assert analyst.get('/api/overview?period=10y').get_json()['period'] == '24h'


def test_services_down_are_reported_not_hidden(analyst, stores, app):
    app.extensions['sentinel_http'] = FakeHTTP(down=True)
    stores.es.down = True
    body = analyst.get('/api/overview').get_json()
    assert body['es_error'] and body['auth'] is None
    s = body['health']['services']
    assert s['elasticsearch'] == 'error' and s['logstash'] == 'error' and s['kibana'] == 'error' and s['mongodb'] == 'ok'


def test_home_page_renders_kpis_priorities_and_health(analyst, stores, http):
    stores.es.responses = [AUTH, FRESH]
    html = analyst.get('/?period=24h').get_data(as_text=True)
    assert 'Échecs d’authentification · 24 heures' in html and '+100 %' in html and '60.0 %' in html
    assert '203.0.113.50' in html and '5 comptes' in html and 'ip=203.0.113.50&amp;outcome=failure' in html
    assert 'Pipelines Logstash' in html and 'csv-security' in html and 'Pare-feu (CSV)' in html
    assert '<polyline points=' in html and '<script>' not in html


def test_home_period_choice_is_remembered(analyst, stores, http):
    analyst.get('/?period=30d')
    assert stores.db.dashboard_prefs.find_one({'username': 'analyste'})['period'] == '30d'
    assert 'aria-current="true">30 jours' in analyst.get('/').get_data(as_text=True)


def test_home_suggests_a_wider_period_when_the_window_is_empty(analyst, stores, http):
    empty = {'aggregations': {'cur': {'doc_count': 0}, 'prev': {'doc_count': 0}}}
    stores.es.responses = [empty, FRESH]
    html = analyst.get('/?period=24h').get_data(as_text=True)
    assert 'Aucun événement sur les 24 heures' in html and 'period=30d' in html
