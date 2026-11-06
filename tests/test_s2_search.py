"""Search API: query building, validation, cache, history, detail, CSV export."""
import csv
import io
import json

import pytest

from conftest import make_hit
from app.services import search as S
from werkzeug.datastructures import MultiDict


def params(**kw):
    return S.parse_params(MultiDict(kw))


# ------------------------------------------------------------ query builder (pure)
def test_empty_search_is_match_all_sorted_newest_first():
    body = S.build_body(params())
    assert body['query'] == {'match_all': {}}
    assert body['sort'][0]['@timestamp']['order'] == 'desc'
    assert body['from'] == 0 and body['size'] == 50 and body['track_total_hits'] is True


def test_all_filters_become_es_filters():
    p = params(q='failed password', start='2026-10-30', end='2026-10-31', level='error,warning', service='sshd',
               ip='203.0.113.50', user='alice', outcome='failure', upload_id='a' * 32, page='3', size='20', sort='asc')
    body = S.build_body(p)
    f = body['query']['bool']['filter']
    assert {'range': {'@timestamp': {'gte': '2026-10-30T00:00:00.000Z', 'lte': '2026-10-31T23:59:59.999Z'}}} in f
    assert {'terms': {'log.level': ['ERROR', 'WARNING']}} in f
    assert {'terms': {'service.name': ['sshd']}} in f
    assert {'term': {'source.ip': '203.0.113.50'}} in f and {'term': {'user.name': 'alice'}} in f
    assert {'term': {'event.outcome': 'failure'}} in f and {'term': {'labels.upload_id': 'a' * 32}} in f
    must = body['query']['bool']['must'][0]['simple_query_string']
    assert must['query'] == 'failed password' and must['default_operator'] == 'and' and must['fields'] == ['message']
    assert body['from'] == 40 and body['size'] == 20 and body['sort'][0]['@timestamp']['order'] == 'asc'


def test_cidr_is_supported_and_normalised():
    assert params(ip='203.0.113.77/24').ip == '203.0.113.0/24'


@pytest.mark.parametrize('bad', [
    {'ip': 'not-an-ip'}, {'start': 'yesterday'}, {'start': '2026-10-31', 'end': '2026-10-30'}, {'level': 'LOUD'},
    {'outcome': 'maybe'}, {'size': '0'}, {'size': '101'}, {'page': '0'}, {'page': 'x'}, {'page': '201', 'size': '50'},
    {'sort': 'sideways'}, {'q': 'x' * 300}, {'upload_id': 'nope'}, {'service': 'a;drop'},
])
def test_invalid_parameters_are_rejected(bad):
    with pytest.raises(S.ValidationError):
        params(**bad)


def test_query_text_cannot_inject_dsl():
    q = '"} , "script": {"source": "x"'
    body = S.build_body(params(q=q))
    assert json.dumps(body['query']).count('script') == 1                  # only inside the query string value
    assert body['query']['bool']['must'][0]['simple_query_string']['query'] == q


# ------------------------------------------------------------ HTTP API
def seed(stores, n=3):
    stores.es.response = {'took': 5, 'hits': {'total': {'value': 123, 'relation': 'eq'}, 'hits': [make_hit(i) for i in range(n)]}}


def test_search_returns_shaped_hits_and_pagination(analyst, stores):
    seed(stores)
    body = analyst.get('/api/search?level=warning&size=50').get_json()
    assert body['total'] == 123 and body['pages'] == 3 and body['cached'] is False
    hit = body['hits'][0]
    assert hit['ip'] == '203.0.113.50' and hit['level'] == 'WARNING' and hit['id'].startswith('doc')
    index, sent = stores.es.searches[-1]
    assert index == 'logs-*' and {'terms': {'log.level': ['WARNING']}} in sent['query']['bool']['filter']


def test_search_result_is_cached_then_bypassed_with_nocache(analyst, stores):
    seed(stores)
    analyst.get('/api/search?q=abc')
    assert analyst.get('/api/search?q=abc').get_json()['cached'] is True
    assert len(stores.es.searches) == 1
    assert analyst.get('/api/search?q=abc&nocache=1').get_json()['cached'] is False
    assert len(stores.es.searches) == 2


def test_bad_parameters_return_400_with_details(analyst):
    res = analyst.get('/api/search?ip=zzz&level=LOUD')
    body = res.get_json()
    assert res.status_code == 400 and body['error'] == 'invalid_parameters' and len(body['details']) == 2


def test_elasticsearch_down_returns_502_not_a_stack_trace(analyst, stores):
    stores.es.down = True
    res = analyst.get('/api/search?q=x')
    assert res.status_code == 502 and res.get_json()['error'] == 'elasticsearch_unavailable'


def test_history_records_last_searches_and_deduplicates(analyst, stores):
    seed(stores)
    analyst.get('/api/search?q=alpha')
    analyst.get('/api/search?q=beta&level=error')
    analyst.get('/api/search?q=beta&level=error&nocache=1')               # same criteria: not duplicated
    analyst.get('/api/search')                                            # no criteria: not recorded
    analyst.get('/api/search?q=gamma&page=2')                             # paging is not a new search
    hist = analyst.get('/api/search/history?limit=5').get_json()['history']
    assert [h['filters'].get('q') for h in hist] == ['beta', 'alpha']
    assert hist[0]['filters']['level'] == ['ERROR']


def test_history_is_private_per_user(make_session, stores):
    seed(stores)
    a, b = make_session('analyste'), make_session('admin')
    a.get('/api/search?q=secret-hunt')
    assert b.get('/api/search/history').get_json()['history'] == []


def test_record_flag_can_disable_history(analyst, stores):
    seed(stores)
    analyst.get('/api/search?q=silent&record=0')
    assert analyst.get('/api/search/history').get_json()['history'] == []


def test_event_detail_found_and_not_found(analyst, stores):
    stores.es.response = {'hits': {'total': {'value': 1}, 'hits': [make_hit(7)]}}
    body = analyst.get('/api/events/doc000007abc').get_json()
    assert body['id'] == 'doc000007abc' and body['source']['user']['name'] == 'user_4'
    assert stores.es.searches[-1][1]['query'] == {'ids': {'values': ['doc000007abc']}}
    stores.es.response = {'hits': {'total': {'value': 0}, 'hits': []}}
    assert analyst.get('/api/events/doc000008abc').status_code == 404
    assert analyst.get('/api/events/bad id!!').status_code == 404


def test_facets_use_aggregations_and_are_cached(analyst, stores):
    stores.es.response = {'hits': {'total': {'value': 42}}, 'aggregations': {
        'levels': {'buckets': [{'key': 'INFO', 'doc_count': 40}, {'key': 'WARNING', 'doc_count': 2}]},
        'services': {'buckets': [{'key': 'authentication', 'doc_count': 42}]}, 'outcomes': {'buckets': []},
        'oldest': {'value_as_string': '2026-10-30T13:00:00.000Z'}, 'newest': {'value_as_string': '2026-10-30T20:00:00.000Z'}}}
    body = analyst.get('/api/search/facets').get_json()
    assert body['total'] == 42 and body['levels'][1] == {'value': 'WARNING', 'count': 2}
    analyst.get('/api/search/facets')
    assert len(stores.es.searches) == 1


# ------------------------------------------------------------ CSV export
def test_export_matches_filters_and_is_audited(analyst, stores):
    seed(stores)
    stores.es.response['hits']['total']['value'] = 3
    res = analyst.get('/api/search/export?level=warning&q=failed')
    assert res.status_code == 200 and res.mimetype == 'text/csv'
    assert res.headers['X-Export-Rows'] == '3' and res.headers['X-Export-Truncated'] == 'false'
    rows = list(csv.reader(io.StringIO(res.get_data(as_text=True))))
    assert rows[0] == S.EXPORT_COLUMNS and len(rows) == 4 and rows[1][3] == '203.0.113.50'
    sent = stores.es.searches[-1][1]
    assert {'terms': {'log.level': ['WARNING']}} in sent['query']['bool']['filter']            # same filters as the screen
    assert stores.db.audit_actions.find_one({'action': 'export_csv'})['details']['rows'] == 3


def test_export_neutralises_csv_formula_injection(analyst, stores):
    evil = make_hit(1, message='=HYPERLINK("http://evil","click")', user={'name': '@cmd'})
    stores.es.response = {'hits': {'total': {'value': 1}, 'hits': [evil]}}
    rows = list(csv.reader(io.StringIO(analyst.get('/api/search/export').get_data(as_text=True))))
    assert rows[1][4] == "'@cmd" and rows[1][8].startswith("'=")


def test_export_is_capped_and_says_so(analyst, stores, config):
    config.export_max_rows = 2
    stores.es.response = {'hits': {'total': {'value': 500}, 'hits': [make_hit(1), make_hit(2)]}}
    res = analyst.get('/api/search/export')
    assert res.headers['X-Export-Rows'] == '2' and res.headers['X-Export-Truncated'] == 'true'


def test_csv_safe_helper():
    assert S.csv_safe('-1+1') == "'-1+1" and S.csv_safe('normal') == 'normal' and S.csv_safe(None) == ''


def test_auditor_can_search_and_export(auditor, stores):
    seed(stores)
    assert auditor.get('/api/search?q=x').status_code == 200
    assert auditor.get('/api/search/export').status_code == 200


# ------------------------------------------------------------ pages
def test_pages_render_for_authenticated_user(analyst, stores):
    stores.es.response = {'hits': {'total': {'value': 0}}, 'aggregations': {}}
    for url in ('/', '/upload', '/search', '/events/abc12345'):
        res = analyst.get(url)
        assert res.status_code == 200, url
        assert b'csrf-token' in res.data
    assert b'Parcourir' in analyst.get('/upload').data


def test_auditor_upload_page_is_read_only(auditor):
    html = auditor.get('/upload').get_data(as_text=True)
    assert 'lecture seule' in html and 'file-input' not in html


def test_home_shows_elasticsearch_error_instead_of_fake_numbers(analyst, stores):
    stores.es.down = True
    html = analyst.get('/').get_data(as_text=True)
    assert 'Elasticsearch indisponible' in html


# ------------------------------------------------------------ sorting + dashboard stats
def test_sort_by_level_and_service_has_stable_secondary_sort():
    body = S.build_body(params(sort_by='level', sort='asc'))
    assert body['sort'][0] == {'log.level': {'order': 'asc', 'unmapped_type': 'keyword'}}
    assert body['sort'][1]['@timestamp']['order'] == 'desc'
    assert S.build_body(params(sort_by='service', sort='desc'))['sort'][0]['service.name']['order'] == 'desc'
    assert len(S.build_body(params())['sort']) == 1


def test_invalid_sort_by_rejected():
    with pytest.raises(S.ValidationError):
        params(sort_by='message')


def test_stats_api_returns_dashboard_figures_and_uses_mongo_upload_count(analyst, stores):
    stores.es.response = {'hits': {'total': {'value': 1234}}, 'aggregations': {
        'levels': {'buckets': [{'key': 'INFO', 'doc_count': 1000}, {'key': 'ERROR', 'doc_count': 234}]},
        'services': {'buckets': [{'key': 'sshd', 'doc_count': 900}]},
        'today': {'doc_count': 12}, 'errors': {'doc_count': 234},
        'timeline': {'interval': '30m', 'buckets': [{'key_as_string': '2026-10-30T13:00:00.000Z', 'key': 1, 'doc_count': 5}]}}}
    stores.db.uploaded_files.insert_many([{'_id': 'a', 'state': 'indexed'}, {'_id': 'b', 'state': 'rejected'},
                                          {'_id': 'c', 'state': 'validated'}, {'_id': 'd', 'state': 'cancelled'}])
    body = analyst.get('/api/stats').get_json()
    assert (body['total'], body['today'], body['errors'], body['uploads']) == (1234, 12, 234, 2)
    assert body['levels'][1] == {'label': 'ERROR', 'count': 234} and body['timeline_interval'] == '30m'
    sent = stores.es.searches[-1][1]['aggs']
    assert sent['today']['filter']['range']['@timestamp']['gte'] == 'now/d'       # UTC day boundary
    assert sent['errors']['filter']['terms']['log.level'] == ['ERROR', 'CRITICAL']


def test_home_page_embeds_chart_data_without_inline_script(analyst, stores):
    stores.es.response = {'hits': {'total': {'value': 5}}, 'aggregations': {
        'levels': {'buckets': [{'key': 'INFO', 'doc_count': 5}]}, 'services': {'buckets': []},
        'today': {'doc_count': 1}, 'errors': {'doc_count': 0}, 'timeline': {'buckets': []}}}
    html = analyst.get('/').get_data(as_text=True)
    assert 'id="chart-data"' in html and 'type="application/json"' in html and 'chart-levels' in html
    assert 'Logs ERROR / CRITICAL' in html and 'Fichiers importés' in html
