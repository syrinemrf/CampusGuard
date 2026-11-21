"""Explorer: user-written query (Lucene query_string or validated Query DSL), combined with the filters."""
import json

import pytest
from werkzeug.datastructures import MultiDict

from app.services import search as S
from app.stores import ElasticClient, ElasticError
from conftest import make_hit


def params(**kw):
    return S.parse_params(MultiDict(kw))


def test_lucene_query_is_sent_as_query_string_on_message_and_anded_with_filters():
    p = params(query='event.outcome:failure AND NOT user.name:admin', level='WARNING')
    q = S.build_query(p)
    assert q['bool']['filter'] == [{'terms': {'log.level': ['WARNING']}}]
    qs = q['bool']['must'][0]['query_string']
    assert qs['query'] == 'event.outcome:failure AND NOT user.name:admin'
    assert qs['default_field'] == 'message' and qs['allow_leading_wildcard'] is False


def test_dsl_is_parsed_canonicalised_and_combined():
    dsl = {'bool': {'filter': [{'term': {'event.outcome': 'failure'}}, {'range': {'@timestamp': {'gte': 'now-7d'}}}],
                    'must_not': [{'term': {'user.name': 'admin'}}]}}
    p = params(dsl=json.dumps(dsl, indent=2), ip='203.0.113.0/24')
    assert S.build_query(p)['bool']['must'] == [dsl] and p.dsl == json.dumps(dsl, separators=(',', ':'))
    assert p.criteria()['dsl'] == p.dsl                                # stored in the history in canonical form
    wrapped = params(dsl=json.dumps({'query': {'match': {'message': 'failed'}}}))   # copied from Kibana Dev Tools
    assert S.build_query(wrapped)['bool']['must'] == [{'match': {'message': 'failed'}}]


@pytest.mark.parametrize('dsl, message', [
    ('{"bool": ', 'JSON invalide'),
    ('{"script": {"script": "1"}}', 'non autorisée'),
    ('{"function_score": {"query": {"match_all": {}}}}', 'non autorisée'),
    ('{"wrapper": {"query": "eyJ0ZXJtIjp7fX0="}}', 'non autorisée'),
    ('{"bool": {"filter": [{"script": {"script": {"source": "1"}}}]}}', 'non autorisée'),
    ('{"terms": {"user.name": {"index": "users", "id": "1", "path": "x"}}}', 'autre index'),
    ('{"match": {"message": {"query": "x", "script": "y"}}}', 'clé « script »'),
    ('{"term": {"a": 1}, "match": {"b": 2}}', 'une seule clé'),
    ('{"bool": {"evil": []}}', 'inconnue'),
    ('[1, 2]', 'une seule clé'),
])
def test_dangerous_or_invalid_dsl_is_refused_with_a_clear_message(dsl, message):
    with pytest.raises(S.ValidationError) as err:
        params(dsl=dsl)
    assert any(message in e for e in err.value.errors), err.value.errors


def test_dsl_depth_and_length_are_bounded():
    deep = {'match_all': {}}
    for _ in range(S.MAX_DSL_DEPTH + 2):
        deep = {'bool': {'must': [deep]}}
    with pytest.raises(S.ValidationError):
        params(dsl=json.dumps(deep))
    with pytest.raises(S.ValidationError):
        params(dsl='{"match": {"message": "' + 'x' * S.MAX_DSL_LEN + '"}}')
    with pytest.raises(S.ValidationError):
        params(query='a' * (S.MAX_QUERY_LEN + 1))


def test_search_api_returns_the_executed_es_query_and_records_history(analyst, stores):
    stores.es.response = {'took': 2, 'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [make_hit(1)]}}
    body = analyst.get('/api/search?query=event.outcome:failure&level=WARNING').get_json()
    assert body['es_query']['bool']['must'][0]['query_string']['query'] == 'event.outcome:failure'
    assert stores.db.saved_searches.find_one()['filters']['query'] == 'event.outcome:failure'
    bad = analyst.get('/api/search?dsl={"script":{}}')
    assert bad.status_code == 400 and bad.get_json()['error'] == 'invalid_parameters'


def test_export_and_v1_accept_the_advanced_query(analyst, stores):
    stores.es.response = {'took': 2, 'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [make_hit(1)]}}
    dsl = json.dumps({'term': {'event.outcome': 'failure'}})
    assert analyst.get('/api/search/export', query_string={'dsl': dsl}).status_code == 200
    assert stores.es.searches[-1][1]['query']['bool']['must'] == [{'term': {'event.outcome': 'failure'}}]
    assert analyst.get('/api/v1/logs', query_string={'query': 'user.name:user_4'}).status_code == 200


def test_elasticsearch_syntax_errors_are_explained_to_the_user():
    class Resp:
        status_code = 400

        def json(self):
            return {'error': {'root_cause': [{'reason': 'Failed to parse query [user.name:(]'}],
                              'caused_by': {'reason': "Cannot parse 'user.name:(': Encountered \"<EOF>\""}}}

    class HTTP:
        def post(self, *a, **k):
            return Resp()
    with pytest.raises(ElasticError) as err:
        ElasticClient('http://es:9200', http=HTTP()).search('logs-*', {})
    assert err.value.status == 400 and "Cannot parse 'user.name:('" in str(err.value)


def test_search_page_offers_both_syntaxes_examples_and_field_help(analyst):
    html = analyst.get('/search').get_data(as_text=True)
    assert 'Requête avancée' in html and 'name="query"' in html and 'name="dsl"' in html
    assert 'data-example-mode="dsl"' in html and 'data-field="source.ip"' in html and 'Requête Elasticsearch exécutée' in html
