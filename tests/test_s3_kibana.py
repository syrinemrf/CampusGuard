"""Kibana deliverable: saved objects are consistent with the ES template, the app embeds the dashboard safely."""
import json
import pathlib
import re
import subprocess
import sys

import yaml

from app import kibana
from app.config import Config

ROOT = pathlib.Path(__file__).resolve().parents[1]
NDJSON = ROOT / 'ingestion' / 'kibana' / 'sentinel-dashboard.ndjson'


def objects():
    return [json.loads(line) for line in NDJSON.read_text(encoding='utf-8').splitlines() if line.strip()]


def template_fields():
    tpl = json.loads((ROOT / 'ingestion' / 'elasticsearch' / 'logs-template.json').read_text(encoding='utf-8'))
    props = (tpl.get('template') or tpl)['mappings']['properties']
    out = {}

    def walk(p, prefix=''):
        for key, value in p.items():
            if 'properties' in value:
                walk(value['properties'], prefix + key + '.')
            else:
                out[prefix + key] = value['type']
    walk(props)
    return out


def test_exported_file_is_up_to_date_with_the_generator():
    result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'build_kibana_objects.py'), '--check'],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_ndjson_has_data_view_three_plus_one_visualizations_and_a_dashboard():
    objs = objects()
    kinds = [o['type'] for o in objs]
    assert kinds.count('index-pattern') == 1 and kinds.count('dashboard') == 1
    assert kinds.count('visualization') == 4          # 3 required visualizations + 1 indicator
    assert len({o['id'] for o in objs}) == len(objs)


def test_every_reference_resolves_inside_the_file():
    objs = objects()
    ids = {(o['type'], o['id']) for o in objs}
    for obj in objs:
        for ref in obj['references']:
            assert (ref['type'], ref['id']) in ids, (obj['id'], ref)
    dash = next(o for o in objs if o['type'] == 'dashboard')
    panels = json.loads(dash['attributes']['panelsJSON'])
    names = {r['name'] for r in dash['references']}
    assert len(panels) == 4 and {p['panelRefName'] for p in panels} == names
    assert {r['id'] for r in dash['references']} == set(kibana.VISUALIZATION_IDS.values())
    assert dash['id'] == kibana.DASHBOARD_ID


def test_visualizations_only_use_fields_mapped_in_the_template_with_compatible_types():
    fields = template_fields()
    used = []
    for obj in objects():
        if obj['type'] != 'visualization':
            continue
        state = json.loads(obj['attributes']['visState'])
        assert state['type'] in {'metric', 'histogram', 'pie', 'table'}
        for agg in state['aggs']:
            field = agg['params'].get('field')
            if field:
                used.append((agg['type'], field))
                assert field in fields, f'{field} is not in the ES template'
                if agg['type'] == 'date_histogram':
                    assert fields[field] == 'date'
                if agg['type'] == 'terms':
                    assert fields[field] in {'keyword', 'ip'}
        # KQL filters must also reference mapped fields
        query = json.loads(obj['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])['query']['query']
        for name in re.findall(r'([A-Za-z_.@]+)\s*:', query):
            assert name in fields
    assert {f for _, f in used} == {'@timestamp', 'log.level', 'event.outcome', 'source.ip'}


def test_data_view_matches_the_one_created_by_the_init_container():
    created = json.loads((ROOT / 'ingestion' / 'kibana' / 'data-view.json').read_text(encoding='utf-8'))['data_view']
    view = next(o for o in objects() if o['type'] == 'index-pattern')
    assert view['id'] == created['id'] == kibana.DATA_VIEW_ID
    assert view['attributes']['title'] == created['title'] and view['attributes']['timeFieldName'] == created['timeFieldName']


def test_compose_mounts_the_dashboard_into_kibana_init_and_passes_the_public_url():
    compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))
    init = compose['services']['kibana-init']
    assert any('sentinel-dashboard.ndjson' in v for v in init['volumes'])
    assert init['environment']['OBJECTS_FILE'] == '/setup/sentinel-dashboard.ndjson'
    assert 'KIBANA_PUBLIC_URL' in compose['services']['webapp']['environment']
    assert compose['services']['kibana']['environment']['SERVER_SECURITYRESPONSEHEADERS_DISABLEEMBEDDING'] == 'false'


def test_setup_script_imports_with_overwrite_and_reports_failures_loudly():
    script = (ROOT / 'scripts' / 'setup-kibana.sh').read_text(encoding='utf-8')
    assert '/api/saved_objects/_import?overwrite=true' in script and 'kbn-xsrf' in script
    assert 'KIBANA IMPORT FAILED' in script and '"success":true' in script


def test_origin_helper_rejects_non_http_urls():
    assert kibana.origin('http://kibana.local:5601/app/x') == 'http://kibana.local:5601'
    assert kibana.origin('javascript:alert(1)') == kibana.DEFAULT_PUBLIC_URL
    assert kibana.origin('') == kibana.DEFAULT_PUBLIC_URL


def test_dashboard_urls_point_at_the_exported_dashboard():
    url = kibana.dashboard_url('http://localhost:5601', embed=True)
    assert f'/app/dashboards#/view/{kibana.DASHBOARD_ID}?embed=true' in url and 'now-90d' in url
    assert kibana.discover_url('http://localhost:5601').startswith('http://localhost:5601/app/discover')


def test_kibana_page_embeds_the_dashboard_and_csp_allows_only_that_origin(analyst):
    res = analyst.get('/kibana')
    html = res.get_data(as_text=True)
    assert res.status_code == 200 and '<iframe' in html and kibana.DASHBOARD_ID in html
    csp = res.headers['Content-Security-Policy']
    assert 'frame-src http://localhost:5601' in csp and "frame-ancestors 'none'" in csp and "script-src 'self'" in csp
    assert analyst.get('/').headers['X-Frame-Options'] == 'DENY'


def test_kibana_page_requires_login(app):
    assert app.test_client().get('/kibana').status_code in (302, 401)


def test_custom_kibana_url_changes_the_csp_origin(config, stores, users):
    from app.main import create_app
    from conftest import Session
    cfg = Config(**{**config.__dict__, 'kibana_public_url': 'https://kibana.example.org:8443/anything'})
    session = Session(create_app(cfg, stores), 'analyste')
    res = session.get('/kibana')
    assert 'frame-src https://kibana.example.org:8443;' in res.headers['Content-Security-Policy']
