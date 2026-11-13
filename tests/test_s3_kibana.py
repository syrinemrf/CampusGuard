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


def template_fields(name='logs-template.json'):
    tpl = json.loads((ROOT / 'ingestion' / 'elasticsearch' / name).read_text(encoding='utf-8'))
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


def test_ndjson_has_two_data_views_three_themed_dashboards_and_their_visualizations():
    objs = objects()
    kinds = [o['type'] for o in objs]
    assert kinds.count('index-pattern') == 2 and kinds.count('dashboard') == 3
    assert kinds.count('visualization') == len(kibana.VISUALIZATION_IDS)
    assert len({o['id'] for o in objs}) == len(objs)
    assert {o['id'] for o in objs if o['type'] == 'dashboard'} == {d for d, _ in kibana.DASHBOARDS.values()}
    for vid in ('sentinel-vis-total-events', 'sentinel-vis-events-over-time', 'sentinel-vis-outcome-split', 'sentinel-vis-top-failing-ips'):
        assert vid in {o['id'] for o in objs}       # first S3 ids kept: earlier exports stay importable


def test_every_reference_resolves_and_every_visualization_is_used():
    objs = objects()
    ids = {(o['type'], o['id']) for o in objs}
    used = set()
    for obj in objs:
        for ref in obj['references']:
            assert (ref['type'], ref['id']) in ids, (obj['id'], ref)
    for dash in (o for o in objs if o['type'] == 'dashboard'):
        panels = json.loads(dash['attributes']['panelsJSON'])
        assert {p['panelRefName'] for p in panels} == {r['name'] for r in dash['references']}
        used |= {r['id'] for r in dash['references']}
    assert used == set(kibana.VISUALIZATION_IDS.values())


def test_dashboards_are_landscape_without_overlap_or_text_blocks():
    for dash in (o for o in objects() if o['type'] == 'dashboard'):
        cells, bottom = set(), 0
        for panel in json.loads(dash['attributes']['panelsJSON']):
            g = panel['gridData']
            assert g['x'] + g['w'] <= 48
            bottom = max(bottom, g['y'] + g['h'])
            for x in range(g['x'], g['x'] + g['w']):
                for y in range(g['y'], g['y'] + g['h']):
                    assert (x, y) not in cells, (dash['id'], panel['panelIndex'])
                    cells.add((x, y))
        assert bottom <= 32, dash['id']                     # fits one landscape screen
    kinds = {json.loads(o['attributes']['visState'])['type'] for o in objects() if o['type'] == 'visualization'}
    assert 'markdown' not in kinds and 'input_control_vis' not in kinds


def test_state_colours_match_the_application_identity():
    outcome = next(o for o in objects() if o['id'] == kibana.VISUALIZATION_IDS['outcome'])
    colors = json.loads(outcome['attributes']['uiStateJSON'])['vis']['colors']
    assert colors['failure'] == '#E0344F' and colors['success'] == '#0AA9A0'
    assert '"theme:darkMode":false' in (ROOT / 'scripts' / 'setup-kibana.sh').read_text(encoding='utf-8')


def test_visualizations_only_use_fields_mapped_in_the_template_with_compatible_types():
    logs = {**template_fields(), **{k: v['type'] for k, v in kibana.RUNTIME_FIELDS.items()}}
    alerts = template_fields('alerts-template.json')
    used = []
    for obj in objects():
        if obj['type'] != 'visualization':
            continue
        state = json.loads(obj['attributes']['visState'])
        assert state['type'] in {'metric', 'histogram', 'area', 'pie', 'table', 'heatmap'}
        view = next((r['id'] for r in obj['references']), None)
        fields = alerts if view == kibana.ALERTS_DATA_VIEW_ID else logs
        for agg in state['aggs']:
            field = agg['params'].get('field')
            if field:
                used.append(field)
                assert field in fields, f'{field} is not in the ES template / data view'
                if agg['type'] == 'date_histogram':
                    assert fields[field] == 'date'
                if agg['type'] in ('terms', 'cardinality'):
                    assert fields[field] in {'keyword', 'ip', 'long'}
        for control in state['params'].get('controls', []):
            assert logs.get(control['fieldName']) == 'keyword'
        query = json.loads(obj['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])['query']['query']
        for name in re.findall(r'([A-Za-z_.@]+)\s*:', query):
            assert name in fields
    assert {'@timestamp', 'log.level', 'event.outcome', 'source.ip', 'user.name', 'hour_of_day', 'day_of_week',
            'source.geo.country_iso_code', 'alert.severity', 'rule.name'} <= set(used)


def test_runtime_fields_are_painless_on_local_time_and_shared_with_the_data_view_file():
    view = next(o for o in objects() if o['id'] == kibana.DATA_VIEW_ID)
    assert json.loads(view['attributes']['runtimeFieldMap']) == kibana.RUNTIME_FIELDS
    created = json.loads((ROOT / 'ingestion' / 'kibana' / 'data-view.json').read_text(encoding='utf-8'))['data_view']
    assert created['runtimeFieldMap'] == kibana.RUNTIME_FIELDS
    for spec in kibana.RUNTIME_FIELDS.values():
        assert "ZoneId.of('Africa/Tunis')" in spec['script']['source'] and 'emit(' in spec['script']['source']


def test_alerts_template_and_data_view_are_installed_by_the_init_containers():
    c = yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))['services']
    assert c['elasticsearch-init']['environment']['ALERTS_TEMPLATE_FILE'] == '/setup/alerts-template.json'
    assert 'campusguard-alerts' in (ROOT / 'scripts' / 'setup-index.sh').read_text(encoding='utf-8')
    assert any('data-view-alerts.json' in v for v in c['kibana-init']['volumes'])
    script = (ROOT / 'scripts' / 'setup-kibana.sh').read_text(encoding='utf-8')
    assert 'courier:ignoreFilterIfFieldNotInIndex' in script and 'ALERTS_DATA_VIEW_FILE' in script


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


def test_kibana_page_has_one_tab_per_themed_dashboard_and_no_filler_text(analyst):
    html = analyst.get('/kibana').get_data(as_text=True)
    assert html.count('class="kb-tab') == 3 and 'Si le cadre reste vide' not in html and 'Tableau de bord d’analyse' not in html
    alerts = analyst.get('/kibana?tab=alerts').get_data(as_text=True)
    assert 'sentinel-alerts-overview?embed=true&amp;show-time-filter=true' in alerts
    assert 'sentinel-security-overview' in analyst.get('/kibana?tab=nope').get_data(as_text=True)
