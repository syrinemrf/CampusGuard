"""Static checks of the Docker / Logstash / Elasticsearch wiring added in S2.

These do NOT start Docker or Logstash: they verify the files stay consistent with the application
(paths, ids, mappings). The real end-to-end run is documented in docs/evidence/ once executed.
"""
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app.services import parsing

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def compose():
    return yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))


def test_upload_volume_is_shared_between_webapp_and_logstash():
    c = compose()
    assert 'uploads:/data/uploads' in c['services']['webapp']['volumes']
    assert 'uploads:/data/uploads' in c['services']['logstash']['volumes']
    assert 'uploads' in c['volumes']


def test_uploads_init_runs_before_writers_and_uses_the_image_uid():
    c = compose()
    assert c['services']['uploads-init']['restart'] == 'no'
    for name in ('webapp', 'logstash'):
        assert c['services'][name]['depends_on']['uploads-init'] == {'condition': 'service_completed_successfully'}
    dockerfile = (ROOT / 'app/Dockerfile').read_text(encoding='utf-8')
    assert '10001' in dockerfile and '10001:10001' in ' '.join(c['services']['uploads-init']['command'])


def test_webapp_reads_dead_letters_read_only_and_exposes_only_localhost():
    web = compose()['services']['webapp']
    assert './datasets/rejected:/data/rejected:ro' in web['volumes']
    assert web['ports'][0].startswith('127.0.0.1:')
    assert web['environment']['UPLOAD_DIR'] == '/data/uploads' and web['environment']['REJECTED_DIR'] == '/data/rejected'


def test_logstash_healthcheck_covers_the_upload_pipeline():
    test = ' '.join(compose()['services']['logstash']['healthcheck']['test'])
    assert 'upload-security' in test


def test_pipelines_yml_registers_upload_pipeline():
    pipelines = yaml.safe_load((ROOT / 'ingestion/logstash/config/pipelines.yml').read_text(encoding='utf-8'))
    ids = {p['pipeline.id']: p for p in pipelines}
    assert ids['upload-security']['path.config'].endswith('/upload.conf') and ids['upload-security']['pipeline.workers'] == 1
    assert {'csv-security', 'json-security'} <= set(ids)         # S1 pipelines untouched


def test_upload_pipeline_watches_the_directory_the_app_writes_to():
    conf = (ROOT / 'ingestion/logstash/pipeline/upload.conf').read_text(encoding='utf-8')
    assert 'path => "/data/uploads/ready/*.ndjson"' in conf and 'mode => "read"' in conf
    assert 'sincedb_path => "/usr/share/logstash/data/' in conf             # persistent volume logstash-data
    assert 'codec => json' in conf
    from app.config import Config
    cfg = Config()
    assert cfg.upload_dir == '/data/uploads' and cfg.rejected_dir == '/data/rejected'


def test_upload_pipeline_safeguards():
    conf = (ROOT / 'ingestion/logstash/pipeline/upload.conf').read_text(encoding='utf-8')
    # idempotent ids: re-reading a file cannot duplicate documents
    assert 'source => ["[labels][upload_id]", "[log][origin][file][line]"]' in conf
    assert 'document_id => "%{[@metadata][document_id]}"' in conf
    assert 'index => "logs-upload-%{+YYYY.MM.dd}"' in conf and 'manage_template => false' in conf
    # dead letters are written per upload, and the id is only used in a path once validated as 32 hex chars
    assert '/data/rejected/upload-%{[labels][upload_id]}.ndjson' in conf
    assert 'uid.length == 32' in conf and '/[^0-9a-f]/' in conf
    assert '/data/rejected/upload-unknown.ndjson' in conf
    for tag in ('_bad_timestamp', '_invalid_source_ip', '_invalid_event_outcome', '_invalid_event_action',
                '_invalid_log_level', '_invalid_field_type', '_jsonparsefailure'):
        assert tag in conf
    assert 'event.ingested' in conf or "[event][ingested]" in conf


def test_template_maps_every_field_the_app_writes_and_search_filters_on():
    props = json.loads((ROOT / 'ingestion/elasticsearch/logs-template.json').read_text())['template']['mappings']['properties']
    assert props['labels']['properties']['upload_id']['type'] == 'keyword'
    assert props['labels']['properties']['time_mode']['type'] == 'keyword'
    assert props['event']['properties']['ingested']['type'] == 'date'
    assert props['log']['properties']['origin']['properties']['file']['properties']['line']['type'] == 'integer'
    assert props['source']['properties']['ip']['type'] == 'ip' and props['user']['properties']['name']['type'] == 'keyword'


def test_every_filtered_or_sorted_field_in_search_is_mapped():
    props = json.loads((ROOT / 'ingestion/elasticsearch/logs-template.json').read_text())['template']['mappings']['properties']

    def mapped(path):
        node = {'properties': props}
        for part in path.split('.'):
            node = node['properties'][part]
        return node['type']
    from app.services.search import SearchParams, build_query
    p = SearchParams(q='x', start='2026-10-30T00:00:00.000Z', levels=['INFO'], services=['s'], ip='192.0.2.1', user='u',
                     outcome='failure', upload_id='a' * 32)
    for clause in build_query(p)['bool']['filter']:
        (kind, body), = clause.items()
        (field, _), = body.items()
        assert mapped(field) in {'keyword', 'ip', 'date'}, field


# ---------------------------------------------------------------- contract: app output vs Logstash rules
def logstash_rules_reject(event):
    """Python mirror of the type checks and tags of upload.conf (documented duplication)."""
    problems = []
    if not isinstance(event.get('timestamp'), str):
        problems.append('timestamp')
    if not isinstance(event.get('message'), str):
        problems.append('message')
    for key in ('source', 'user', 'event', 'log', 'service', 'destination', 'labels'):
        if event.get(key) is not None and not isinstance(event[key], dict):
            problems.append(key)
    ip = event.get('source', {}).get('ip')
    if ip is not None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            problems.append('ip')
    port = event.get('destination', {}).get('port')
    if port is not None and not (isinstance(port, int) and 1 <= port <= 65535):
        problems.append('port')
    line = event['log']['origin']['file'].get('line')
    if not (isinstance(line, int) and line > 0):
        problems.append('line')
    uid = event.get('labels', {}).get('upload_id', '')
    if not (isinstance(uid, str) and len(uid) == 32 and not re.search(r'[^0-9a-f]', uid)):
        problems.append('upload_id')
    for path in (('event', 'action'), ('event', 'outcome'), ('event', 'category'), ('log', 'level'), ('service', 'name')):
        if not isinstance(event.get(path[0], {}).get(path[1]), str):
            problems.append('.'.join(path))
    if not re.fullmatch(r'success|failure|unknown', event['event']['outcome']):
        problems.append('outcome')
    if not re.fullmatch(r'[A-Za-z0-9._-]+', event['event']['action']):
        problems.append('action')
    if event['log']['level'] not in parsing.LEVELS:
        problems.append('level')
    return problems


def test_events_produced_by_the_app_always_satisfy_the_logstash_contract(tmp_path):
    samples = {
        'csv': (ROOT / 'datasets/samples/firewall.csv').read_text(encoding='utf-8'),
        'json': (ROOT / 'datasets/samples/auth.jsonl').read_text(encoding='utf-8'),
        'txt': 'Oct 30 13:00:00 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\nplain line without time\n',
    }
    for fmt, text in samples.items():
        path = tmp_path / f'sample.{fmt}'
        path.write_text(text, encoding='utf-8')
        events = []
        analysis = parsing.analyze(str(path), fmt, now=NOW, sink=events.append)
        assert events, fmt
        for event in events:
            event['labels']['upload_id'] = 'f' * 32
            event['log']['origin']['file']['name'] = 'sample'
            assert logstash_rules_reject(event) == [], (fmt, event)
        assert analysis.invalid_rows == 0, (fmt, analysis.errors[:3])
