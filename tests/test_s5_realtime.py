"""S5, module H : rejeu du journal sshd réel, classement Logstash, diffusion WebSocket, métriques, chaîne mesurée."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from app import live
from app.services.stream import StreamStatus

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import replay_openssh as R  # noqa: E402

REAL = """Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.example.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from 119.137.62.142 port 49116 ssh2
Dec 10 09:32:20 LabSZ sshd[24680]: pam_unix(sshd:session): session opened for user fztu by (uid=0)
"""


# ---------------------------------------------------------------- rejeu et pseudonymisation
def test_pseudonymisation_keeps_the_country_prefix_and_is_stable():
    a = R.pseudo_ip('183', '62', '140', '253')
    assert a.startswith('183.62.') and a != '183.62.140.253' and a == R.pseudo_ip('183', '62', '140', '253')
    last = [int(x) for x in a.split('.')[2:]]
    assert all(1 <= x <= 254 for x in last)


def test_real_accounts_are_renamed_but_attack_dictionary_words_are_kept(tmp_path):
    src = tmp_path / 'sshd.log'
    src.write_text(REAL, encoding='utf-8')
    out = tmp_path / 'stream.log'
    events = R.read_events(src)
    assert len(events) == 5 and events[2][0] - events[0][0] == 2
    sink = R.Sink('file', out)
    assert R.replay(events, sink, speed=0) == 5
    sink.close()
    lines = out.read_text(encoding='utf-8').splitlines()
    assert 'webmaster' in lines[1] and '173.234.31.186' not in ''.join(lines)
    assert 'fztu' not in ''.join(lines) and 'Accepted password for user_' in lines[3]
    assert lines[3].split('for ')[1].split(' ')[0] == lines[4].split('for user ')[1].split(' ')[0]
    assert lines[0][:4].isdigit() and 'T' in lines[0][:24] and ' LabSZ sshd[24200]: ' in lines[0]


def test_replay_keeps_the_original_rhythm_divided_by_speed(tmp_path):
    src = tmp_path / 'sshd.log'
    src.write_text(REAL, encoding='utf-8')
    waits = []

    class Null:
        def write(self, line):
            pass
    R.replay(R.read_events(src), Null(), speed=2, max_gap=5, sleep=waits.append)
    assert waits == [1.0, 5]          # 2 s / 2 ; puis 2 h 36 min plafonnées à 5 s


# ---------------------------------------------------------------- classement des lignes sshd dans Logstash
RUBY = shutil.which('ruby')


@pytest.mark.skipif(not RUBY, reason='ruby absent : le filtre Logstash est testé là où ruby est installé')
def test_logstash_sshd_classifier_counts_one_failure_per_attempt():
    msgs = [line.split(']: ', 1)[1] for line in REAL.splitlines()] + [
        'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root',
        'message repeated 5 times: [ Failed password for root from 183.62.140.253 port 1 ssh2]',
        'Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2',
        'Disconnecting: Too many authentication failures for admin [preauth]',
        'fatal: Write failed: Connection reset by peer [preauth]']
    run = subprocess.run([RUBY, str(ROOT / 'tests/ruby/run_filter.rb'), str(ROOT / 'ingestion/logstash/pipeline/stream.conf'),
                          'sshd_classify'], input='\n'.join(msgs), capture_output=True, text=True, encoding='utf-8',
                         env={'LANG': 'C.UTF-8'}, check=True)
    out = [json.loads(line) for line in run.stdout.splitlines()]
    kinds = [(o['event']['action'], o['event']['outcome'], o['log']['level']) for o in out]
    assert kinds[0] == ('ssh-reverse-mapping', 'unknown', 'WARNING')
    assert kinds[1] == ('ssh-invalid-user', 'unknown', 'WARNING')          # pas un échec : sinon compté 2 fois
    assert kinds[2] == ('ssh-login', 'failure', 'WARNING') and out[2]['user']['name'] == 'webmaster'
    assert kinds[3] == ('ssh-login', 'success', 'INFO') and out[3]['source']['ip'] == '119.137.62.142'
    assert out[3]['event']['category'] == 'authentication' and out[1]['event']['category'] == 'network'
    assert kinds[5] == ('pam-auth-failure', 'unknown', 'WARNING') and out[5]['user']['name'] == 'root'
    assert kinds[6] == ('ssh-login', 'failure', 'WARNING') and out[6]['event']['count'] == 5
    assert out[7]['user']['name'] == '0101' and out[7]['source']['ip'] == '5.188.10.180'
    assert kinds[8][2] == 'ERROR' and kinds[9][2] == 'CRITICAL'


def test_stream_pipeline_is_registered_and_publishes_after_indexing():
    pipelines = {p['pipeline.id'] for p in yaml.safe_load((ROOT / 'ingestion/logstash/config/pipelines.yml').read_text())}
    assert 'stream-security' in pipelines
    conf = (ROOT / 'ingestion/logstash/pipeline/stream.conf').read_text(encoding='utf-8')
    assert 'topics => ["logs.auth"]' in conf and 'port => 5140' in conf and 'geoip' in conf
    out = conf[conf.index('output {'):]
    assert out.index('elasticsearch {') < out.index('redis {') and 'sentinel:live:logs' in out
    fb = yaml.safe_load((ROOT / 'ingestion/filebeat/filebeat.yml').read_text())
    assert fb['output.kafka']['topic'] == 'logs.auth' and fb['http.enabled'] is True
    compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())['services']
    assert compose['kafka-init']['profiles'] == ['stream'] and 'kafka-init' in compose['filebeat']['depends_on']


# ---------------------------------------------------------------- WebSocket : relais Redis → navigateur
class FakeWS:
    def __init__(self):
        self.sent = []

    def send(self, data):
        self.sent.append(json.loads(data))


class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        self.t += 0.05
        return self.t


def test_shape_log_measures_end_to_end_latency():
    doc = {'@timestamp': '2023-11-14T22:13:20.000Z', 'log': {'level': 'warning'}, 'service': {'name': 'openssh'},
           'source': {'ip': '183.62.1.2', 'geo': {'country_iso_code': 'CN'}}, 'user': {'name': 'root'},
           'event': {'action': 'ssh-login', 'outcome': 'failure', 'ingest_lag_ms': 120}, 'message': 'Failed password'}
    item = live.shape_log(doc, now_ms=1_700_000_000_350)
    assert item['latency_ms'] == 350 and item['level'] == 'WARNING' and item['country'] == 'CN' and item['ingest_ms'] == 120


def test_percentiles_and_sliding_windows():
    assert live.percentile([], .5) is None and live.percentile([100, 200, 300, 400], .5) == 250
    clock = Clock()
    s = live.StreamStats(clock)
    for lvl in ('INFO', 'ERROR', 'CRITICAL', 'INFO'):
        s.add({'level': lvl, 'latency_ms': 200})
    snap = s.snapshot()
    assert snap['errors_per_min'] == 2 and snap['received'] == 4 and snap['latency_p50_ms'] == 200
    clock.t += 120
    assert s.snapshot()['errors_per_min'] == 0


def test_serve_pushes_logs_in_batches_alerts_at_once_and_metrics_every_second(stores):
    ws, clock = FakeWS(), Clock()
    redis = stores.redis
    sent = {'n': 0}

    def receive():
        sent['n'] += 1
        if sent['n'] == 3:
            for i in range(3):
                redis.publish(live.LOGS_CHANNEL, json.dumps({'@timestamp': '2023-11-14T22:13:20Z', 'log': {'level': 'ERROR'},
                                                             'message': f'ligne {i}', 'service': {'name': 'openssh'}}))
            live.publish_alert(redis, {'id': 'a1', 'rule_name': 'Force brute', 'severity': 'high', 'group': '1.2.3.4',
                                       'secret_field': 'non diffusé'})
        return None
    total = live.serve(ws, redis, 'analyste', clock=clock, max_seconds=3, receive=receive)
    types = [m['type'] for m in ws.sent]
    assert types[0] == 'hello' and 'metrics' in types and total == 3
    logs = [m for m in ws.sent if m['type'] == 'logs']
    assert sum(len(m['items']) for m in logs) == 3 and len(logs) < 3           # regroupés (paquets de 250 ms)
    alert = next(m for m in ws.sent if m['type'] == 'alert')['alert']
    assert alert['rule_name'] == 'Force brute' and 'secret_field' not in alert
    last = [m for m in ws.sent if m['type'] == 'metrics'][-1]
    assert last['errors_per_min'] == 3 and last['connected_users'] >= 1
    assert redis.zcard(live.CLIENTS_KEY) == 0                                   # connexion retirée à la fermeture
    assert redis.llen(live.LATENCY_KEY) == 3


def test_serve_stops_when_the_browser_closes(stores):
    ws = FakeWS()
    assert live.serve(ws, stores.redis, 'analyste', clock=Clock(), max_seconds=60, receive=lambda: live.Closed) == 0


def test_websocket_refuses_other_origins():
    assert live.same_origin('http://localhost:8000', 'localhost:8000')
    assert not live.same_origin('https://evil.example', 'localhost:8000') and not live.same_origin(None, 'localhost:8000')


def test_requests_in_flight_and_connected_users_are_counted(analyst, stores):
    analyst.get('/api/stream/status')
    m = live.platform_metrics(stores.redis)
    assert m['active_requests'] == 0 and m['connected_users'] == 1        # requête terminée, utilisateur vu
    token = live.request_started(stores.redis, 'admin')
    assert live.platform_metrics(stores.redis)['active_requests'] == 1
    live.request_finished(stores.redis, token)


def test_csp_allows_the_websocket_of_the_same_host_only(analyst):
    csp = analyst.get('/live').headers['Content-Security-Policy']
    assert "connect-src 'self' ws://localhost wss://localhost" in csp


# ---------------------------------------------------------------- pages et état de la chaîne
class HTTP:
    def __init__(self, filebeat=True):
        self.filebeat = filebeat

    def get(self, url, timeout=None):
        import requests

        class Resp:
            def __init__(self, payload):
                self.payload, self.ok, self.status_code = payload, True, 200

            def json(self):
                return self.payload

            def raise_for_status(self):
                pass
        if '5066' in url:
            if not self.filebeat:
                raise requests.ConnectionError('absent')
            return Resp({'libbeat': {'output': {'events': {'acked': 1950, 'failed': 0}}}})
        if 'stream-security' in url:
            return Resp({'pipelines': {'stream-security': {'events': {'in': 2000, 'out': 2000}, 'plugins': {'inputs': [
                {'id': 'kafka_logs_auth', 'events': {'out': 1950}}, {'id': 'tcp_raw_syslog', 'events': {'out': 50}}]}}}})
        if 'pipelines' in url:
            return Resp({'pipelines': {}})
        return Resp({'status': {'overall': {'level': 'available'}}})


def test_stream_status_reports_each_hop(stores, app):
    stores.es.responses = [{'hits': {'total': {'value': 2000}}, 'aggregations': {'newest': {'value_as_string': '2026-11-20T22:00:00Z'},
                                                                                'last5m': {'doc_count': 120}}}]
    stores.redis.lpush(live.LATENCY_KEY, 300, 400, 1200)
    st = StreamStatus(stores, app.extensions['sentinel_config'], http=HTTP(), tcp_open=lambda hp: True).build()
    hops = {h['key']: h for h in st['chain']}
    assert hops['filebeat']['published'] == 1950 and hops['kafka']['status'] == 'ok'
    assert hops['logstash']['kafka_in'] == 1950 and hops['logstash']['tcp_in'] == 50
    assert hops['elasticsearch']['documents'] == 2000 and st['kafka_mode'] is True
    assert st['latency'] == {'samples': 3, 'p50_ms': 400, 'p95_ms': 1120, 'max_ms': 1200, 'under_1s_pct': 66.7}


def test_without_the_stream_profile_kafka_and_filebeat_are_shown_as_not_started(stores, app):
    st = StreamStatus(stores, app.extensions['sentinel_config'], http=HTTP(filebeat=False), tcp_open=lambda hp: False).build()
    hops = {h['key']: h for h in st['chain']}
    assert hops['kafka']['status'] == 'absent' and hops['filebeat']['status'] == 'absent' and not st['kafka_mode']


def test_live_and_sources_pages(analyst, app, stores):
    app.extensions['sentinel_http'] = HTTP()
    html = analyst.get('/live').get_data(as_text=True)
    assert 'id="console"' in html and 'js/live.js' in html and 'Pause' in html and '<script>' not in html
    html = analyst.get('/sources').get_data(as_text=True)
    assert 'Chaîne d’acquisition' in html and 'Kafka' in html and 'Filebeat' in html and 'localhost:5140' in html
    assert 'Flux en direct' in analyst.get('/').get_data(as_text=True)


def test_worker_publishes_new_alerts_live(stores):
    msgs = []
    p = stores.redis.pubsub(ignore_subscribe_messages=True)
    p.subscribe(live.ALERTS_CHANNEL)
    live.publish_alert(stores.redis, {'id': 'x', 'rule_name': 'r', 'severity': 'critical', 'triggered_at': None})
    for _ in range(5):
        m = p.get_message(timeout=0.1)
        if m:
            msgs.append(json.loads(m['data']))
    assert msgs and msgs[0]['severity'] == 'critical'
