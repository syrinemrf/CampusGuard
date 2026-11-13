"""The attack scenario and the real-stack verification script stay consistent with the default rules."""
import importlib.util
import pathlib
import re
import sys
from datetime import datetime, timedelta, timezone

from app.alerting import rules as R

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import simulate_attack as S  # noqa: E402

NOW = datetime(2026, 11, 13, 21, 0, tzinfo=timezone.utc)


def test_each_part_matches_the_rule_it_is_meant_to_trigger():
    ips = S.pick_ips(seed=1)
    ev = S.scenario(ips, NOW)
    brute = [e for e in ev if e['source_ip'] == ips['brute']]
    assert len(brute) == 8 and all(e['outcome'] == 'failure' and e['event']['category'] == 'authentication' for e in brute)
    stamps = sorted(datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00')) for e in brute)
    assert stamps[-1] - stamps[0] < timedelta(minutes=5)                       # brute-force-ip: >= 5 in 5 min
    assert len({e['username'] for e in ev if e['source_ip'] == ips['stuffer']}) >= 5   # credential-stuffing
    sqli = next(e for e in ev if e['source_ip'] == ips['sqli'])
    assert re.search(next(r for r in R.DEFAULT_RULES if r['id'] == 'sql-injection')['pattern'], sqli['message'])
    night = next(e for e in ev if e['username'] == ips['night_user'])
    local = datetime.fromisoformat(night['timestamp'].replace('Z', '+00:00')) + timedelta(hours=1)
    assert local.hour == 3 and NOW - timedelta(hours=24) <= datetime.fromisoformat(night['timestamp'].replace('Z', '+00:00')) <= NOW
    assert next(e for e in ev if e['username'] == ips['sudo_user'])['action'] == 'sudo'


def test_only_documentation_addresses_except_the_single_geoip_example():
    import ipaddress
    doc = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
    for e in S.scenario(S.pick_ips(seed=2), NOW):
        addr = ipaddress.ip_address(e['source_ip'])
        assert any(addr in n for n in doc) or e['source_ip'] == '8.8.8.8'
        assert e['labels']['provenance'] == 'simulate_attack'


def test_events_have_the_shape_expected_by_the_json_pipeline():
    conf = (ROOT / 'ingestion/logstash/pipeline/json.conf').read_text(encoding='utf-8')
    for key in ('source_ip', 'username', 'outcome', 'action', 'level', 'message', 'timestamp'):
        assert f"'{key}'" in conf or f'"{key}"' in conf
    for e in S.scenario(S.pick_ips(seed=3), NOW):
        assert re.fullmatch(r'[A-Za-z0-9._-]+', e['action']) and e['outcome'] in ('success', 'failure')
        assert isinstance(e['service'], dict) and isinstance(e['event'], dict)


def test_verify_script_imports_and_covers_the_whole_loop():
    spec = importlib.util.spec_from_file_location('verify_s4', ROOT / 'scripts' / 'verify_s4.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    text = (ROOT / 'scripts' / 'verify_s4.py').read_text(encoding='utf-8')
    for needle in ('/api/alerts/run', 'Mailpit', '/api/notifications/demo', 'sentinel-alerts-*', 'Silencing', 'MTTR', 'unblock-ip'):
        assert needle in text


def test_compose_runs_a_separate_worker_and_a_local_mail_catcher():
    import yaml
    c = yaml.safe_load((ROOT / 'docker-compose.yml').read_text(encoding='utf-8'))['services']
    w = c['alert-worker']
    assert w['command'] == ['python', '-m', 'app.alerting.worker'] and w['build'] == c['webapp']['build']
    assert '--healthcheck' in w['healthcheck']['test'] and w['restart'] == 'unless-stopped'
    assert c['mailpit']['ports'] == ['127.0.0.1:8025:8025'] and 'profiles' not in c['mailpit']
    assert c['webapp']['environment']['LOGSTASH_HTTP_URL'] == 'http://logstash:8088'
    assert 'demo' in c['alert-worker']['environment']['ALERT_WEBHOOK_URL']
