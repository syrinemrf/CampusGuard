"""Vérification S5 sur la stack Docker réelle : flux continu, WebSocket, latence, GeoIP, alertes, escalade, rapport.

    python scripts/verify_s5.py --password <mot de passe analyste> [--admin-password ...] [--evidence]

Rejoue 600 lignes du journal sshd réel vers Logstash (TCP 5140, ou via Filebeat → Kafka si le profil stream tourne),
écoute la WebSocket /ws/live comme le ferait la page « Flux en direct », et contrôle chaque étape.
"""
import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_s3 import default_es_url  # noqa: E402

RESULTS = []
LINES = 600
REAL_ATTACKERS = ('103.99.', '112.95.', '187.141.', '5.188.')     # /16 conservé par la pseudonymisation


def check(name, ok, detail=''):
    RESULTS.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))


def login(url, user, password):
    s = requests.Session()
    r = s.post(f'{url}/api/auth/login', json={'username': user, 'password': password}, timeout=10)
    if r.status_code != 200:
        sys.exit(f'STOP : connexion « {user} » refusée (HTTP {r.status_code}).')
    s.headers['X-CSRF-Token'] = r.json()['csrf_token']
    return s


class Listener(threading.Thread):
    """Client WebSocket : compte les lignes et alertes reçues, garde les latences mesurées par le serveur."""

    def __init__(self, url, session):
        super().__init__(daemon=True)
        import simple_websocket
        host = url.split('://', 1)[1]
        self.ws = simple_websocket.Client.connect(f'ws://{host}/ws/live', headers={
            'Origin': url, 'Cookie': f"sentinel_session={session.cookies.get('sentinel_session')}"})
        self.lines, self.alerts, self.latencies, self.metrics, self.stop = 0, [], [], None, False

    def run(self):
        while not self.stop:
            try:
                raw = self.ws.receive(timeout=1)
            except Exception:  # noqa: BLE001
                return
            if not raw:
                continue
            msg = json.loads(raw)
            if msg['type'] == 'logs':
                self.lines += len(msg['items'])
                self.latencies += [i['latency_ms'] for i in msg['items'] if i.get('latency_ms') is not None]
            elif msg['type'] == 'alert':
                self.alerts.append(msg['alert'])
            elif msg['type'] == 'metrics':
                self.metrics = msg


def pct(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * (len(v) - 1)))] if v else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--url', default='http://localhost:8000')
    ap.add_argument('--es', default=default_es_url())
    ap.add_argument('--password', required=True, help='mot de passe du compte analyste')
    ap.add_argument('--admin-password', help='mot de passe admin (évaluation immédiate des règles)')
    ap.add_argument('--evidence', action='store_true')
    a = ap.parse_args(argv)
    url = a.url.rstrip('/')
    try:
        analyst = login(url, 'analyste', a.password)
    except requests.RequestException:
        sys.exit(f'STOP : {url} injoignable. docker compose up -d --build')

    st = analyst.get(f'{url}/api/stream/status', timeout=15).json()
    hops = {h['key']: h for h in st['chain']}
    check('Pipeline Logstash « stream-security » chargé', hops['logstash']['status'] == 'ok', hops['logstash']['detail'])
    kafka = st['kafka_mode'] and hops['filebeat']['status'] == 'ok'
    check('Mode d’acquisition détecté', True, 'Filebeat → Kafka → Logstash' if kafka else 'TCP 5140 direct (profil stream non lancé)')

    listener = Listener(url, analyst)
    listener.start()
    time.sleep(1.5)
    before = requests.get(f'{a.es}/logs-ssh-*/_count', timeout=5).json().get('count', 0) if requests.get(f'{a.es}/logs-ssh-*/_count', timeout=5).ok else 0
    args = [sys.executable, str(ROOT / 'scripts/replay_openssh.py'), '--speed', '0', '--limit', str(LINES)]
    if not (ROOT / 'datasets/raw/OpenSSH_2k.log').exists():
        args.append('--download')
    if not kafka:
        args += ['--to', 'tcp']
    t0 = time.monotonic()
    run = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    check('Rejeu du journal sshd réel', run.returncode == 0, (run.stderr or run.stdout).strip().splitlines()[-1] if (run.stderr or run.stdout) else '')

    deadline = time.monotonic() + 90
    count = before
    while time.monotonic() < deadline:
        r = requests.get(f'{a.es}/logs-ssh-*/_count', timeout=5)
        count = r.json().get('count', 0) if r.ok else 0
        if count - before >= LINES:
            break
        time.sleep(2)
    check(f'{LINES} lignes indexées dans logs-ssh-*', count - before >= LINES, f'{count - before} nouvelles en {round(time.monotonic() - t0, 1)} s')
    time.sleep(3)
    check('Lignes poussées sur la WebSocket', listener.lines >= LINES * 0.95, f'{listener.lines} reçues')
    p50, p95 = pct(listener.latencies, .5), pct(listener.latencies, .95)
    check('Latence de bout en bout < 1 s (médiane)', p50 is not None and p50 < 1000, f'médiane {p50} ms, p95 {p95} ms')
    m = listener.metrics or {}
    check('Métriques en direct reçues', 'logs_per_s' in m and m.get('connected_users') is not None,
          f"{m.get('logs_per_s')} logs/s, {m.get('errors_per_min')} erreurs/min, {m.get('connected_users')} utilisateur(s)")

    q = {'size': 0, 'query': {'bool': {'filter': [{'range': {'@timestamp': {'gte': 'now-10m'}}}, {'term': {'event.outcome': 'failure'}}]}},
         'aggs': {'c': {'terms': {'field': 'source.geo.country_iso_code', 'size': 5}}}}
    countries = requests.post(f'{a.es}/logs-ssh-*/_search', json=q, timeout=10).json().get('aggregations', {}).get('c', {}).get('buckets', [])
    check('GeoIP sur les IP pseudonymisées (pays des échecs)', bool(countries), ', '.join(f"{b['key']} {b['doc_count']}" for b in countries))

    if a.admin_password:
        admin = login(url, 'admin', a.admin_password)
        time.sleep(2)
        admin.post(f'{url}/api/alerts/run', timeout=120)
    deadline = time.monotonic() + 100
    alerts = []
    while time.monotonic() < deadline:
        alerts = analyst.get(f'{url}/api/alerts', params={'status': 'active'}, timeout=10).json()
        alerts = alerts if isinstance(alerts, list) else alerts.get('alerts', [])
        if any(x['rule_id'] == 'brute-force-ip' and str(x.get('group', '')).startswith(REAL_ATTACKERS) for x in alerts):
            break
        time.sleep(5)
    bf = next((x for x in alerts if x['rule_id'] == 'brute-force-ip' and str(x.get('group', '')).startswith(REAL_ATTACKERS)), None)
    check('Force brute réelle détectée (attaquants du journal LabSZ)', bf is not None, bf['message'] if bf else 'aucune alerte après 100 s')
    check('Alerte poussée en direct sur la WebSocket', bool(listener.alerts), f'{len(listener.alerts)} alerte(s) reçue(s)')

    if bf:
        aid = bf['id']
        r1 = analyst.post(f'{url}/api/alerts/{aid}/comments', json={'text': 'verify_s5 : IP du journal LabSZ'}, timeout=10)
        r2 = analyst.post(f'{url}/api/alerts/{aid}/snooze', json={'minutes': 15}, timeout=10)
        r3 = analyst.post(f'{url}/api/alerts/{aid}/acknowledge', json={}, timeout=10)
        check('Incident : commentaire, mise en veille, prise en compte', (r1.status_code, r2.status_code, r3.status_code) == (201, 200, 200),
              f'{r1.status_code}, {r2.status_code}, {r3.status_code}')

    month = datetime.now(timezone.utc).strftime('%Y-%m')
    pdf = analyst.get(f'{url}/api/reports/monthly', params={'month': month}, timeout=60)
    check('Rapport mensuel de conformité (PDF)', pdf.status_code == 200 and pdf.content.startswith(b'%PDF'), f'{len(pdf.content) // 1024} Ko')
    rules = analyst.get(f'{url}/api/alerts/rules', timeout=10).json()
    rules = rules if isinstance(rules, list) else rules.get('rules', [])
    ml = next((r for r in rules if r.get('id', r.get('_id')) == 'ml-anomaly-ssh'), None)
    check('Règle Isolation Forest présente et évaluée', ml is not None and ml.get('last_status') in ('ok', None),
          f"dernier état : {ml.get('last_status') if ml else 'absente'}")

    listener.stop = True
    passed = sum(r['ok'] for r in RESULTS)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if a.evidence and passed == len(RESULTS):
        out = ROOT / 'docs/evidence/verify_s5.json'
        out.write_text(json.dumps({'at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'mode': 'kafka' if kafka else 'tcp',
                                   'latency_ms': {'p50': p50, 'p95': p95, 'samples': len(listener.latencies)},
                                   'results': RESULTS}, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'Preuve : {out}')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    raise SystemExit(main())
