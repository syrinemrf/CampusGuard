#!/usr/bin/env python3
"""Real end-to-end check of S4 (alerting + SOAR-lite) against a RUNNING stack (docker compose up -d).

    python scripts/verify_s4.py --username admin --password '<mot de passe admin>' \\
        [--app-url http://localhost:8000 --logstash-url http://localhost:8088 --elasticsearch-url http://localhost:9200 \\
         --mailpit-url http://localhost:8025] [--self-block] [--evidence docs/evidence/verify_s4.json]

Path checked, nothing mocked:
  synthetic attack -> Logstash (json-security) -> Elasticsearch -> alert worker (rules) -> alert in MongoDB + ES
  -> e-mail in Mailpit (with PNG chart) + webhook received -> IP blocked in Redis (TTL) -> silencing of the same
  attack -> acknowledge / resolve -> MTTR -> manual unblock (audited).
--self-block also attacks the web application's own login page from this machine: its failed logins are shipped
to Logstash, detected, and THIS machine gets 403 until it is unblocked (done automatically at the end through
`docker compose exec webapp flask --app app.main unblock-ip`).
Exit code 0 only if every check passes (lines marked INFO are informative and not counted).
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import simulate_attack  # noqa: E402

RESULTS = []
UNREACHABLE = """La stack n'est pas joignable sur {url} (connexion refusée). Démarrez Docker Desktop, attendez « Engine running », puis : docker compose up -d --build --wait --wait-timeout 600 et docker compose ps (tout « healthy »). Aucune preuve n'est écrite."""


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))
    return ok


def info(name, detail):
    print(f'[INFO] {name} — {detail}')


class App:
    def __init__(self, base, username, password):
        self.base, self.s = base.rstrip('/'), requests.Session()
        r = self.s.post(f'{self.base}/api/auth/login', json={'username': username, 'password': password}, timeout=15)
        self.status = r.status_code
        self.csrf = r.json().get('csrf_token') if r.ok else None

    def get(self, path, **kw):
        return self.s.get(self.base + path, timeout=30, **kw)

    def send(self, method, path, body=None):
        return self.s.request(method, self.base + path, json=body, headers={'X-CSRF-Token': self.csrf or ''}, timeout=60)


def wait_for(predicate, timeout, step=3):
    deadline = time.time() + timeout
    while True:
        value = predicate()
        if value or time.time() > deadline:
            return value
        time.sleep(step)


def es_count(es, query):
    r = requests.post(f'{es}/logs-*/_count', json={'query': query}, timeout=15)
    return r.json().get('count', 0) if r.ok else 0


def find_alert(app, rule_id, group=None):
    for a in app.get(f'/api/alerts?rule={rule_id}&limit=50').json().get('alerts', []):
        if group is None or a['group'] == group:
            return a
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--app-url', default='http://localhost:8000')
    ap.add_argument('--logstash-url', default='http://localhost:8088')
    ap.add_argument('--elasticsearch-url', default='http://localhost:9200')
    ap.add_argument('--mailpit-url', default='http://localhost:8025')
    ap.add_argument('--username', required=True)
    ap.add_argument('--password', required=True)
    ap.add_argument('--self-block', action='store_true')
    ap.add_argument('--evidence')
    args = ap.parse_args()
    es = args.elasticsearch_url.rstrip('/')

    if '<' in args.password:
        print('[STOP] Remplacez « <mot de passe admin> » par le vrai mot de passe du compte admin (affiché par seed-users ou défini dans .env).')
        return 2
    try:
        app = App(args.app_url, args.username, args.password)
    except requests.ConnectionError:
        print('[STOP] ' + UNREACHABLE.format(url=args.app_url))
        return 2
    if not check('Connexion administrateur à l’application', app.status == 200, f'HTTP {app.status}'):
        return finish(args)
    rules = app.get('/api/alerts/rules').json().get('rules', [])
    enabled = {r['id'] for r in rules if r['enabled']}
    check('Règles par défaut présentes (scénario C)', {'brute-force-ip', 'credential-stuffing', 'sql-injection',
                                                       'privilege-escalation', 'unauthorized-country', 'off-hours-login'} <= enabled,
          f'{len(rules)} règles, actives : {sorted(enabled)}')
    worker = wait_for(lambda: app.get('/api/alerts/summary').json().get('worker'), 90)
    check('Worker d’alertes actif (battement de cœur Redis)', bool(worker),
          f"dernier cycle {worker.get('at')} — {worker.get('rules')} règles en {worker.get('duration_ms')} ms" if worker else 'aucun cycle depuis 90 s')

    ips = simulate_attack.pick_ips()
    events = simulate_attack.scenario(ips)
    try:
        sent = simulate_attack.send(events, args.logstash_url)
        check('Scénario d’attaque envoyé à Logstash (HTTP 8088)', sent == len(events), f'{sent} événements, IP {ips}')
    except (requests.RequestException, RuntimeError) as exc:
        check('Scénario d’attaque envoyé à Logstash (HTTP 8088)', False, str(exc))
        return finish(args)
    indexed = wait_for(lambda: es_count(es, {'terms': {'source.ip': [ips['brute'], ips['stuffer'], ips['sqli']]}}) >= 15, 90)
    check('Événements indexés dans Elasticsearch (logs-auth-*)', indexed, f"IP de test : {ips['brute']}, {ips['stuffer']}, {ips['sqli']}")
    geo = requests.post(f'{es}/logs-*/_search', timeout=15, json={'size': 1, 'query': {'term': {'source.ip': '8.8.8.8'}},
                                                                    '_source': ['source.geo']}).json()
    hits = geo.get('hits', {}).get('hits', [])
    country = ((hits[0]['_source'].get('source') or {}).get('geo') or {}).get('country_iso_code') if hits else None
    info('GeoIP de Logstash', f'8.8.8.8 → {country}' if country else 'pas de pays (base GeoLite non chargée) : la règle « pays non autorisé » ne peut pas se déclencher')

    run = app.send('POST', '/api/alerts/run')
    info('Cycle immédiat demandé', run.json() if run.ok else f'HTTP {run.status_code} (le worker tourne déjà : attente du cycle suivant)')
    expected = [('brute-force-ip', ips['brute']), ('credential-stuffing', ips['stuffer']), ('sql-injection', ips['sqli']),
                ('privilege-escalation', ips['sudo_user']), ('off-hours-login', ips['night_user'])]
    if country and country not in ('TN', 'FR'):
        expected.append(('unauthorized-country', '8.8.8.8'))
    found = {}
    for rule_id, group in expected:
        found[rule_id] = wait_for(lambda: find_alert(app, rule_id, group), 75)
        a = found[rule_id]
        check(f'Alerte « {rule_id} » levée pour {group}', a is not None,
              f"gravité {a['severity']}, {a['count']} évén., état {a['status']}" if a else 'absente après 75 s')

    bf = found.get('brute-force-ip')
    if bf:
        notes = {n['channel']: n for n in bf.get('notifications', [])}
        check('Notification e-mail envoyée (SMTP → Mailpit)', notes.get('email', {}).get('status') == 'sent', json.dumps(notes.get('email')))
        check('Notification webhook envoyée (avec retry)', notes.get('webhook', {}).get('status') == 'sent', json.dumps(notes.get('webhook')))
        try:
            mails = requests.get(f"{args.mailpit_url.rstrip('/')}/api/v1/search", params={'query': ips['brute']}, timeout=15).json()
            msg = (mails.get('messages') or [None])[0]
            check('E-mail reçu dans Mailpit (avec graphique PNG en pièce jointe)', bool(msg) and msg.get('Attachments', 0) >= 1,
                  f"sujet : {msg.get('Subject')} — pièces jointes : {msg.get('Attachments')}" if msg else 'aucun e-mail pour cette IP')
        except (requests.RequestException, ValueError) as exc:
            check('E-mail reçu dans Mailpit (avec graphique PNG en pièce jointe)', False, str(exc))
        inbox = app.get('/api/notifications/demo').json().get('webhooks', [])
        check('Webhook reçu par le récepteur de démonstration', any(w['payload'].get('group') == ips['brute'] for w in inbox),
              f'{len(inbox)} webhook(s) dans la boîte')
        block = next((b for b in app.get('/api/blocklist').json().get('active', []) if b['ip'] == ips['brute']), None)
        check('IP de l’attaquant bloquée dans Redis avec une durée (TTL)', bool(block) and block['remaining_seconds'] > 0,
              f"jusqu’à {block['until']} (reste {block['remaining_seconds']} s), motif : {block['reason']}" if block else 'non bloquée')
        doc = requests.get(f'{es}/sentinel-alerts-*/_search', params={'q': f"alert.id:{bf['id']}"}, timeout=15).json()
        check('Alerte copiée dans Elasticsearch (sentinel-alerts-*) pour Kibana', doc.get('hits', {}).get('total', {}).get('value', 0) >= 1)

        more = simulate_attack.scenario(ips, only=['brute-force'])[:3]
        for e in more:
            e['message'] += ' (relance)'
        simulate_attack.send(more, args.logstash_url)
        time.sleep(8)
        app.send('POST', '/api/alerts/run')
        again = wait_for(lambda: (lambda a: a if a and a.get('occurrences', 1) > 1 else None)(find_alert(app, 'brute-force-ip', ips['brute'])), 75)
        same = [a for a in app.get('/api/alerts?rule=brute-force-ip&limit=100').json()['alerts'] if a['group'] == ips['brute']]
        check('Silencing : la même attaque ne crée pas de 2e alerte', len(same) == 1 and bool(again),
              f"{len(same)} alerte(s) pour {ips['brute']}, occurrences = {again.get('occurrences') if again else '?'}")

        ack = app.send('POST', f"/api/alerts/{bf['id']}/acknowledge")
        res = app.send('POST', f"/api/alerts/{bf['id']}/resolve", {'note': 'verify_s4 : IP de test bloquée, aucune compromission'})
        check('Cycle d’incident : prise en compte puis résolution', ack.ok and res.ok and res.json().get('status') == 'resolved',
              f"HTTP {ack.status_code}/{res.status_code}, délai {res.json().get('time_to_resolve_s') if res.ok else '?'} s")
        stats = app.get('/api/alerts/stats').json()
        check('MTTR calculé', stats.get('mttr_seconds') is not None, f"MTTR = {stats.get('mttr_seconds')} s sur {stats.get('resolved')} alerte(s)")
        unblock = app.send('DELETE', f"/api/blocklist/{ips['brute']}")
        hist = app.get('/api/blocklist').json().get('history', [])
        check('Déblocage manuel audité', unblock.ok and any(h['ip'] == ips['brute'] and h['action'] == 'unblock' for h in hist),
              f'HTTP {unblock.status_code}')

    if args.self_block:
        self_block(app, args)
    return finish(args)


def self_block(app, args):
    """Brute force the app's own login from this machine and check that this machine gets 403, then unblock it."""
    probe = requests.Session()
    for i in range(6):
        probe.post(f'{app.base}/api/auth/login', json={'username': 'verify-nobody', 'password': f'wrong-{i}'}, timeout=15)
    app.send('POST', '/api/alerts/run')
    blocked = wait_for(lambda: requests.get(f'{app.base}/login', timeout=15).status_code == 403, 90)
    check('Auto-protection : 6 échecs sur la page de connexion → cette machine reçoit 403', blocked)
    if blocked:
        alert = None
        try:
            out = subprocess.run(['docker', 'compose', 'exec', '-T', 'redis', 'redis-cli', '--scan', '--pattern', 'sentinel:blocklist:*'],
                                 capture_output=True, text=True, timeout=30).stdout.split()
            for key in out:
                addr = key.split('sentinel:blocklist:', 1)[1]
                if not addr.startswith(('203.0.113.', '198.51.100.')):
                    subprocess.run(['docker', 'compose', 'exec', '-T', 'webapp', 'flask', '--app', 'app.main', 'unblock-ip', addr],
                                   capture_output=True, text=True, timeout=60)
                    alert = addr
        except (OSError, subprocess.SubprocessError) as exc:
            print(f'Déblocage automatique impossible ({exc}) : docker compose exec webapp flask --app app.main unblock-ip <IP>')
        check('Déblocage de cette machine (CLI flask unblock-ip, audité)', requests.get(f'{app.base}/login', timeout=15).status_code == 200,
              f'IP vue par l’application : {alert}')


def finish(args):
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if args.evidence:
        with open(args.evidence, 'w', encoding='utf-8') as fh:
            json.dump({'date_utc': datetime.now(timezone.utc).isoformat(), 'app_url': args.app_url,
                       'checks': [{'name': n, 'passed': ok, 'detail': d} for n, ok, d in RESULTS]}, fh, ensure_ascii=False, indent=2)
        print(f'Preuve écrite dans {args.evidence}')
    return 0 if RESULTS and passed == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
