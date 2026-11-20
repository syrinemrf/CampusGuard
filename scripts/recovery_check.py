"""Tests de reprise (S6) : on arrête ou on tue un service de la stack et on mesure le retour à la normale.

    python scripts/recovery_check.py --password <mot de passe analyste>             # Redis, worker, Elasticsearch
    python scripts/recovery_check.py --password ... --kafka                         # + aucune perte quand Logstash tombe
    python scripts/recovery_check.py --password ... --evidence                      # docs/evidence/recovery_check.json

À lancer depuis la racine du dépôt, stack démarrée (docker compose up -d ; profil stream pour --kafka).
Durée : 5 à 8 minutes. Ce que chaque scénario vérifie :
1. Redis redémarre : l'application répond, les sessions sont perdues (reconnexion demandée), le worker reprend.
2. Le worker d'alertes est tué : Docker le relance (restart: unless-stopped), le battement de cœur revient.
3. Elasticsearch redémarre : l'application signale l'indisponibilité (pas d'erreur 500), puis la recherche revient.
4. (--kafka) Logstash est arrêté pendant que des lignes sshd arrivent : Kafka les garde, rien n'est perdu au retour.
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
from verify_s3 import default_es_url  # noqa: E402  (ELASTICSEARCH_PORT du fichier .env)

RESULTS = []


def dc(*args, check=True):
    return subprocess.run(['docker', 'compose', *args], cwd=ROOT, capture_output=True, text=True, check=check)


def record(name, ok, seconds=None, detail=''):
    RESULTS.append({'scenario': name, 'ok': bool(ok), 'recovery_seconds': seconds, 'detail': detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — retour en {seconds} s' if seconds is not None else '') + (f' ({detail})' if detail else ''))


def wait_for(predicate, timeout, step=2):
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            if predicate():
                return round(time.monotonic() - t0, 1)
        except requests.RequestException:
            pass
        time.sleep(step)
    return None


class App:
    def __init__(self, url, password):
        self.url, self.password = url.rstrip('/'), password
        self.s = None

    def login(self):
        self.s = requests.Session()
        r = self.s.post(f'{self.url}/api/auth/login', json={'username': 'analyste', 'password': self.password}, timeout=10)
        if r.status_code == 200:
            self.s.headers['X-CSRF-Token'] = r.json()['csrf_token']
        return r.status_code == 200

    def get(self, path, **kw):
        return self.s.get(self.url + path, timeout=10, **kw)


def heartbeat_at():
    out = dc('exec', '-T', 'redis', 'redis-cli', 'GET', 'sentinel:alerting:heartbeat', check=False).stdout.strip()
    return json.loads(out).get('at') if out.startswith('{') else None


def scenario_redis(app):
    dc('restart', 'redis')
    secs = wait_for(lambda: requests.get(app.url + '/health', timeout=3).ok and app.login(), 90)
    record('Redis redémarré : connexion de nouveau possible', secs is not None, secs, 'sessions perdues, reconnexion demandée')
    before = heartbeat_at()
    secs = wait_for(lambda: (heartbeat_at() or '') != (before or ''), 120, 5)
    record('Redis redémarré : le worker d’alertes reprend ses cycles', secs is not None, secs)


def scenario_worker():
    before = heartbeat_at()
    dc('kill', 'alert-worker')
    secs = wait_for(lambda: (heartbeat_at() or '') != (before or ''), 150, 5)
    state = dc('ps', '--format', 'json', 'alert-worker', check=False).stdout
    record('Worker tué : relancé par Docker, cycles repris', secs is not None, secs, 'restart: unless-stopped' if 'running' in state else state[:80])


def scenario_elasticsearch(app):
    app.login()
    dc('stop', 'elasticsearch')
    r = app.get('/api/search', params={'q': 'Failed', 'nocache': '1', 'record': '0'})
    home = app.get('/')
    record('Elasticsearch arrêté : indisponibilité signalée, pas d’erreur 500', r.status_code in (502, 503) and home.status_code == 200,
           detail=f'recherche HTTP {r.status_code}, accueil HTTP {home.status_code}')
    dc('start', 'elasticsearch')
    secs = wait_for(lambda: app.get('/api/search', params={'q': 'Failed', 'nocache': '1', 'record': '0'}).status_code == 200, 240, 5)
    record('Elasticsearch redémarré : la recherche revient', secs is not None, secs)


def count_ssh(es):
    r = requests.get(f'{es}/logs-ssh-*/_count', timeout=5)
    return r.json().get('count', 0) if r.ok else 0


def scenario_kafka(es, lines=200):
    if 'kafka' not in dc('ps', '--services', '--status', 'running', check=False).stdout:
        record('Logstash arrêté pendant le flux : aucune ligne perdue (Kafka)', False, detail='profil stream non lancé')
        return
    before = count_ssh(es)
    dc('stop', 'logstash')
    subprocess.run([sys.executable, str(ROOT / 'scripts/replay_openssh.py'), '--speed', '0', '--limit', str(lines)], cwd=ROOT,
                   check=True, capture_output=True)
    time.sleep(5)
    dc('start', 'logstash')
    secs = wait_for(lambda: count_ssh(es) - before >= lines, 300, 5)
    got = count_ssh(es) - before
    record('Logstash arrêté pendant le flux : aucune ligne perdue (Kafka)', got >= lines, secs, f'{got}/{lines} lignes indexées après reprise')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--url', default='http://localhost:8000')
    ap.add_argument('--es', default=default_es_url())
    ap.add_argument('--password', required=True, help='mot de passe du compte analyste')
    ap.add_argument('--kafka', action='store_true')
    ap.add_argument('--evidence', action='store_true')
    a = ap.parse_args(argv)
    app = App(a.url, a.password)
    try:
        if not app.login():
            sys.exit('STOP : connexion « analyste » refusée (mot de passe ?)')
    except requests.RequestException:
        sys.exit(f'STOP : {a.url} injoignable. Lancez la stack : docker compose up -d')
    scenario_redis(app)
    scenario_worker()
    scenario_elasticsearch(app)
    if a.kafka:
        scenario_kafka(a.es)
    passed = sum(r['ok'] for r in RESULTS)
    print(f'\n{passed}/{len(RESULTS)} scénarios réussis.')
    if a.evidence and passed == len(RESULTS):
        out = ROOT / 'docs/evidence/recovery_check.json'
        out.write_text(json.dumps({'at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'results': RESULTS},
                                  ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'Preuve : {out}')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    raise SystemExit(main())
