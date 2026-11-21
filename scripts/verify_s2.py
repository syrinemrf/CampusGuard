#!/usr/bin/env python3
"""Real end-to-end check of S2 against a RUNNING stack (docker compose up).

    docker compose up -d --build            # ES, Mongo, Redis, Logstash, Kibana, webapp
    docker compose exec webapp flask --app app.main seed-users     # note the printed passwords
    python scripts/verify_s2.py --base-url http://localhost:8000 --username analyste --password '<mot de passe>'

It exercises the whole chain: login → upload → validation/preview → confirm → Logstash → Elasticsearch
→ measured status → search by upload → CSV export → event detail, plus refusals (binary file,
duplicate). Nothing here is mocked: PASS means the real services did the work.
Exit code 0 only if every check passes.
"""
import argparse
import io
import json
import secrets
import sys
import time
from datetime import datetime, timezone

import requests

RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))
    return ok


def build_csv(token, valid=20, invalid=2):
    lines = ['timestamp,ip,user,outcome,level,message']
    base = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(valid):
        ts = (base.replace(minute=i % 60)).strftime('%Y-%m-%dT%H:%M:%SZ')
        lines.append(f'{ts},203.0.113.{i + 1},user_{i % 4},{"failure" if i % 3 == 0 else "success"},'
                     f'{"WARNING" if i % 3 == 0 else "INFO"},verify-s2 {token} row {i}')
    for i in range(invalid):
        lines.append(f'2026-10-30T13:00:00Z,999.999.0.{i},mallory,failure,WARNING,verify-s2 {token} bad {i}')
    return '\n'.join(lines) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--base-url', default='http://localhost:8000')
    ap.add_argument('--username', required=True)
    ap.add_argument('--password', required=True)
    ap.add_argument('--timeout', type=int, default=150, help='seconds to wait for Logstash/ES')
    ap.add_argument('--evidence', help='write a JSON evidence file to this path')
    args = ap.parse_args()
    base = args.base_url.rstrip('/')
    http = requests.Session()
    token = secrets.token_hex(4)

    r = http.get(f'{base}/ready', timeout=10)
    check('Dépendances prêtes (/ready)', r.status_code == 200, json.dumps(r.json().get('services')))
    r = http.post(f'{base}/api/auth/login', json={'username': args.username, 'password': args.password}, timeout=10)
    if not check('Connexion (session Redis)', r.status_code == 200, f'HTTP {r.status_code}'):
        return finish(args)
    http.headers['X-CSRF-Token'] = r.json()['csrf_token']
    check('Accès refusé sans session', requests.get(f'{base}/api/search', timeout=10).status_code == 401)

    content = build_csv(token)
    r = http.post(f'{base}/api/uploads', files={'file': (f'verify-{token}.csv', content, 'text/csv')}, timeout=30)
    doc = r.json()
    check('Upload validé (HTTP 201)', r.status_code == 201 and doc.get('state') == 'validated', f"HTTP {r.status_code} état={doc.get('state')}")
    stats = doc.get('stats') or {}
    check('Validation : 20 lignes valides, 2 invalides détectées', (stats.get('valid_rows'), stats.get('invalid_rows')) == (20, 2), str(stats))
    check('Aperçu : 10 lignes brutes', len((doc.get('preview') or {}).get('raw_lines', [])) == 10)
    upload_id = doc.get('id')
    if not upload_id:
        return finish(args)

    r = http.post(f'{base}/api/uploads', files={'file': ('copy.csv', content, 'text/csv')}, timeout=30)
    check('Doublon refusé (409)', r.status_code == 409, f'HTTP {r.status_code}')
    r = http.post(f'{base}/api/uploads', files={'file': ('x.csv', b'timestamp,ip\n\x00\x01', 'text/csv')}, timeout=30)
    check('Fichier binaire refusé (422)', r.status_code == 422 and r.json().get('state') == 'rejected', f'HTTP {r.status_code}')
    r = http.post(f'{base}/api/uploads', files={'file': ('x.exe', b'MZ', 'application/octet-stream')}, timeout=30)
    check('Extension interdite refusée (415)', r.status_code == 415, f'HTTP {r.status_code}')

    r = http.post(f'{base}/api/uploads/{upload_id}/confirm', timeout=30)
    check('Ingestion lancée (202)', r.status_code == 202 and r.json().get('state') == 'ingesting', f'HTTP {r.status_code}')

    deadline, state, last = time.time() + args.timeout, 'ingesting', {}
    while time.time() < deadline:
        last = http.get(f'{base}/api/uploads/{upload_id}', timeout=30).json()
        state = last.get('state')
        if state != 'ingesting':
            break
        time.sleep(3)
    check('Statut final mesuré = indexé', state == 'indexed' and last.get('indexed_count') == 20,
          f"état={state} indexés={last.get('indexed_count')} rejetés={last.get('rejected_count')}"
          + (' — rien indexé : voir `docker compose logs logstash`' if state == 'ingesting' else ''))

    r = http.get(f'{base}/api/search', params={'upload_id': upload_id, 'nocache': 1, 'size': 100}, timeout=30)
    body = r.json()
    check('Recherche par import : 20 événements', r.status_code == 200 and body.get('total') == 20, f"total={body.get('total')}")
    r = http.get(f'{base}/api/search', params={'upload_id': upload_id, 'outcome': 'failure', 'nocache': 1}, timeout=30)
    check('Filtre résultat=failure : 7 événements', r.json().get('total') == 7, f"total={r.json().get('total')}")
    r = http.get(f'{base}/api/search', params={'upload_id': upload_id, 'q': f'verify-s2 {token} row 3', 'nocache': 1}, timeout=30)
    check('Recherche plein texte', r.json().get('total', 0) >= 1, f"total={r.json().get('total')}")
    r = http.get(f'{base}/api/search', params={'upload_id': upload_id, 'ip': '203.0.113.5', 'nocache': 1}, timeout=30)
    check('Filtre IP exacte', r.json().get('total') == 1, f"total={r.json().get('total')}")
    r = http.get(f'{base}/api/search/export', params={'upload_id': upload_id}, timeout=30)
    rows = r.text.strip().splitlines()
    check('Export CSV identique (20 lignes + en-tête)', r.status_code == 200 and len(rows) == 21, f'{len(rows) - 1} lignes')
    hits = body.get('hits') or []
    if hits:
        r = http.get(f"{base}/api/events/{hits[0]['id']}", timeout=30)
        src = r.json().get('source', {})
        check('Détail d’un événement (champs ECS + labels.upload_id)',
              r.status_code == 200 and src.get('labels', {}).get('upload_id') == upload_id and 'ingested' in src.get('event', {}),
              f"index={r.json().get('index')}")
    r = http.get(f'{base}/api/search/history', timeout=10)
    check('Historique MongoDB enregistré', any(h['filters'].get('upload_id') == upload_id for h in r.json().get('history', [])))
    return finish(args)


def finish(args):
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if args.evidence:
        with open(args.evidence, 'w', encoding='utf-8') as fh:
            json.dump({'date_utc': datetime.now(timezone.utc).isoformat(), 'base_url': args.base_url,
                       'checks': [{'name': n, 'passed': ok, 'detail': d} for n, ok, d in RESULTS]}, fh, ensure_ascii=False, indent=2)
        print(f'Preuve écrite dans {args.evidence}')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
