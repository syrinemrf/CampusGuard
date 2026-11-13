#!/usr/bin/env python3
"""Real check of the S3 Kibana deliverable against a RUNNING stack (docker compose up).

    python scripts/verify_s3.py --kibana-url http://localhost:5601 \\
        [--app-url http://localhost:8000 --username analyste --password '<mdp>'] [--evidence docs/evidence/s3-verify-result.json]

Checks: Kibana is up, the 2 data views + 12 visualizations + dashboard exist and reference each other, the dashboard
can be exported and re-imported (round trip), Kibana allows embedding in an iframe, the visualizations' fields
exist in the live index mapping, and (optionally) the web app serves the embedded dashboard page.
Exit code 0 only if every check passes. Nothing is mocked.
"""
import argparse
import io
import json
import sys
from datetime import datetime, timezone

import pathlib

import requests

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.kibana import ALERTS_DATA_VIEW_ID, DASHBOARD_ID as DASHBOARD, RUNTIME_FIELDS, VISUALIZATION_IDS  # noqa: E402

VIS = list(VISUALIZATION_IDS.values())
UNREACHABLE = """La stack n'est pas joignable sur {url} (connexion refusée). Démarrez Docker Desktop, attendez « Engine running », puis : docker compose up -d --build --wait --wait-timeout 600 et docker compose ps (tout « healthy »). Aucune preuve n'est écrite."""

def default_es_url():
    """Elasticsearch URL as published by docker compose: ELASTICSEARCH_PORT from the environment or .env (default 9200)."""
    import os
    port = os.getenv('ELASTICSEARCH_PORT')
    env = pathlib.Path(__file__).resolve().parents[1] / '.env'
    if not port and env.exists():
        for line in env.read_text(encoding='utf-8', errors='ignore').splitlines():
            if line.strip().startswith('ELASTICSEARCH_PORT='):
                port = line.split('=', 1)[1].strip()
    return f'http://localhost:{port or 9200}'


RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--kibana-url', default='http://localhost:5601')
    ap.add_argument('--elasticsearch-url', default=default_es_url(), help='défaut : port ELASTICSEARCH_PORT de .env')
    ap.add_argument('--app-url')
    ap.add_argument('--username')
    ap.add_argument('--password')
    ap.add_argument('--evidence')
    args = ap.parse_args()
    kb = args.kibana_url.rstrip('/')
    if args.password and '<' in args.password:
        print('[STOP] Remplacez « <mdp> » par le vrai mot de passe du compte (affiché par seed-users ou défini dans .env).')
        return 2
    hdr = {'kbn-xsrf': 'campusguard-verify'}

    try:
        r = requests.get(f'{kb}/api/status', timeout=15)
        check('Kibana joignable', r.status_code == 200, f"HTTP {r.status_code} niveau={r.json().get('status', {}).get('overall', {}).get('level')}")
    except requests.ConnectionError:
        print('[STOP] ' + UNREACHABLE.format(url=kb))
        return 2
    except requests.RequestException as exc:
        check('Kibana joignable', False, str(exc))
        return finish(args)

    r = requests.get(f'{kb}/api/saved_objects/index-pattern/campusguard-logs', timeout=15)
    runtime = json.loads(r.json().get('attributes', {}).get('runtimeFieldMap') or '{}') if r.status_code == 200 else {}
    check('Data view « CampusGuard logs » présente avec les champs runtime heure/jour', r.status_code == 200 and set(RUNTIME_FIELDS) <= set(runtime),
          f'HTTP {r.status_code} runtime={sorted(runtime)}')
    r = requests.get(f'{kb}/api/saved_objects/index-pattern/{ALERTS_DATA_VIEW_ID}', timeout=15)
    check('Data view « CampusGuard alertes » présente', r.status_code == 200, f'HTTP {r.status_code}')
    found = {}
    for vid in VIS:
        r = requests.get(f'{kb}/api/saved_objects/visualization/{vid}', timeout=15)
        found[vid] = r.status_code == 200
    check(f'{len(VIS)} visualisations présentes', all(found.values()),
          ', '.join(f"{k.split('sentinel-vis-')[1]}={'ok' if v else 'ABSENT'}" for k, v in found.items()))
    r = requests.get(f'{kb}/api/saved_objects/dashboard/{DASHBOARD}', timeout=15)
    dash_ok = r.status_code == 200
    refs = {x['id'] for x in r.json().get('references', [])} if dash_ok else set()
    check(f'Dashboard présent et relié aux {len(VIS)} visualisations', dash_ok and refs == set(VIS), f'HTTP {r.status_code} références={len(refs)}')

    r = requests.post(f'{kb}/api/saved_objects/_export', headers=hdr, timeout=30,
                      json={'objects': [{'type': 'dashboard', 'id': DASHBOARD}], 'includeReferencesDeep': True})
    lines = [json.loads(x) for x in r.text.splitlines() if x.strip()] if r.status_code == 200 else []
    objs = [x for x in lines if 'type' in x]
    check('Export du dashboard (dépendances comprises)', r.status_code == 200 and len(objs) >= len(VIS) + 3, f'HTTP {r.status_code} objets={len(objs)}')
    if objs:
        payload = ''.join(json.dumps(o) + '\n' for o in objs)
        r = requests.post(f'{kb}/api/saved_objects/_import?overwrite=true', headers=hdr, timeout=60,
                          files={'file': ('roundtrip.ndjson', io.BytesIO(payload.encode()), 'application/ndjson')})
        body = r.json() if r.headers.get('content-type', '').startswith('application/json') else {}
        check('Ré-import de l’export (aller-retour)', r.status_code == 200 and body.get('success') is True,
              f"HTTP {r.status_code} importés={body.get('successCount')} erreurs={body.get('errors', [])[:1]}")

    r = requests.get(f'{kb}/app/dashboards', timeout=15)
    xfo = r.headers.get('X-Frame-Options')
    csp = r.headers.get('Content-Security-Policy', '')
    check('Kibana autorise l’intégration en iframe', r.status_code == 200 and not xfo and 'frame-ancestors' not in csp,
          f"X-Frame-Options={xfo} frame-ancestors={'oui' if 'frame-ancestors' in csp else 'non'}")

    try:
        m = requests.get(f'{args.elasticsearch_url.rstrip("/")}/logs-*/_mapping/field/log.level,event.outcome,source.ip,@timestamp', timeout=15)
        names = {f for idx in m.json().values() for f in idx.get('mappings', {})} if m.status_code == 200 else set()
        check('Champs des visualisations présents dans le mapping réel', {'log.level', 'event.outcome', 'source.ip', '@timestamp'} <= names,
              f'trouvés : {sorted(names)}' if names else f'HTTP {m.status_code} (aucun index logs-* ?)')
        c = requests.get(f'{args.elasticsearch_url.rstrip("/")}/logs-*/_count', timeout=15).json().get('count', 0)
        check('Des données existent à afficher', c > 0, f'{c} documents')
        # The painless scripts of the runtime fields really compile and run on the live data (heatmap).
        h = requests.post(f'{args.elasticsearch_url.rstrip("/")}/logs-*/_search', timeout=30, json={
            'size': 0, 'runtime_mappings': RUNTIME_FIELDS,
            'aggs': {'h': {'terms': {'field': 'hour_of_day', 'size': 24}}, 'd': {'terms': {'field': 'day_of_week', 'size': 7}}}})
        aggs = h.json().get('aggregations', {}) if h.status_code == 200 else {}
        check('Champs runtime heure/jour calculés par Elasticsearch (carte de chaleur)',
              h.status_code == 200 and bool(aggs.get('h', {}).get('buckets')),
              f"HTTP {h.status_code} heures={len(aggs.get('h', {}).get('buckets', []))} jours={[b['key'] for b in aggs.get('d', {}).get('buckets', [])]}")
    except requests.RequestException as exc:
        check('Elasticsearch joignable pour le contrôle des champs', False, str(exc))

    if args.app_url and args.username and args.password:
        app = args.app_url.rstrip('/')
        s = requests.Session()
        r = s.post(f'{app}/api/auth/login', json={'username': args.username, 'password': args.password}, timeout=15)
        if not check('Connexion à l’application', r.status_code == 200, f'HTTP {r.status_code}'):
            print('       Mot de passe refusé : vérifiez SEED_..._PASSWORD dans .env, ou redéfinissez-le avec '
                  'docker compose exec webapp flask --app app.main set-password <compte>')
        else:
            r = s.get(f'{app}/kibana', timeout=15)
            check('Page /kibana de l’application avec iframe du dashboard', r.status_code == 200 and '<iframe' in r.text and DASHBOARD in r.text,
                  f"HTTP {r.status_code} frame-src={'frame-src' in r.headers.get('Content-Security-Policy', '')}")
    return finish(args)


def finish(args):
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if args.evidence and RESULTS and passed == len(RESULTS):
        with open(args.evidence, 'w', encoding='utf-8') as fh:
            json.dump({'date_utc': datetime.now(timezone.utc).isoformat(), 'kibana_url': args.kibana_url,
                       'checks': [{'name': n, 'passed': ok, 'detail': d} for n, ok, d in RESULTS]}, fh, ensure_ascii=False, indent=2)
        print(f'Preuve écrite dans {args.evidence}')
    elif args.evidence:
        print(f'Preuve NON écrite ({args.evidence} inchangé) : corrigez les contrôles en échec puis relancez.')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
