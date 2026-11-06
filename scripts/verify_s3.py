#!/usr/bin/env python3
"""Real check of the S3 Kibana deliverable against a RUNNING stack (docker compose up).

    python scripts/verify_s3.py --kibana-url http://localhost:5601 \\
        [--app-url http://localhost:8000 --username analyste --password '<mdp>'] [--evidence docs/evidence/s3-verify-result.json]

Checks: Kibana is up, the data view + 4 visualizations + dashboard exist and reference each other, the dashboard
can be exported and re-imported (round trip), Kibana allows embedding in an iframe, the visualizations' fields
exist in the live index mapping, and (optionally) the web app serves the embedded dashboard page.
Exit code 0 only if every check passes. Nothing is mocked.
"""
import argparse
import io
import json
import sys
from datetime import datetime, timezone

import requests

DASHBOARD = 'sentinel-security-overview'
VIS = ['sentinel-vis-total-events', 'sentinel-vis-events-over-time', 'sentinel-vis-outcome-split', 'sentinel-vis-top-failing-ips']
RESULTS = []


def check(name, ok, detail=''):
    RESULTS.append((name, bool(ok), detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--kibana-url', default='http://localhost:5601')
    ap.add_argument('--elasticsearch-url', default='http://localhost:9200')
    ap.add_argument('--app-url')
    ap.add_argument('--username')
    ap.add_argument('--password')
    ap.add_argument('--evidence')
    args = ap.parse_args()
    kb = args.kibana_url.rstrip('/')
    hdr = {'kbn-xsrf': 'campusguard-verify'}

    try:
        r = requests.get(f'{kb}/api/status', timeout=15)
        check('Kibana joignable', r.status_code == 200, f"HTTP {r.status_code} niveau={r.json().get('status', {}).get('overall', {}).get('level')}")
    except requests.RequestException as exc:
        check('Kibana joignable', False, str(exc))
        return finish(args)

    r = requests.get(f'{kb}/api/saved_objects/index-pattern/campusguard-logs', timeout=15)
    check('Data view « CampusGuard logs » présente', r.status_code == 200, f'HTTP {r.status_code}')
    found = {}
    for vid in VIS:
        r = requests.get(f'{kb}/api/saved_objects/visualization/{vid}', timeout=15)
        found[vid] = r.status_code == 200
    check('4 visualisations présentes (indicateur, histogramme, camembert, tableau)', all(found.values()),
          ', '.join(f"{k.split('sentinel-vis-')[1]}={'ok' if v else 'ABSENT'}" for k, v in found.items()))
    r = requests.get(f'{kb}/api/saved_objects/dashboard/{DASHBOARD}', timeout=15)
    dash_ok = r.status_code == 200
    refs = {x['id'] for x in r.json().get('references', [])} if dash_ok else set()
    check('Dashboard présent et relié aux 4 visualisations', dash_ok and refs == set(VIS), f'HTTP {r.status_code} références={len(refs)}')

    r = requests.post(f'{kb}/api/saved_objects/_export', headers=hdr, timeout=30,
                      json={'objects': [{'type': 'dashboard', 'id': DASHBOARD}], 'includeReferencesDeep': True})
    lines = [json.loads(x) for x in r.text.splitlines() if x.strip()] if r.status_code == 200 else []
    objs = [x for x in lines if 'type' in x]
    check('Export du dashboard (dépendances comprises)', r.status_code == 200 and len(objs) >= 6, f'HTTP {r.status_code} objets={len(objs)}')
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
    except requests.RequestException as exc:
        check('Elasticsearch joignable pour le contrôle des champs', False, str(exc))

    if args.app_url and args.username and args.password:
        app = args.app_url.rstrip('/')
        s = requests.Session()
        r = s.post(f'{app}/api/auth/login', json={'username': args.username, 'password': args.password}, timeout=15)
        if check('Connexion à l’application', r.status_code == 200, f'HTTP {r.status_code}'):
            r = s.get(f'{app}/kibana', timeout=15)
            check('Page /kibana de l’application avec iframe du dashboard', r.status_code == 200 and '<iframe' in r.text and DASHBOARD in r.text,
                  f"HTTP {r.status_code} frame-src={'frame-src' in r.headers.get('Content-Security-Policy', '')}")
    return finish(args)


def finish(args):
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if args.evidence:
        with open(args.evidence, 'w', encoding='utf-8') as fh:
            json.dump({'date_utc': datetime.now(timezone.utc).isoformat(), 'kibana_url': args.kibana_url,
                       'checks': [{'name': n, 'passed': ok, 'detail': d} for n, ok, d in RESULTS]}, fh, ensure_ascii=False, indent=2)
        print(f'Preuve écrite dans {args.evidence}')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
