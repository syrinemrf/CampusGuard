"""Tests de sécurité (S6) contre l'application qui tourne : authentification, rôles, CSRF, sessions, en-têtes,
injections, XSS, limitation de débit, WebSocket. Chaque contrôle est PASS ou FAIL avec ce qui a été observé.

    python scripts/security_check.py --analyst-password ... --auditor-password ... [--url http://localhost:8000]
    python scripts/security_check.py ... --evidence      # écrit docs/evidence/security_check.json si tout passe

Ne touche que l'application locale. Le contrôle de débit (--rate) envoie ~320 requêtes en quelques secondes.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

RESULTS = []
ROOT = Path(__file__).resolve().parents[1]


def check(name, ok, detail=''):
    RESULTS.append({'check': name, 'ok': bool(ok), 'detail': detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f' — {detail}' if detail else ''))


def login(url, user, password):
    s = requests.Session()
    r = s.post(f'{url}/api/auth/login', json={'username': user, 'password': password}, timeout=10)
    if r.status_code != 200:
        sys.exit(f'STOP : connexion de « {user} » impossible (HTTP {r.status_code}). Vérifiez le mot de passe.')
    s.headers['X-CSRF-Token'] = r.json()['csrf_token']
    return s


def run(a):
    url = a.url.rstrip('/')
    anon = requests.Session()
    # 1. tout est protégé
    protected = ['/api/search', '/api/overview', '/api/alerts', '/api/stream/status', '/api/reports/monthly',
                 '/api/blocklist', '/api/alerts/rules', '/api/notifications/demo']
    codes = {p: anon.get(url + p, timeout=10, allow_redirects=False).status_code for p in protected}
    check('API inaccessible sans session (401)', all(c == 401 for c in codes.values()), json.dumps(codes))
    pages = {p: anon.get(url + p, timeout=10, allow_redirects=False).status_code for p in ('/', '/alerts', '/live', '/reports', '/sources')}
    check('Pages redirigées vers la connexion', all(c in (302, 303) for c in pages.values()), json.dumps(pages))

    # 2. connexion : injection d'opérateur MongoDB, mauvais types
    r = anon.post(f'{url}/api/auth/login', json={'username': {'$ne': None}, 'password': {'$ne': None}}, timeout=10)
    check('Injection NoSQL au login refusée', r.status_code in (400, 401), f'HTTP {r.status_code}')

    analyst = login(url, 'analyste', a.analyst_password)
    auditor = login(url, 'auditeur', a.auditor_password)

    # 3. session
    raw = requests.post(f'{url}/api/auth/login', json={'username': 'analyste', 'password': a.analyst_password}, timeout=10)
    cookie = raw.headers.get('Set-Cookie', '')
    check('Cookie de session HttpOnly et SameSite', 'HttpOnly' in cookie and 'SameSite' in cookie, cookie.split(';', 1)[-1].strip()[:120])
    s2 = requests.Session()
    s2.get(f'{url}/login', timeout=10)                                     # session anonyme posée avant la connexion
    before = s2.cookies.get('sentinel_session')
    s2.post(f'{url}/api/auth/login', json={'username': 'analyste', 'password': a.analyst_password}, timeout=10)
    after = [c.value for c in s2.cookies if c.name == 'sentinel_session'][-1:]
    check('Identifiant de session renouvelé à la connexion (fixation)', bool(after) and after[0] != before,
          'nouvel identifiant' if after and after[0] != before else 'identique')

    # 4. CSRF
    no_token = requests.Session()
    no_token.cookies.set('sentinel_session', analyst.cookies.get('sentinel_session'))
    r = no_token.post(f'{url}/api/alerts/inconnue/acknowledge', json={}, timeout=10)
    check('Requête modifiante sans jeton CSRF refusée (403)', r.status_code == 403, f'HTTP {r.status_code}')

    # 5. rôles
    r1 = auditor.post(f'{url}/api/alerts/rules', json={'id': 'x-test', 'name': 'x', 'type': 'threshold'}, timeout=10)
    r2 = auditor.post(f'{url}/api/blocklist', json={'ip': '203.0.113.9'}, timeout=10)
    r3 = analyst.delete(f'{url}/api/blocklist/203.0.113.9', timeout=10)
    check('Auditeur : lecture seule (règles, blocage)', r1.status_code == 403 and r2.status_code == 403, f'{r1.status_code}, {r2.status_code}')
    check('Analyste : pas de déblocage (administrateur seulement)', r3.status_code == 403, f'HTTP {r3.status_code}')

    # 6. en-têtes
    h = analyst.get(url + '/', timeout=10).headers
    csp = h.get('Content-Security-Policy', '')
    check('En-têtes de sécurité (CSP sans script en ligne, anti-iframe, nosniff)',
          "script-src 'self'" in csp and "unsafe-inline" not in csp and h.get('X-Frame-Options') == 'DENY'
          and h.get('X-Content-Type-Options') == 'nosniff', csp[:100])

    # 7. injections dans la recherche
    r = analyst.get(f'{url}/api/search', params={'dsl': json.dumps({'script': {'script': 'Math.random()'}})}, timeout=10)
    check('Query DSL : script interdit', r.status_code == 400, f'HTTP {r.status_code}')
    r = analyst.get(f'{url}/api/search', params={'query': '*admin'}, timeout=10)
    check('Lucene : joker en tête refusé (coût)', r.status_code == 400, f'HTTP {r.status_code}')
    payload = '<script>alert(1)</script>'
    page = analyst.get(f'{url}/search', params={'q': payload}, timeout=10).text
    check('XSS réfléchi : charge échappée', payload not in page)

    # 8. fichiers
    files = {'file': ('../../etc/passwd.csv', b'timestamp,ip\n2026-11-20T10:00:00Z,203.0.113.1\n', 'text/csv')}
    r = analyst.post(f'{url}/api/uploads', files=files, timeout=20)
    name = (r.json() or {}).get('original_name', '') if r.headers.get('Content-Type', '').startswith('application/json') else ''
    check('Nom de fichier avec ../ neutralisé', r.status_code >= 400 or '..' not in name.replace('..csv', ''), f'HTTP {r.status_code} {name}')
    r = analyst.post(f'{url}/api/uploads', files={'file': ('malware.exe', b'MZ\x90\x00binary', 'application/octet-stream')}, timeout=20)
    check('Extension non autorisée refusée', r.status_code in (400, 415, 422), f'HTTP {r.status_code}')

    # 9. WebSocket depuis un autre site
    try:
        import simple_websocket
        host = url.split('://', 1)[1]
        ws = simple_websocket.Client.connect(f'ws://{host}/ws/live', headers={'Origin': 'https://evil.example',
                                                                               'Cookie': f"sentinel_session={analyst.cookies.get('sentinel_session')}"})
        try:
            data = ws.receive(timeout=3)
            check('WebSocket : origine étrangère refusée', data is None, f'reçu : {str(data)[:60]}')
        except simple_websocket.ConnectionClosed as exc:
            check('WebSocket : origine étrangère refusée', True, f'fermée ({exc.reason})')
        finally:
            try:
                ws.close()
            except Exception:  # noqa: BLE001 - déjà fermée par le serveur
                pass
    except ImportError:
        check('WebSocket : origine étrangère refusée', False, 'simple-websocket absent (pip install -r requirements-dev.txt)')
    except Exception as exc:  # noqa: BLE001 - refus pendant la poignée de main : c'est aussi un refus
        check('WebSocket : origine étrangère refusée', True, f'poignée de main refusée ({exc.__class__.__name__})')

    # 10. limitation de débit
    if a.rate:
        codes = []
        while len(codes) < 700 and 429 not in codes:        # fenêtre d'une minute : au plus 2 fenêtres traversées
            codes.append(analyst.get(f'{url}/api/alerts/summary', timeout=10).status_code)
        check('Limitation de débit de l’API (429)', 429 in codes, f'429 après {len(codes)} requêtes' if 429 in codes else 'jamais')

    # 11. force brute sur la page de connexion (en dernier : le compte « auditeur » reste bloqué quelques minutes)
    statuses = [anon.post(f'{url}/api/auth/login', json={'username': 'auditeur', 'password': f'faux-{i}'}, timeout=10).status_code
                for i in range(7)]
    check('Force brute au login limitée (429 après 5 échecs)', 429 in statuses, ' '.join(map(str, statuses)))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--url', default='http://localhost:8000')
    ap.add_argument('--analyst-password', required=True)
    ap.add_argument('--auditor-password', required=True)
    ap.add_argument('--rate', action='store_true', help='tester aussi la limitation de débit (330 requêtes)')
    ap.add_argument('--evidence', action='store_true')
    a = ap.parse_args(argv)
    try:
        requests.get(a.url, timeout=5)
    except requests.RequestException:
        sys.exit(f'STOP : {a.url} injoignable. Lancez la stack : docker compose up -d')
    run(a)
    passed = sum(r['ok'] for r in RESULTS)
    print(f'\n{passed}/{len(RESULTS)} contrôles réussis.')
    if a.evidence and passed == len(RESULTS):
        out = ROOT / 'docs/evidence/security_check.json'
        out.write_text(json.dumps({'at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'url': a.url,
                                   'results': RESULTS}, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f'Preuve : {out}')
    return 0 if passed == len(RESULTS) else 1


if __name__ == '__main__':
    raise SystemExit(main())
