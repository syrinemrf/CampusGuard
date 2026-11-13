#!/usr/bin/env python3
"""Send a SYNTHETIC attack scenario (scenario C) to Logstash, timestamped NOW, to demonstrate the S4 alerting.

    python scripts/simulate_attack.py                       # default Logstash HTTP input http://localhost:8088
    python scripts/simulate_attack.py --only brute-force    # one part of the scenario
    python scripts/simulate_attack.py --dry-run             # print the events, send nothing

Everything goes through the normal json-security pipeline (validation, GeoIP, fingerprint) into logs-auth-*.
Addresses come from the documentation ranges (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), except
ONE public example address (8.8.8.8) needed to demonstrate the GeoIP « unauthorized country » rule.
No packet is sent to any of these addresses: they only appear as text in the log lines.

Parts (and the default rule each one should trigger):
  brute-force       8 failed logins from one IP on « admin » in < 1 min      -> brute-force-ip (+ IP blocked)
  stuffing          1 IP fails on 6 different accounts                        -> credential-stuffing (+ IP blocked)
  country           successful login from a public IP outside TN / FR       -> unauthorized-country
  off-hours         successful login at 03:10 (Africa/Tunis) today           -> off-hours-login
  escalation        sudo to root by a standard account                       -> privilege-escalation
  sqli              HTTP request with « ' OR '1'='1 » in the URL              -> sql-injection (+ IP blocked)
"""
import argparse
import json
import random
import sys
from datetime import datetime, timedelta, timezone

import requests

TUNIS = timezone(timedelta(hours=1))        # Africa/Tunis: UTC+1, no daylight saving time since 2009
PARTS = ('brute-force', 'stuffing', 'country', 'off-hours', 'escalation', 'sqli')


def _stamp(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _event(ts, ip, user, outcome, action, message, level='WARNING', category='authentication', service='authentication'):
    return {'timestamp': _stamp(ts), 'source_ip': ip, 'username': user, 'outcome': outcome, 'action': action,
            'level': level, 'message': message, 'service': {'name': service}, 'event': {'category': category},
            'labels': {'provenance': 'simulate_attack', 'ground_truth': 'attack'}}


def pick_ips(seed=None):
    rng = random.Random(seed)
    return {'brute': f'203.0.113.{rng.randint(100, 199)}', 'stuffer': f'198.51.100.{rng.randint(100, 199)}',
            'sqli': f'203.0.113.{rng.randint(200, 250)}', 'foreign': '8.8.8.8', 'internal': f'192.0.2.{rng.randint(10, 99)}',
            # random account names so that a second run is not hidden by the cooldown of the first one
            'night_user': f'user_{rng.randint(100, 999)}', 'sudo_user': f'user_{rng.randint(100, 999)}'}


def scenario(ips, now=None, only=None):
    now = now or datetime.now(timezone.utc)
    parts = set(only or PARTS)
    events = []
    if 'brute-force' in parts:
        for i in range(8):
            events.append(_event(now - timedelta(seconds=50 - i * 6), ips['brute'], 'admin', 'failure', 'ssh-login',
                                 f"Failed password for admin from {ips['brute']} port {40000 + i} ssh2", service='sshd'))
    if 'stuffing' in parts:
        for i, user in enumerate(['alice', 'bob', 'charlie', 'dora', 'eve', 'farid']):
            events.append(_event(now - timedelta(seconds=40 - i * 5), ips['stuffer'], user, 'failure', 'login',
                                 f"Invalid credentials for {user} from {ips['stuffer']} (webmail)", service='webmail'))
    if 'country' in parts:
        events.append(_event(now - timedelta(seconds=30), ips['foreign'], 'user_3', 'success', 'login',
                             f"Accepted password for user_3 from {ips['foreign']} (VPN)", level='INFO', service='vpn'))
    if 'off-hours' in parts:
        local = now.astimezone(TUNIS).replace(hour=3, minute=10, second=0, microsecond=0)
        if local > now.astimezone(TUNIS):
            local -= timedelta(days=1)
        user = ips['night_user']
        events.append(_event(local, ips['internal'], user, 'success', 'login',
                             f"Accepted password for {user} from {ips['internal']} (intranet)", level='INFO', service='intranet'))
    if 'escalation' in parts:
        user = ips['sudo_user']
        events.append(_event(now - timedelta(seconds=20), ips['internal'], user, 'success', 'sudo',
                             f'{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/su -', service='sudo',
                             category='iam'))
    if 'sqli' in parts:
        events.append(_event(now - timedelta(seconds=10), ips['sqli'], 'anonymous', 'failure', 'http_request',
                             "GET /login.php?user=admin' OR '1'='1&pass=x HTTP/1.1 403", service='intranet-web', category='web'))
    return events


def send(events, url, http=requests):
    sent = 0
    for event in events:
        response = http.post(url, json=event, timeout=10)
        if response.status_code >= 300:
            raise RuntimeError(f'Logstash a refusé un événement : HTTP {response.status_code}')
        sent += 1
    return sent


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--logstash', default='http://localhost:8088')
    ap.add_argument('--only', action='append', choices=PARTS)
    ap.add_argument('--seed', type=int)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)
    ips = pick_ips(args.seed)
    events = scenario(ips, only=args.only)
    if args.dry_run:
        print('\n'.join(json.dumps(e, ensure_ascii=False) for e in events))
        return 0
    try:
        n = send(events, args.logstash)
    except (requests.RequestException, RuntimeError) as exc:
        print(f'Échec de l’envoi vers {args.logstash} : {exc}')
        return 1
    print(f'{n} événement(s) envoyé(s) à {args.logstash}.')
    print('Adresses utilisées : ' + ', '.join(f'{k}={v}' for k, v in ips.items()))
    print('Les alertes apparaissent dans http://localhost:8000/alerts au prochain cycle du worker (≤ 30 s).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
