"""Classement des lignes sshd, identique au filtre Logstash ``stream.conf`` (même expressions, mêmes champs).

Sert aux expériences hors ligne (S6) ; ``tests/test_s6_ml.py`` vérifie que les deux versions donnent le même résultat.
"""
import re
from datetime import datetime

IP = r'(\d{1,3}(?:\.\d{1,3}){3})'
SYSLOG = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s?(.*)$')
ISO = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2}))\s+(\S+)\s+sshd\[(\d+)\]:\s?(.*)$')
MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}
RULES = [
    (re.compile(rf'^Failed (?:password|none|publickey) for (?:invalid user )?(.*?) from {IP} port \d+'), 'ssh-login', 'failure', 'WARNING', (1, 2)),
    (re.compile(rf'^message repeated (\d+) times: \[ Failed (?:password|none) for (?:invalid user )?(.*?) from {IP}'), 'ssh-login', 'failure', 'WARNING', (2, 3)),
    (re.compile(rf'^Accepted (?:password|publickey|keyboard-interactive\S*) for (\S+) from {IP} port \d+'), 'ssh-login', 'success', 'INFO', (1, 2)),
    (re.compile(rf'^Invalid user (.*?) from {IP}'), 'ssh-invalid-user', 'unknown', 'WARNING', (1, 2)),
    (re.compile(rf'^reverse mapping checking getaddrinfo for \S+ \[{IP}\] failed - POSSIBLE BREAK-IN ATTEMPT'), 'ssh-reverse-mapping', 'unknown', 'WARNING', (None, 1)),
    (re.compile(r'authentication failures?;.*rhost=(\S+)(?:\s+user=(\S+))?'), 'pam-auth-failure', 'unknown', 'WARNING', (2, 1)),
    (re.compile(r'^Disconnecting: Too many authentication failures(?: for (\S+))?'), 'ssh-too-many-failures', 'unknown', 'ERROR', (1, None)),
]
ANY_IP = re.compile(rf'(?<![\d.]){IP}(?![\d.])')
DISCONNECT = re.compile(rf'^(?:Received disconnect|Connection closed|Disconnected) (?:from|by) {IP}')


def classify(message):
    m = message
    out = {'action': 'ssh-other', 'outcome': 'unknown', 'level': 'INFO', 'user': None, 'ip': None, 'count': 1}
    for rx, action, outcome, level, (u, i) in RULES:
        r = rx.search(m) if action == 'pam-auth-failure' else rx.match(m)
        if r:
            out.update(action=action, outcome=outcome, level=level)
            out['user'] = r.group(u) if u else None
            ip = r.group(i) if i else None
            if action == 'pam-auth-failure':
                ip = ip if ip and re.fullmatch(IP, ip) else None
            out['ip'] = ip
            if action == 'ssh-login' and m.startswith('message repeated'):
                out['count'] = int(r.group(1))
            break
    else:
        if m.startswith('error:') or m.startswith('fatal:'):
            out.update(action='ssh-error', level='CRITICAL' if m.startswith('fatal:') else 'ERROR')
        elif (r := DISCONNECT.match(m)):
            out.update(action='ssh-disconnect', ip=r.group(1))
    if not out['ip'] and (r := ANY_IP.search(m)):
        out['ip'] = r.group(1)
    if out['user'] is not None:
        out['user'] = out['user'].strip() or None
    out['category'] = 'authentication' if out['action'] == 'ssh-login' else 'network'
    return out


def parse_line(line, year=2015):
    """Ligne syslog (format classique ou ISO) → dict avec horodatage, pid et classement."""
    line = line.rstrip('\n')
    if (m := ISO.match(line)):
        ts = datetime.fromisoformat(m.group(1).replace('Z', '+00:00'))
        host, pid, msg = m.group(2), m.group(3), m.group(4)
    elif (m := SYSLOG.match(line)):
        mon, day, hh, mi, ss, host, pid, msg = m.groups()
        ts = datetime(year, MONTHS[mon], int(day), int(hh), int(mi), int(ss))
    else:
        return None
    return {'ts': ts, 'host': host, 'pid': pid, 'message': msg.rstrip(), **classify(msg.rstrip())}
