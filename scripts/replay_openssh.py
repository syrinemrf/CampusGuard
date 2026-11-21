"""Rejoue en temps réel le journal sshd réel de Loghub (OpenSSH_2k, serveur LabSZ, déc. 2015).

Les 2 000 lignes sont réécrites au fil de l'eau, avec l'heure actuelle et le rythme d'origine (accéléré par --speed),
exactement comme sshd les écrirait dans /var/log/auth.log :

    --to file  (défaut) ajoute les lignes à datasets/stream/sshd.log → Filebeat (tail) → Kafka → Logstash
    --to tcp   envoie les lignes au port 5140 de Logstash (sans Kafka)
    --to stdout affiche les lignes

Pseudonymisation : les adresses IP gardent leurs deux premiers octets (le pays reste juste pour la GeoIP), les deux
derniers sont remplacés par un hachage stable ; les comptes qui se sont réellement connectés sont renommés. Les noms
essayés par les attaquants (root, admin, oracle…) sont conservés : ce sont des mots de dictionnaire, pas des personnes.

Exemples :
    python scripts/replay_openssh.py --download            # télécharge le journal (une fois)
    python scripts/replay_openssh.py --speed 60            # ~4 h de journal rejouées en ~4 min
    python scripts/replay_openssh.py --to tcp --speed 120 --limit 500
"""
import argparse
import hashlib
import hmac
import re
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SOURCE_URL = 'https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log'
RAW = BASE / 'datasets/raw/OpenSSH_2k.log'
OUT = BASE / 'datasets/stream/sshd.log'
SALT = b'campusguard-sentinel'

LINE = re.compile(r'^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(sshd)\[(\d+)\]:\s?(.*)$')
IPV4 = re.compile(r'(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])')
EC2 = re.compile(r'ec2-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})')
ACCEPTED = re.compile(r'(Accepted \S+ for |session (?:opened|closed) for user )(\S+)')
MONTHS = {m: i for i, m in enumerate('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(), 1)}


def _h(value, n=4):
    return hmac.new(SALT, value.encode(), hashlib.sha256).digest()[:n]


def pseudo_ip(a, b, c, d):
    """Garde le /16 (donc le pays et l'opérateur pour la GeoIP), remplace les deux derniers octets."""
    x, y = _h(f'{a}.{b}.{c}.{d}', 2)
    return f'{a}.{b}.{x % 254 + 1}.{y % 254 + 1}'


def pseudonymize(message, real_users):
    message = IPV4.sub(lambda m: pseudo_ip(*m.groups()), message)
    message = EC2.sub(lambda m: 'ec2-' + pseudo_ip(*m.groups()).replace('.', '-'), message)

    def user(m):
        real_users.add(m.group(2))
        return m.group(1) + 'user_' + _h(m.group(2)).hex()[:6]
    message = ACCEPTED.sub(user, message)
    for name in real_users:   # le même compte peut réapparaître dans d'autres lignes
        message = re.sub(rf'(?<=[ =]){re.escape(name)}(?=[ \]]|$)', 'user_' + _h(name).hex()[:6], message)
    return message


def read_events(path):
    """(seconde relative du journal, hôte, pid, message) ; l'année absente du syslog n'a pas d'importance ici."""
    events = []
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        mon, day, hh, mm, ss, host, _, pid, msg = m.groups()
        t = (((MONTHS.get(mon, 1) * 31 + int(day)) * 24 + int(hh)) * 60 + int(mm)) * 60 + int(ss)
        events.append((t, host, pid, msg.rstrip()))
    return events


def syslog_line(host, pid, message, now=None):
    now = now or datetime.now(timezone.utc)
    return f"{now.isoformat(timespec='milliseconds')} {host} sshd[{pid}]: {message}"


class Sink:
    def __init__(self, kind, path=OUT, host='localhost', port=5140):
        self.kind = kind
        if kind == 'file':
            path.parent.mkdir(parents=True, exist_ok=True)
            self.fh = path.open('a', encoding='utf-8')
        elif kind == 'tcp':
            self.sock = socket.create_connection((host, port), timeout=5)

    def write(self, line):
        if self.kind == 'file':
            self.fh.write(line + '\n')
            self.fh.flush()
        elif self.kind == 'tcp':
            self.sock.sendall((line + '\n').encode('utf-8'))
        else:
            print(line, flush=True)

    def close(self):
        if self.kind == 'file':
            self.fh.close()
        elif self.kind == 'tcp':
            self.sock.close()


def replay(events, sink, speed=60.0, max_gap=5.0, sleep=time.sleep, clock=None):
    real_users, sent = set(), 0
    previous = events[0][0] if events else 0
    for t, host, pid, msg in events:
        gap = min(max(t - previous, 0) / speed, max_gap) if speed > 0 else 0
        if gap:
            sleep(gap)
        previous = t
        sink.write(syslog_line(host, pid, pseudonymize(msg, real_users), clock() if clock else None))
        sent += 1
    return sent


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--download', action='store_true', help='télécharger le journal Loghub dans datasets/raw/')
    p.add_argument('--source', type=Path, default=RAW)
    p.add_argument('--to', choices=['file', 'tcp', 'stdout'], default='file')
    p.add_argument('--out', type=Path, default=OUT, help='fichier suivi par Filebeat (--to file)')
    p.add_argument('--host', default='localhost')
    p.add_argument('--port', type=int, default=5140)
    p.add_argument('--speed', type=float, default=60.0, help='facteur d’accélération (0 = sans attente)')
    p.add_argument('--max-gap', type=float, default=5.0, help='attente maximale entre deux lignes, en secondes')
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--loop', action='store_true', help='recommencer à la fin du journal')
    a = p.parse_args(argv)
    if a.download:
        a.source.parent.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(SOURCE_URL, a.source)
    if not a.source.exists():
        p.error(f'{a.source} absent : lancer une fois avec --download')
    events = read_events(a.source)
    if a.limit:
        events = events[:a.limit]
    try:
        sink = Sink(a.to, a.out, a.host, a.port)
    except OSError as exc:
        sys.exit(f'Connexion impossible à {a.host}:{a.port} ({exc}). Logstash est-il démarré ?')
    span = (events[-1][0] - events[0][0]) if events else 0
    print(f'{len(events)} lignes réelles, {span // 60} min de journal, vitesse x{a.speed:g} → {a.to}', file=sys.stderr)
    total = 0
    try:
        while True:
            total += replay(events, sink, a.speed, a.max_gap)
            if not a.loop:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sink.close()
    print(f'{total} lignes émises.', file=sys.stderr)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
