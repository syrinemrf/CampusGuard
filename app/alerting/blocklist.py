"""SOAR-lite response: temporary IP blocklist in Redis, enforced by the web application (laboratory service).

- ``sentinel:blocklist:{ip}`` holds a JSON record with a TTL: the block lifts itself (no forgotten rule).
- Every block / unblock is written to MongoDB ``ip_blocks`` (history) and ``audit_actions`` (who, when, why).
- Enforcement is LOCAL ONLY: a Flask ``before_request`` hook answers 403 to a blocked address.
  Nothing is sent to a firewall or to the network; no offensive action is ever taken.
- Addresses in ``BLOCK_NEVER`` (CIDR list, default loopback) can never be blocked.
"""
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from app.services.users import record_audit

PREFIX = 'sentinel:blocklist:'


class BlockError(ValueError):
    pass


def normalise_ip(value):
    try:
        return str(ipaddress.ip_address((value or '').strip()))
    except ValueError as exc:
        raise BlockError('Adresse IP invalide.') from exc


def _never_networks(spec):
    nets = []
    for part in (spec or '').split(','):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                continue
    return nets


class Blocklist:
    def __init__(self, redis, db, config):
        self.redis, self.db, self.cfg = redis, db, config
        self.never = _never_networks(config.block_never)

    def protected(self, ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.never)

    def block(self, ip, actor, reason, minutes=None, alert_id=None, rule=None):
        ip = normalise_ip(ip)
        if self.protected(ip):
            raise BlockError(f'{ip} fait partie des adresses protégées (BLOCK_NEVER) : blocage refusé.')
        minutes = int(minutes or self.cfg.block_ttl_minutes)
        if not 1 <= minutes <= 1440:
            raise BlockError('Durée de blocage : 1 à 1440 minutes.')
        now = datetime.now(timezone.utc)
        until = now + timedelta(minutes=minutes)
        record = {'ip': ip, 'reason': reason[:200], 'by': actor, 'at': now.isoformat(), 'until': until.isoformat(),
                  'minutes': minutes, 'alert_id': alert_id, 'rule': rule}
        self.redis.setex(PREFIX + ip, minutes * 60, json.dumps(record))
        self.db.ip_blocks.insert_one({**record, 'action': 'block', 'at': now, 'until': until})
        record_audit(self.db, actor, 'ip_blocked', target=ip, reason=reason[:200],
                     details={'minutes': minutes, 'alert_id': alert_id, 'rule': rule})
        return record

    def unblock(self, ip, actor, reason='déblocage manuel'):
        ip = normalise_ip(ip)
        existed = bool(self.redis.delete(PREFIX + ip))
        if existed:
            self.db.ip_blocks.insert_one({'ip': ip, 'action': 'unblock', 'by': actor, 'reason': reason[:200],
                                          'at': datetime.now(timezone.utc)})
            record_audit(self.db, actor, 'ip_unblocked', target=ip, reason=reason[:200])
        return existed

    def get(self, ip):
        try:
            raw = self.redis.get(PREFIX + normalise_ip(ip))
        except BlockError:
            return None
        if not raw:
            return None
        record = json.loads(raw)
        record['remaining_seconds'] = max(0, int(self.redis.ttl(PREFIX + record['ip']) or 0))
        return record

    def active(self):
        out = []
        for key in self.redis.scan_iter(match=PREFIX + '*', count=200):
            record = self.get(key[len(PREFIX):])
            if record:
                out.append(record)
        return sorted(out, key=lambda r: r['until'])

    def history(self, limit=20):
        docs = self.db.ip_blocks.find({}, {'_id': 0}).sort('at', -1).limit(limit)
        out = []
        for d in docs:
            for k in ('at', 'until'):
                if isinstance(d.get(k), datetime):
                    d[k] = (d[k] if d[k].tzinfo else d[k].replace(tzinfo=timezone.utc)).isoformat()
            out.append(d)
        return out
