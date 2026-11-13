"""Alerting engine: evaluates the enabled rules, raises / deduplicates alerts, notifies, responds, tracks incidents.

Life cycle of an alert (MongoDB ``alerts``, mirrored to Elasticsearch ``sentinel-alerts-YYYY.MM`` for Kibana):

    open ──acknowledge──▶ acknowledged ──resolve──▶ resolved
      └────────────────────────resolve────────────────▲

- **Silencing / deduplication**: while an alert with the same fingerprint (rule + group, e.g. rule + IP) is open
  or acknowledged, a new match only updates it (count, last_seen, occurrences): no new alert, no new notification.
- **Cooldown**: after an alert is raised, the same fingerprint cannot raise a NEW alert for ``cooldown_minutes``
  (Redis key with TTL), even if the first one was resolved quickly while the attack continues.
- **Response**: rules with ``actions.block_ip`` block the source IP in the laboratory service (see blocklist.py).
- **MTTR**: mean of (resolved_at - triggered_at) over resolved alerts.
"""
import hashlib
import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from app.alerting import rules as R
from app.alerting.blocklist import Blocklist, BlockError
from app.alerting.notify import Notifier, png_bar_chart, search_link
from app.services.users import record_audit
from app.stores import ElasticError

log = logging.getLogger('sentinel.alerting')
ACTIVE = ('open', 'acknowledged')
STATUS_LABELS = {'open': 'Ouverte', 'acknowledged': 'Prise en compte', 'resolved': 'Résolue'}
COOLDOWN_PREFIX = 'sentinel:alerting:cooldown:'
HEARTBEAT_KEY = 'sentinel:alerting:heartbeat'
LOCK_KEY = 'sentinel:alerting:lock'


def utcnow():
    return datetime.now(timezone.utc)


def iso(value):
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return value


def fingerprint(rule_id, key):
    return hashlib.sha256(f'{rule_id}|{key}'.encode()).hexdigest()[:24]


class AlertError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class AlertEngine:
    def __init__(self, stores, config, http=None, smtp_factory=None, sleep=None, now=utcnow):
        self.db, self.redis, self.es, self.cfg = stores.db, stores.redis, stores.es, config
        self.rules = R.RuleStore(stores.db)
        self.blocklist = Blocklist(stores.redis, stores.db, config)
        kwargs = {'http': http, 'smtp_factory': smtp_factory}
        if sleep is not None:
            kwargs['sleep'] = sleep
        self.notifier = Notifier(config, **kwargs)
        self.now = now

    # ------------------------------------------------------------ evaluation
    def evaluate(self, rule):
        """Run the rule's query; return the triggering groups (no side effect). Used by « Tester la règle »."""
        raw = self.es.search(self.cfg.logs_index, R.build_query(rule))
        return R.matches(rule, raw)

    def run_once(self):
        """One evaluation cycle over every enabled rule. Errors of one rule never stop the others."""
        started = self.now()
        summary = {'rules': 0, 'matches': 0, 'created': 0, 'updated': 0, 'suppressed': 0, 'errors': 0}
        for rule in self.rules.enabled():
            summary['rules'] += 1
            try:
                groups = self.evaluate(rule)
            except ElasticError as exc:
                summary['errors'] += 1
                self.rules.record_run(rule['_id'], 'error', error=str(exc))
                log.warning('rule %s failed: %s', rule['_id'], exc)
                continue
            summary['matches'] += len(groups)
            for group in groups:
                outcome = self.raise_or_update(rule, group)
                summary[outcome] += 1
            self.rules.record_run(rule['_id'], 'ok', matches=len(groups))
        summary['duration_ms'] = int((self.now() - started).total_seconds() * 1000)
        summary['at'] = iso(self.now())
        return summary

    def raise_or_update(self, rule, group):
        fp = fingerprint(rule['_id'], group['key'])
        now = self.now()
        current = self.db.alerts.find_one({'fingerprint': fp, 'status': {'$in': list(ACTIVE)}})
        if current:                                            # silencing: same incident still being handled
            self.db.alerts.update_one({'_id': current['_id']}, {
                '$set': {'count': max(current.get('count', 0), group['count']), 'value': group.get('value'),
                         'last_seen': group.get('last') or current.get('last_seen'), 'last_match_at': now},
                '$inc': {'occurrences': 1}})
            return 'updated'
        if self.redis.exists(COOLDOWN_PREFIX + fp):            # cooldown: resolved recently, do not re-alert yet
            return 'suppressed'
        alert = {
            '_id': uuid.uuid4().hex, 'fingerprint': fp, 'rule_id': rule['_id'], 'rule_name': rule['name'],
            'rule_type': rule['type'], 'severity': rule['severity'], 'status': 'open',
            'group_field': rule.get('group_by') or None, 'group': group['key'], 'count': group['count'],
            'value': group.get('value'), 'first_seen': group.get('first'), 'last_seen': group.get('last'),
            'samples': group.get('samples', []), 'message': R.describe(rule, group), 'occurrences': 1,
            'triggered_at': now, 'last_match_at': now, 'notifications': [], 'response': None, 'history': [
                {'status': 'open', 'by': 'alert-worker', 'at': now}],
        }
        if rule['cooldown_minutes']:
            self.redis.setex(COOLDOWN_PREFIX + fp, rule['cooldown_minutes'] * 60, alert['_id'])
        self.db.alerts.insert_one(alert)
        public = self.public(alert)
        if rule['actions'].get('block_ip') and rule.get('group_by') == 'source.ip':
            try:
                block = self.blocklist.block(group['key'], 'alert-worker', f"règle {rule['_id']}",
                                             alert_id=alert['_id'], rule=rule['_id'])
                alert['response'] = {'action': 'block_ip', 'ip': block['ip'], 'until': block['until']}
            except BlockError as exc:
                alert['response'] = {'action': 'block_ip', 'ip': group['key'], 'error': str(exc)}
            public['response'] = alert['response']
        notifications = []
        if rule['actions'].get('email'):
            notifications.append(self.notifier.email(public, self._chart(rule, group)))
        if rule['actions'].get('webhook'):
            notifications.append(self.notifier.webhook(public))
        self.db.alerts.update_one({'_id': alert['_id']}, {'$set': {'notifications': notifications,
                                                                   'response': alert['response']}})
        alert['notifications'] = notifications
        self._mirror(alert)
        record_audit(self.db, 'alert-worker', 'alert_raised', target=alert['_id'], reason=rule['_id'],
                     details={'group': group['key'], 'severity': rule['severity']})
        return 'created'

    def _chart(self, rule, group):
        """Event counts of the group over 3 windows (context before the alert), for the e-mail attachment."""
        minutes = R.WINDOWS[rule['window']] * 3
        filters = [{'range': {'@timestamp': {'gte': f'now-{minutes}m'}}}]
        if rule.get('query'):
            filters.append({'query_string': {'query': rule['query'], 'default_field': 'message', 'analyze_wildcard': True}})
        if rule.get('group_by'):
            filters.append({'term': {rule['group_by']: group['key']}})
        body = {'size': 0, 'query': {'bool': {'filter': filters}},
                'aggs': {'h': {'date_histogram': {'field': '@timestamp', 'fixed_interval': f'{max(1, minutes // 24)}m',
                                                  'min_doc_count': 0, 'extended_bounds': {'min': f'now-{minutes}m', 'max': 'now'}}}}}
        try:
            raw = self.es.search(self.cfg.logs_index, body)
            values = [b['doc_count'] for b in raw.get('aggregations', {}).get('h', {}).get('buckets', [])]
            return png_bar_chart(values) if values else None
        except Exception:  # noqa: BLE001 - the chart is a bonus, never a reason to lose the e-mail
            return None

    def _mirror(self, alert):
        """Copy the alert to Elasticsearch for the Kibana panels (best effort: MongoDB is the source of truth)."""
        when = alert['triggered_at']
        doc = {'@timestamp': iso(when), 'message': alert.get('message', ''),
               'alert': {'id': alert['_id'], 'severity': alert['severity'], 'status': alert['status'],
                         'group': alert.get('group'), 'count': alert.get('count'), 'fingerprint': alert.get('fingerprint')},
               'rule': {'id': alert['rule_id'], 'name': alert['rule_name'], 'type': alert.get('rule_type')},
               'response': {'action': (alert.get('response') or {}).get('action')}}
        if alert.get('group_field') == 'source.ip':
            doc['source'] = {'ip': alert['group']}
        if alert.get('group_field') == 'user.name':
            doc['user'] = {'name': alert['group']}
        try:
            self.es.index(f"{self.cfg.alerts_index_prefix}-{when.strftime('%Y.%m')}", alert['_id'], doc)
        except Exception as exc:  # noqa: BLE001
            log.warning('alert %s not mirrored to Elasticsearch: %s', alert['_id'], exc)

    # ------------------------------------------------------------ incident handling (ack / resolve)
    def transition(self, alert_id, action, user, note=''):
        alert = self.db.alerts.find_one({'_id': alert_id})
        if not alert:
            raise AlertError('Alerte introuvable.', 404)
        target = {'acknowledge': 'acknowledged', 'resolve': 'resolved'}.get(action)
        if not target:
            raise AlertError('Action inconnue : acknowledge ou resolve.')
        allowed = {'acknowledged': ('open',), 'resolved': ('open', 'acknowledged')}[target]
        if alert['status'] not in allowed:
            raise AlertError(f"Transition impossible depuis l’état « {STATUS_LABELS[alert['status']]} ».", 409)
        now = self.now()
        update = {'status': target, f"{'acknowledged' if target == 'acknowledged' else 'resolved'}_by": user,
                  f"{'acknowledged' if target == 'acknowledged' else 'resolved'}_at": now}
        if target == 'resolved':
            update['resolution_note'] = (note or '').strip()[:500]
            triggered = alert['triggered_at'] if alert['triggered_at'].tzinfo else alert['triggered_at'].replace(tzinfo=timezone.utc)
            update['time_to_resolve_s'] = int((now - triggered).total_seconds())
        self.db.alerts.update_one({'_id': alert_id}, {'$set': update,
                                                      '$push': {'history': {'status': target, 'by': user, 'at': now, 'note': (note or '')[:500]}}})
        record_audit(self.db, user, f'alert_{target}', target=alert_id, reason=(note or None))
        alert.update(update)
        self._mirror(alert)
        return self.public(self.db.alerts.find_one({'_id': alert_id}))

    # ------------------------------------------------------------ reading
    def public(self, alert):
        out = {k: iso(v) for k, v in alert.items() if k not in ('_id', 'history')}
        out['_id'] = out['id'] = alert['_id']
        out['history'] = [{**h, 'at': iso(h.get('at'))} for h in alert.get('history', [])]
        out['severity_label'] = R.SEVERITY_LABELS.get(alert['severity'], alert['severity'])
        out['status_label'] = STATUS_LABELS.get(alert['status'], alert['status'])
        out['search_url'] = search_link(self.cfg, out).replace(self.cfg.app_public_url, '')
        return out

    def list(self, status=None, severity=None, rule_id=None, limit=50):
        flt = {}
        if status == 'active':
            flt['status'] = {'$in': list(ACTIVE)}
        elif status in STATUS_LABELS:
            flt['status'] = status
        if severity in R.SEVERITIES:
            flt['severity'] = severity
        if rule_id:
            flt['rule_id'] = rule_id
        order = [('triggered_at', -1)]
        return [self.public(a) for a in self.db.alerts.find(flt).sort(order).limit(max(1, min(limit, 200)))]

    def stats(self, days=14):
        now = self.now()
        since = now - timedelta(days=days)
        docs = list(self.db.alerts.find({'triggered_at': {'$gte': since}},
                                        {'triggered_at': 1, 'rule_id': 1, 'rule_name': 1, 'severity': 1, 'status': 1,
                                         'time_to_resolve_s': 1}))
        per_day = Counter()
        for d in docs:
            t = d['triggered_at'] if d['triggered_at'].tzinfo else d['triggered_at'].replace(tzinfo=timezone.utc)
            per_day[t.date().isoformat()] += 1
        days_list = [(now - timedelta(days=i)).date().isoformat() for i in range(days - 1, -1, -1)]
        top = Counter((d['rule_id'], d['rule_name']) for d in docs).most_common(10)
        resolved = [d['time_to_resolve_s'] for d in docs if d.get('time_to_resolve_s') is not None]
        open_by_sev = Counter(a['severity'] for a in self.db.alerts.find({'status': {'$in': list(ACTIVE)}}, {'severity': 1}))
        return {
            'days': days, 'per_day': [{'day': d, 'count': per_day.get(d, 0)} for d in days_list],
            'top_rules': [{'rule_id': rid, 'rule_name': name, 'count': c} for (rid, name), c in top],
            'mttr_seconds': int(sum(resolved) / len(resolved)) if resolved else None, 'resolved': len(resolved),
            'total': len(docs), 'today': per_day.get(now.date().isoformat(), 0),
            'open_by_severity': {s: open_by_sev.get(s, 0) for s in R.SEVERITIES},
            'open_total': sum(open_by_sev.values()),
        }

    def heartbeat(self):
        import json
        raw = self.redis.get(HEARTBEAT_KEY)
        return json.loads(raw) if raw else None
