"""« Centre de pilotage » (page d'accueil) : ce qu'il faut regarder MAINTENANT.

Complémentaire du dashboard Kibana (analyse et exploration des tendances) : l'accueil répond à
« qu'est-ce qui demande une action ? » et « la chaîne d'ingestion fonctionne-t-elle ? ».

- indicateurs d'authentification sur une période glissante, comparés à la période précédente ;
- IP sources les plus en échec, cliquables vers l'explorateur pré-filtré ;
- santé de la plateforme mesurée (services, pipelines Logstash, fraîcheur par source, rejets).

Toutes les valeurs viennent d'Elasticsearch, MongoDB, Redis et des API de Logstash / Kibana ;
rien n'est inventé. Les résultats sont mis en cache 30 s dans Redis.
"""
import json
import logging
import os
from datetime import datetime, timedelta, timezone

import requests

log = logging.getLogger('sentinel.overview')

PERIODS = {
    '24h': {'label': '24 heures', 'math': '24h', 'delta': timedelta(hours=24), 'interval': '2h'},
    '7d': {'label': '7 jours', 'math': '7d', 'delta': timedelta(days=7), 'interval': '12h'},
    '30d': {'label': '30 jours', 'math': '30d', 'delta': timedelta(days=30), 'interval': '2d'},
    '90d': {'label': '90 jours', 'math': '90d', 'delta': timedelta(days=90), 'interval': '7d'},
}
DEFAULT_PERIOD = '24h'
SOURCES = {'logs-auth': 'Authentification (JSON / HTTP)', 'logs-firewall': 'Pare-feu (CSV)',
           'logs-upload': 'Fichiers importés'}
CACHE_TTL = 30


def _total(raw):
    total = raw.get('hits', {}).get('total', {})
    return total.get('value', 0) if isinstance(total, dict) else int(total or 0)


def _source_of(index):
    """``logs-auth-2026.10.30`` -> ``logs-auth`` (falls back to the index name)."""
    parts = (index or '').split('-')
    return '-'.join(parts[:2]) if len(parts) >= 3 else (index or '?')


def _ratio(success, failure):
    attempts = success + failure
    return round(100 * success / attempts, 1) if attempts else None


def _delta(current, previous):
    if previous == 0:
        return None
    return round(100 * (current - previous) / previous)


def build_auth_query(period):
    """One request: current window and previous window (same length) for the comparison."""
    math = PERIODS[period]['math']
    fail = {'term': {'event.outcome': 'failure'}}
    cur = {'range': {'@timestamp': {'gte': f'now-{math}'}}}
    prev = {'range': {'@timestamp': {'gte': f'now-{math}-{math}', 'lt': f'now-{math}'}}}
    return {
        'size': 0, 'track_total_hits': True,
        'query': {'range': {'@timestamp': {'gte': f'now-{math}-{math}'}}},
        'aggs': {
            'cur': {'filter': cur, 'aggs': {
                'outcomes': {'terms': {'field': 'event.outcome', 'size': 3}},
                'failures': {'filter': fail, 'aggs': {
                    'ips': {'cardinality': {'field': 'source.ip'}},
                    'users': {'cardinality': {'field': 'user.name'}},
                    'top_ips': {'terms': {'field': 'source.ip', 'size': 5}, 'aggs': {
                        'users': {'cardinality': {'field': 'user.name'}},
                        'last': {'max': {'field': '@timestamp'}},
                        'country': {'terms': {'field': 'source.geo.country_iso_code', 'size': 1}}}},
                    'spark': {'date_histogram': {'field': '@timestamp', 'fixed_interval': PERIODS[period]['interval'],
                                                 'min_doc_count': 0,
                                                 'extended_bounds': {'min': f'now-{math}', 'max': 'now'}}}}}}},
            'prev': {'filter': prev, 'aggs': {
                'outcomes': {'terms': {'field': 'event.outcome', 'size': 3}},
                'failures': {'filter': fail, 'aggs': {'ips': {'cardinality': {'field': 'source.ip'}},
                                                      'users': {'cardinality': {'field': 'user.name'}}}}}},
        },
    }


FRESHNESS_QUERY = {
    'size': 0, 'track_total_hits': True,
    'aggs': {
        'newest': {'max': {'field': '@timestamp'}},
        'by_index': {'terms': {'field': '_index', 'size': 200}, 'aggs': {
            'newest': {'max': {'field': '@timestamp'}},
            'ingested': {'max': {'field': 'event.ingested'}},
            'last24h': {'filter': {'range': {'@timestamp': {'gte': 'now-24h'}}}}}},
    },
}


def _outcomes(bucket):
    out = {b['key']: b['doc_count'] for b in bucket.get('outcomes', {}).get('buckets', [])}
    return out.get('success', 0), out.get('failure', 0)


def shape_auth(raw, period):
    aggs = raw.get('aggregations', {})
    cur, prev = aggs.get('cur', {}), aggs.get('prev', {})
    cs, cf = _outcomes(cur)
    ps, pf = _outcomes(prev)
    cfail, pfail = cur.get('failures', {}), prev.get('failures', {})
    ips = cfail.get('ips', {}).get('value', 0) or 0
    users = cfail.get('users', {}).get('value', 0) or 0
    p_ips = pfail.get('ips', {}).get('value', 0) or 0
    p_users = pfail.get('users', {}).get('value', 0) or 0
    top = []
    for b in cfail.get('top_ips', {}).get('buckets', []):
        country = b.get('country', {}).get('buckets', [])
        top.append({'ip': b['key'], 'failures': b['doc_count'], 'users': b.get('users', {}).get('value', 0),
                    'last': b.get('last', {}).get('value_as_string'),
                    'country': country[0]['key'] if country else None})
    spark = [b['doc_count'] for b in cfail.get('spark', {}).get('buckets', [])]
    return {
        'period': period, 'period_label': PERIODS[period]['label'], 'events': cur.get('doc_count', 0),
        'kpis': {
            'failures': {'value': cf, 'previous': pf, 'delta_pct': _delta(cf, pf)},
            'success_rate': {'value': _ratio(cs, cf), 'previous': _ratio(ps, pf), 'attempts': cs + cf},
            'failing_ips': {'value': ips, 'previous': p_ips, 'delta_pct': _delta(ips, p_ips)},
            'targeted_users': {'value': users, 'previous': p_users, 'delta_pct': _delta(users, p_users)},
        },
        'top_ips': top, 'spark': spark,
    }


def shape_freshness(raw, now=None):
    now = now or datetime.now(timezone.utc)
    aggs = raw.get('aggregations', {})
    sources = {}
    for b in aggs.get('by_index', {}).get('buckets', []):
        key = _source_of(b['key'])
        entry = sources.setdefault(key, {'source': key, 'label': SOURCES.get(key, key), 'documents': 0, 'last24h': 0,
                                         'newest': None, 'ingested': None})
        entry['documents'] += b['doc_count']
        entry['last24h'] += b.get('last24h', {}).get('doc_count', 0)
        for field in ('newest', 'ingested'):
            value = b.get(field, {}).get('value_as_string')
            if value and (entry[field] is None or value > entry[field]):
                entry[field] = value
    for entry in sources.values():
        stamp = entry['ingested'] or entry['newest']
        entry['age_seconds'] = _age(stamp, now)
    newest = aggs.get('newest', {}).get('value_as_string')
    return {'total': _total(raw), 'newest': newest, 'newest_age_seconds': _age(newest, now),
            'sources': sorted(sources.values(), key=lambda e: e['source'])}


def _age(stamp, now):
    if not stamp:
        return None
    try:
        dt = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    except ValueError:
        return None
    return max(0, int((now - dt).total_seconds()))


def count_rejected(directory):
    """Lines in the dead-letter files written by Logstash (bounded read, never raises)."""
    out = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        path = os.path.join(directory, name)
        if not os.path.isfile(path) or name.startswith('.'):
            continue
        try:
            with open(path, 'rb') as fh:
                lines = sum(1 for line in fh if line.strip())
            out.append({'file': name, 'lines': lines,
                        'modified': datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat()})
        except OSError:
            continue
    return out


def fmt_age(seconds):
    if seconds is None:
        return '—'
    if seconds < 90:
        return f'{seconds} s'
    if seconds < 5400:
        return f'{round(seconds / 60)} min'
    if seconds < 172800:
        return f'{round(seconds / 3600)} h'
    return f'{round(seconds / 86400)} j'


class OverviewService:
    def __init__(self, stores, config, http=None):
        self.db, self.redis, self.es = stores.db, stores.redis, stores.es
        self.cfg = config
        self.http = http or requests

    # ------------------------------------------------------------ cached helpers
    def _cached(self, key, builder):
        try:
            hit = self.redis.get(key)
        except Exception:  # noqa: BLE001 - Redis down: compute without cache
            hit = None
        if hit:
            return json.loads(hit)
        data = builder()
        try:
            self.redis.setex(key, CACHE_TTL, json.dumps(data))
        except Exception:  # noqa: BLE001
            pass
        return data

    def auth(self, period):
        return self._cached(f'sentinel:cache:overview:auth:{period}',
                            lambda: shape_auth(self.es.search(self.cfg.logs_index, build_auth_query(period)), period))

    def freshness(self):
        return self._cached('sentinel:cache:overview:freshness',
                            lambda: shape_freshness(self.es.search(self.cfg.logs_index, FRESHNESS_QUERY)))

    # ------------------------------------------------------------ platform health
    def _probe_logstash(self):
        url = f'{self.cfg.logstash_api_url}/_node/stats/pipelines'
        try:
            response = self.http.get(url, timeout=2)
            response.raise_for_status()
            pipelines = response.json().get('pipelines', {})
        except (requests.RequestException, ValueError):
            return {'status': 'error', 'pipelines': []}
        rows = []
        for name, data in sorted(pipelines.items()):
            if name.startswith('.'):
                continue
            ev = data.get('events', {})
            rows.append({'name': name, 'in': ev.get('in', 0), 'out': ev.get('out', 0), 'filtered': ev.get('filtered', 0)})
        return {'status': 'ok', 'pipelines': rows}

    def _probe_kibana(self):
        try:
            response = self.http.get(f'{self.cfg.kibana_internal_url}/api/status', timeout=2)
            level = response.json().get('status', {}).get('overall', {}).get('level') if response.ok else None
        except (requests.RequestException, ValueError):
            return 'error'
        return 'ok' if level == 'available' else ('degraded' if level else 'error')

    def health(self, es_ok):
        def build():
            services = {'elasticsearch': 'ok' if es_ok else 'error'}
            try:
                self.db.command('ping')
                services['mongodb'] = 'ok'
            except Exception:  # noqa: BLE001
                services['mongodb'] = 'error'
            logstash = self._probe_logstash()
            services['logstash'] = logstash['status']
            services['kibana'] = self._probe_kibana()
            return {'services': services, 'pipelines': logstash['pipelines']}
        data = self._cached('sentinel:cache:overview:health', build)
        try:
            self.redis.ping()
            data['services']['redis'] = 'ok'
        except Exception:  # noqa: BLE001
            data['services']['redis'] = 'error'
        return data

    def imports_to_check(self):
        """Imports whose ingestion did not fully succeed (to look at), from MongoDB."""
        docs = self.db.uploaded_files.find({'state': {'$in': ['partial', 'failed']}},
                                           {'original_name': 1, 'state': 1, 'stats': 1, 'uploaded_by': 1, 'created_at': 1}
                                           ).sort('created_at', -1).limit(5)
        return [{'id': str(d['_id']), 'name': d.get('original_name'), 'state': d.get('state'),
                 'by': d.get('uploaded_by')} for d in docs]

    def alerting(self):
        """S4: alerts to handle, blocked IPs and the worker heartbeat (never fatal for the home page)."""
        from app.alerting.blocklist import Blocklist
        from app.alerting.engine import HEARTBEAT_KEY
        out = {'alerts_open': [], 'alerts_open_by_severity': {}, 'blocked_ips': []}
        try:
            docs = self.db.alerts.find({'status': {'$in': ['open', 'acknowledged']}},
                                       {'rule_name': 1, 'severity': 1, 'group': 1, 'status': 1, 'triggered_at': 1, 'count': 1})
            docs = sorted(docs, key=lambda d: (['critical', 'high', 'medium', 'low'].index(d.get('severity', 'low')),
                                               -d['triggered_at'].timestamp()))
            for d in docs:
                out['alerts_open_by_severity'][d['severity']] = out['alerts_open_by_severity'].get(d['severity'], 0) + 1
            out['alerts_open'] = [{'id': d['_id'], 'rule_name': d['rule_name'], 'severity': d['severity'], 'group': d.get('group'),
                                   'status': d['status'], 'count': d.get('count')} for d in docs[:5]]
            out['alerts_open_total'] = len(docs)
            out['blocked_ips'] = [b['ip'] for b in Blocklist(self.redis, self.db, self.cfg).active()]
        except Exception:  # noqa: BLE001
            log.warning('alerting summary unavailable on the home page')
        try:
            out['worker'] = json.loads(self.redis.get(HEARTBEAT_KEY) or 'null')
        except Exception:  # noqa: BLE001
            out['worker'] = None
        return out

    # ------------------------------------------------------------ page model
    def build(self, period):
        if period not in PERIODS:
            period = DEFAULT_PERIOD
        from app.stores import ElasticError
        result = {'period': period, 'periods': {k: v['label'] for k, v in PERIODS.items()}, 'es_error': None,
                  'auth': None, 'freshness': None}
        try:
            result['auth'] = self.auth(period)
            result['freshness'] = self.freshness()
        except ElasticError as exc:
            result['es_error'] = str(exc)
        result['health'] = self.health(result['es_error'] is None)
        result.update(self.alerting())
        result['rejected'] = count_rejected(self.cfg.rejected_dir)
        result['rejected_total'] = sum(r['lines'] for r in result['rejected'])
        try:
            result['imports_to_check'] = self.imports_to_check()
        except Exception:  # noqa: BLE001 - MongoDB down: shown by the health block
            result['imports_to_check'] = []
        return result
