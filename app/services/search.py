"""Search over ``logs-*``: query building, cached execution, event detail, CSV export, history."""
import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.services.parsing import LEVELS, RowError, parse_timestamp

MAX_WINDOW = 10000  # Elasticsearch default index.max_result_window
DEFAULT_SIZE, MAX_SIZE = 50, 100
OUTCOMES = {'success', 'failure', 'unknown'}
_ID_RE = re.compile(r'^[A-Za-z0-9_-]{8,128}$')
_TOKEN_RE = re.compile(r'^[\w.\- ]{1,64}$')
SORT_FIELDS = {'timestamp': '@timestamp', 'level': 'log.level', 'service': 'service.name'}
SOURCE_FIELDS = ['@timestamp', 'log.level', 'service.name', 'source.ip', 'user.name', 'event.action',
                 'event.outcome', 'event.category', 'message', 'labels.upload_id', 'labels.time_mode',
                 'labels.provenance']
EXPORT_COLUMNS = ['timestamp', 'level', 'service', 'source_ip', 'user', 'action', 'outcome', 'category', 'message']


class ValidationError(Exception):
    def __init__(self, errors):
        super().__init__('; '.join(errors))
        self.errors = errors


@dataclass
class SearchParams:
    q: str = ''
    start: str = ''
    end: str = ''
    levels: list = field(default_factory=list)
    services: list = field(default_factory=list)
    ip: str = ''
    user: str = ''
    outcome: str = ''
    upload_id: str = ''
    page: int = 1
    size: int = DEFAULT_SIZE
    sort: str = 'desc'
    sort_by: str = 'timestamp'

    def criteria(self):
        """Non-empty filters (what is stored in the history)."""
        data = {'q': self.q, 'start': self.start, 'end': self.end, 'level': self.levels, 'service': self.services,
                'ip': self.ip, 'user': self.user, 'outcome': self.outcome, 'upload_id': self.upload_id}
        return {k: v for k, v in data.items() if v}


def _split(values):
    out = []
    for value in values:
        out.extend(part.strip() for part in value.split(',') if part.strip())
    return out


def _bound(value, name, now, end_of_day, errors):
    if not value:
        return ''
    value = value.strip()
    try:
        if re.fullmatch(r'\d{4}-\d{2}-\d{2}', value):
            dt = parse_timestamp(value + 'T00:00:00Z', now + timedelta(days=3650))
            if end_of_day:
                dt = dt + timedelta(days=1) - timedelta(milliseconds=1)
        else:
            dt = parse_timestamp(value, now + timedelta(days=3650))
    except RowError:
        errors.append(f'« {name} » : date ISO 8601 attendue (ex. 2026-10-30 ou 2026-10-30T13:00:00Z).')
        return ''
    return dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def parse_params(args, now=None):
    now = now or datetime.now(timezone.utc)
    errors = []
    p = SearchParams()
    p.q = (args.get('q') or '').strip()
    if len(p.q) > 256:
        errors.append('« q » : 256 caractères maximum.')
    p.start = _bound(args.get('start', ''), 'start', now, False, errors)
    p.end = _bound(args.get('end', ''), 'end', now, True, errors)
    if p.start and p.end and p.start > p.end:
        errors.append('La date de début est postérieure à la date de fin.')
    p.levels = [lv.upper() for lv in _split(args.getlist('level'))]
    bad = [lv for lv in p.levels if lv not in LEVELS]
    if bad:
        errors.append(f"Niveau(x) inconnu(s) : {', '.join(bad)}.")
    p.services = _split(args.getlist('service'))
    if any(not _TOKEN_RE.match(s) for s in p.services):
        errors.append('« service » : caractères non autorisés.')
    ip = (args.get('ip') or '').strip()
    if ip:
        try:
            p.ip = str(ipaddress.ip_network(ip, strict=False)) if '/' in ip else str(ipaddress.ip_address(ip))
        except ValueError:
            errors.append('« ip » : adresse IPv4/IPv6 ou CIDR invalide.')
    p.user = (args.get('user') or '').strip()
    if len(p.user) > 128:
        errors.append('« user » : 128 caractères maximum.')
    p.outcome = (args.get('outcome') or '').strip().lower()
    if p.outcome and p.outcome not in OUTCOMES:
        errors.append('« outcome » : success, failure ou unknown.')
    p.upload_id = (args.get('upload_id') or '').strip().lower()
    if p.upload_id and not re.fullmatch(r'[0-9a-f]{32}', p.upload_id):
        errors.append('« upload_id » invalide.')
    try:
        p.page = int(args.get('page', 1))
        p.size = int(args.get('size', DEFAULT_SIZE))
    except ValueError:
        errors.append('« page » et « size » doivent être des entiers.')
    if p.page < 1 or not 1 <= p.size <= MAX_SIZE:
        errors.append(f'« page » ≥ 1 et « size » entre 1 et {MAX_SIZE}.')
    elif p.page * p.size > MAX_WINDOW:
        errors.append(f'Pagination limitée aux {MAX_WINDOW} premiers résultats : affinez la période ou les filtres.')
    p.sort = (args.get('sort') or 'desc').lower()
    if p.sort not in {'asc', 'desc'}:
        errors.append('« sort » : asc ou desc.')
    p.sort_by = (args.get('sort_by') or 'timestamp').lower()
    if p.sort_by not in SORT_FIELDS:
        errors.append('« sort_by » : timestamp, level ou service.')
    if errors:
        raise ValidationError(errors)
    return p


def build_query(p):
    filters = []
    if p.start or p.end:
        rng = {}
        if p.start:
            rng['gte'] = p.start
        if p.end:
            rng['lte'] = p.end
        filters.append({'range': {'@timestamp': rng}})
    if p.levels:
        filters.append({'terms': {'log.level': p.levels}})
    if p.services:
        filters.append({'terms': {'service.name': p.services}})
    if p.ip:
        filters.append({'term': {'source.ip': p.ip}})
    if p.user:
        filters.append({'term': {'user.name': p.user}})
    if p.outcome:
        filters.append({'term': {'event.outcome': p.outcome}})
    if p.upload_id:
        filters.append({'term': {'labels.upload_id': p.upload_id}})
    must = []
    if p.q:
        must.append({'simple_query_string': {'query': p.q, 'fields': ['message'], 'default_operator': 'and',
                                             'lenient': True}})
    if not filters and not must:
        return {'match_all': {}}
    return {'bool': {'filter': filters, 'must': must}}


def build_sort(p):
    primary = {SORT_FIELDS[p.sort_by]: {'order': p.sort, 'unmapped_type': 'date' if p.sort_by == 'timestamp' else 'keyword'}}
    if p.sort_by == 'timestamp':
        return [primary]
    return [primary, {'@timestamp': {'order': 'desc', 'unmapped_type': 'date'}}]    # stable, newest first within ties


def build_body(p, *, offset=None, size=None):
    return {
        'query': build_query(p),
        'sort': build_sort(p),
        'from': (p.page - 1) * p.size if offset is None else offset,
        'size': p.size if size is None else size,
        'track_total_hits': True,
        '_source': SOURCE_FIELDS,
    }


def _dig(src, path, default=None):
    cur = src
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
    return default if cur is None else cur


def shape_hit(hit, message_limit=300):
    src = hit.get('_source', {})
    message = _dig(src, 'message', '') or ''
    return {
        'id': hit.get('_id'), 'index': hit.get('_index'), 'timestamp': _dig(src, '@timestamp'),
        'level': _dig(src, 'log.level'), 'service': _dig(src, 'service.name'), 'ip': _dig(src, 'source.ip'),
        'user': _dig(src, 'user.name'), 'action': _dig(src, 'event.action'), 'outcome': _dig(src, 'event.outcome'),
        'category': _dig(src, 'event.category'), 'upload_id': _dig(src, 'labels.upload_id'),
        'time_mode': _dig(src, 'labels.time_mode'),
        'message': message[:message_limit] + ('…' if len(message) > message_limit else ''),
    }


def csv_safe(value):
    """Neutralise spreadsheet formula injection (cells starting with = + - @ tab or CR)."""
    text = '' if value is None else str(value)
    return "'" + text if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text


class SearchService:
    def __init__(self, db, redis, es, config):
        self.db, self.redis, self.es, self.cfg = db, redis, es, config

    # ------------------------------------------------------------ search
    def search(self, p, *, nocache=False):
        body = build_body(p)
        key = 'sentinel:cache:search:' + hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        if not nocache and self.cfg.search_cache_ttl > 0:
            cached = self.redis.get(key)
            if cached:
                result = json.loads(cached)
                result['cached'] = True
                return result
        raw = self.es.search(self.cfg.logs_index, body)
        total = raw.get('hits', {}).get('total', {})
        total_value = total.get('value', 0) if isinstance(total, dict) else int(total or 0)
        result = {
            'total': total_value,
            'total_exact': (total.get('relation', 'eq') == 'eq') if isinstance(total, dict) else True,
            'page': p.page, 'size': p.size,
            'pages': max(1, -(-min(total_value, MAX_WINDOW) // p.size)),
            'took_ms': raw.get('took'), 'cached': False,
            'hits': [shape_hit(h) for h in raw.get('hits', {}).get('hits', [])],
        }
        if self.cfg.search_cache_ttl > 0:
            self.redis.setex(key, self.cfg.search_cache_ttl, json.dumps(result))
        return result

    def facets(self):
        key = 'sentinel:cache:facets'
        cached = self.redis.get(key)
        if cached:
            return json.loads(cached)
        raw = self.es.search(self.cfg.logs_index, {
            'size': 0, 'track_total_hits': True,
            'aggs': {'levels': {'terms': {'field': 'log.level', 'size': 10}},
                     'services': {'terms': {'field': 'service.name', 'size': 50}},
                     'outcomes': {'terms': {'field': 'event.outcome', 'size': 5}},
                     'oldest': {'min': {'field': '@timestamp'}}, 'newest': {'max': {'field': '@timestamp'}}}})
        aggs = raw.get('aggregations', {})
        total = raw.get('hits', {}).get('total', {})
        data = {
            'total': total.get('value', 0) if isinstance(total, dict) else int(total or 0),
            'levels': [{'value': b['key'], 'count': b['doc_count']} for b in aggs.get('levels', {}).get('buckets', [])],
            'services': [{'value': b['key'], 'count': b['doc_count']} for b in aggs.get('services', {}).get('buckets', [])],
            'outcomes': [{'value': b['key'], 'count': b['doc_count']} for b in aggs.get('outcomes', {}).get('buckets', [])],
            'oldest': aggs.get('oldest', {}).get('value_as_string'), 'newest': aggs.get('newest', {}).get('value_as_string'),
        }
        self.redis.setex(key, 30, json.dumps(data))
        return data

    def stats(self, uploads_count=0):
        """Dashboard figures straight from Elasticsearch (cached 30 s). ``uploads_count`` comes from MongoDB."""
        key = 'sentinel:cache:stats'
        cached = self.redis.get(key)
        if cached:
            data = json.loads(cached)
        else:
            raw = self.es.search(self.cfg.logs_index, {
                'size': 0, 'track_total_hits': True,
                'aggs': {'levels': {'terms': {'field': 'log.level', 'size': 10}},
                         'services': {'terms': {'field': 'service.name', 'size': 8}},
                         'today': {'filter': {'range': {'@timestamp': {'gte': 'now/d'}}}},
                         'errors': {'filter': {'terms': {'log.level': ['ERROR', 'CRITICAL']}}},
                         'timeline': {'auto_date_histogram': {'field': '@timestamp', 'buckets': 24}}}})
            aggs = raw.get('aggregations', {})
            total = raw.get('hits', {}).get('total', {})
            data = {
                'total': total.get('value', 0) if isinstance(total, dict) else int(total or 0),
                'today': aggs.get('today', {}).get('doc_count', 0),
                'errors': aggs.get('errors', {}).get('doc_count', 0),
                'levels': [{'label': b['key'], 'count': b['doc_count']} for b in aggs.get('levels', {}).get('buckets', [])],
                'services': [{'label': b['key'], 'count': b['doc_count']} for b in aggs.get('services', {}).get('buckets', [])],
                'timeline': [{'label': b.get('key_as_string', str(b['key'])), 'count': b['doc_count']}
                             for b in aggs.get('timeline', {}).get('buckets', [])],
                'timeline_interval': aggs.get('timeline', {}).get('interval'),
            }
            self.redis.setex(key, 30, json.dumps(data))
        data['uploads'] = uploads_count
        return data

    # ------------------------------------------------------------ detail
    def get_event(self, event_id):
        if not _ID_RE.match(event_id or ''):
            return None
        raw = self.es.search(self.cfg.logs_index, {'query': {'ids': {'values': [event_id]}}, 'size': 1})
        hits = raw.get('hits', {}).get('hits', [])
        if not hits:
            return None
        hit = hits[0]
        return {'id': hit['_id'], 'index': hit['_index'], 'source': hit.get('_source', {}), 'summary': shape_hit(hit, 10 ** 6)}

    # ------------------------------------------------------------ export
    def export_csv(self, p):
        """Return (csv_text, truncated, rows). Same filters/sort as the on-screen search."""
        limit = self.cfg.export_max_rows
        rows, offset, total_hits = [], 0, 0
        while len(rows) < limit:
            take = min(1000, limit - len(rows), MAX_WINDOW - offset)
            if take <= 0:
                break
            raw = self.es.search(self.cfg.logs_index, build_body(p, offset=offset, size=take))
            hits = raw.get('hits', {}).get('hits', [])
            total = raw.get('hits', {}).get('total', {})
            total_hits = total.get('value', 0) if isinstance(total, dict) else int(total or 0)
            rows.extend(shape_hit(h, 10 ** 6) for h in hits)
            offset += len(hits)
            if len(hits) < take or offset >= total_hits:
                break
        truncated = total_hits > len(rows)
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator='\n')
        writer.writerow(EXPORT_COLUMNS)
        for r in rows:
            writer.writerow([csv_safe(v) for v in (r['timestamp'], r['level'], r['service'], r['ip'], r['user'],
                                                   r['action'], r['outcome'], r['category'], r['message'])])
        return buf.getvalue(), truncated, len(rows)

    # ------------------------------------------------------------ history (MongoDB saved_searches)
    def record_history(self, user, p):
        criteria = p.criteria()
        if not criteria:
            return
        col = self.db.saved_searches
        now = datetime.now(timezone.utc)
        last = col.find_one({'user_id': user.id}, sort=[('created_at', -1)])
        if last and last.get('filters') == criteria:
            col.update_one({'_id': last['_id']}, {'$set': {'created_at': now}})
            return
        col.insert_one({'user_id': user.id, 'username': user.username, 'text': p.q, 'filters': criteria,
                        'created_at': now})

    def history(self, user, limit=5):
        docs = self.db.saved_searches.find({'user_id': user.id}).sort('created_at', -1).limit(limit)
        return [{'id': str(d['_id']), 'filters': d['filters'], 'created_at': d['created_at'].replace(tzinfo=timezone.utc).isoformat()
                 if d['created_at'].tzinfo is None else d['created_at'].isoformat()} for d in docs]
