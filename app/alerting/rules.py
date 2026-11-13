"""Alert rules (MongoDB ``alert_rules``): validation, default scenario-C rules, Elasticsearch query, evaluation.

A rule is evaluated against ``logs-*`` on a sliding window (5m, 15m, 1h, 24h). Four condition types
(project statement, module G):

- ``threshold``   : number of matching events >= threshold (optionally per group: source.ip, user.name, service.name);
- ``cardinality`` : number of DISTINCT values of a field >= threshold per group (e.g. accounts tried by one IP);
- ``pattern``     : a regular expression on ``message`` (evaluated in Python on the matching events);
- ``silence``     : NO matching event during the window (« silence alarm »).

``query`` is an Elasticsearch ``query_string`` (Lucene syntax), the same language as the Kibana search bar.
An optional ``outside_hours`` [start, end) keeps only events OUTSIDE business hours (local time zone), through
the same painless runtime field as the Kibana heatmap. Anomaly-based rules come with the ML module (S6).
"""
import re
from datetime import datetime, timezone

from app.kibana import RUNTIME_FIELDS

RULE_TYPES = ('threshold', 'cardinality', 'pattern', 'silence')
WINDOWS = {'5m': 5, '15m': 15, '1h': 60, '24h': 1440}
SEVERITIES = ('low', 'medium', 'high', 'critical')
SEVERITY_LABELS = {'low': 'Faible', 'medium': 'Moyenne', 'high': 'Haute', 'critical': 'Critique'}
GROUP_FIELDS = ('', 'source.ip', 'user.name', 'service.name')
DISTINCT_FIELDS = ('user.name', 'source.ip', 'service.name')
TYPE_LABELS = {'threshold': 'Seuil', 'cardinality': 'Valeurs distinctes', 'pattern': 'Motif (regex)', 'silence': 'Absence de logs'}
MAX_GROUPS = 50
PATTERN_SCAN = 500
_ID_RE = re.compile(r'^[a-z0-9][a-z0-9-]{2,48}$')


class RuleError(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors))
        self.errors = errors


def _int(value, name, low, high, errors):
    try:
        number = int(value)
    except (TypeError, ValueError):
        errors.append(f'« {name} » doit être un entier.')
        return low
    if not low <= number <= high:
        errors.append(f'« {name} » doit être entre {low} et {high}.')
    return number


def validate(data, existing_id=None):
    """Return a clean rule dict or raise RuleError (all problems at once, in French)."""
    if not isinstance(data, dict):
        raise RuleError(['Objet JSON attendu.'])
    errors = []
    rule_id = existing_id or (data.get('id') or '').strip().lower()
    if not _ID_RE.match(rule_id or ''):
        errors.append('« id » : 3 à 49 caractères a-z, 0-9 ou tiret (ex. brute-force-ip).')
    name = (data.get('name') or '').strip()
    if not 3 <= len(name) <= 80:
        errors.append('« name » : 3 à 80 caractères.')
    description = (data.get('description') or '').strip()[:500]
    rtype = data.get('type')
    if rtype not in RULE_TYPES:
        errors.append('« type » : ' + ', '.join(RULE_TYPES) + '.')
    query = (data.get('query') or '').strip()
    if len(query) > 500:
        errors.append('« query » : 500 caractères maximum.')
    window = data.get('window')
    if window not in WINDOWS:
        errors.append('« window » : ' + ', '.join(WINDOWS) + '.')
    severity = data.get('severity')
    if severity not in SEVERITIES:
        errors.append('« severity » : ' + ', '.join(SEVERITIES) + '.')
    group_by = data.get('group_by') or ''
    if group_by not in GROUP_FIELDS:
        errors.append('« group_by » : vide, source.ip, user.name ou service.name.')
    threshold = _int(data.get('threshold', 1), 'threshold', 1, 100000, errors)
    cooldown = _int(data.get('cooldown_minutes', 15), 'cooldown_minutes', 0, 1440, errors)
    distinct_field = data.get('distinct_field') or ''
    pattern = data.get('pattern') or ''
    if rtype == 'cardinality':
        if distinct_field not in DISTINCT_FIELDS:
            errors.append('« distinct_field » : user.name, source.ip ou service.name.')
        if not group_by:
            errors.append('Une règle « valeurs distinctes » doit être regroupée (group_by).')
    else:
        distinct_field = ''
    if rtype == 'pattern':
        if not 1 <= len(pattern) <= 200:
            errors.append('« pattern » : expression régulière de 1 à 200 caractères.')
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f'« pattern » invalide : {exc}.')
    else:
        pattern = ''
    if rtype == 'silence':
        group_by = ''
    outside = data.get('outside_hours') or None
    if outside is not None:
        if (not isinstance(outside, (list, tuple)) or len(outside) != 2
                or not all(isinstance(h, int) and 0 <= h <= 23 for h in outside) or outside[0] == outside[1]):
            errors.append('« outside_hours » : [début, fin] en heures entières 0-23, ex. [7, 20].')
        else:
            outside = [int(outside[0]), int(outside[1])]
    actions = data.get('actions') or {}
    if not isinstance(actions, dict) or any(k not in ('email', 'webhook', 'block_ip') for k in actions):
        errors.append('« actions » : objet {email, webhook, block_ip}.')
        actions = {}
    actions = {k: bool(actions.get(k, False)) for k in ('email', 'webhook', 'block_ip')}
    if actions['block_ip'] and group_by != 'source.ip':
        errors.append('Le blocage d’IP exige un regroupement par source.ip.')
    if errors:
        raise RuleError(errors)
    return {'_id': rule_id, 'name': name, 'description': description, 'type': rtype, 'query': query,
            'window': window, 'severity': severity, 'group_by': group_by, 'threshold': threshold,
            'distinct_field': distinct_field, 'pattern': pattern, 'outside_hours': outside,
            'cooldown_minutes': cooldown, 'enabled': bool(data.get('enabled', True)), 'actions': actions}


# ---------------------------------------------------------------- default rules (scenario C)
FAIL_AUTH = 'event.outcome:failure AND event.category:authentication'
DEFAULT_RULES = [
    {'id': 'brute-force-ip', 'name': 'Force brute : 5 échecs en 5 min depuis une IP', 'type': 'threshold',
     'description': 'Cas d’usage du sujet : bloquer automatiquement une IP après 5 tentatives échouées.',
     'query': FAIL_AUTH, 'window': '5m', 'group_by': 'source.ip', 'threshold': 5, 'severity': 'high',
     'cooldown_minutes': 15, 'actions': {'email': True, 'webhook': True, 'block_ip': True}},
    {'id': 'credential-stuffing', 'name': 'Credential stuffing : une IP essaie 5 comptes ou plus', 'type': 'cardinality',
     'description': 'Une même IP échoue sur au moins 5 comptes différents en 15 min (listes d’identifiants volés).',
     'query': 'event.outcome:failure', 'window': '15m', 'group_by': 'source.ip', 'distinct_field': 'user.name',
     'threshold': 5, 'severity': 'high', 'cooldown_minutes': 30, 'actions': {'email': True, 'webhook': True, 'block_ip': True}},
    {'id': 'unauthorized-country', 'name': 'Connexion réussie depuis un pays non autorisé', 'type': 'threshold',
     'description': 'Cas d’usage du sujet : alerter le SOC. Pays autorisés du laboratoire : TN, FR (modifiable dans la requête).',
     'query': 'event.outcome:success AND source.geo.country_iso_code:* AND NOT source.geo.country_iso_code:(TN OR FR)',
     'window': '15m', 'group_by': 'source.ip', 'threshold': 1, 'severity': 'critical', 'cooldown_minutes': 60,
     'actions': {'email': True, 'webhook': True, 'block_ip': False}},
    {'id': 'off-hours-login', 'name': 'Connexion réussie hors horaires (20 h – 7 h)', 'type': 'threshold',
     'description': 'Connexion réussie en dehors de 7 h – 20 h (heure de Tunis) : compte compromis ou usage anormal.',
     'query': 'event.outcome:success AND event.category:authentication', 'outside_hours': [7, 20], 'window': '24h',
     'group_by': 'user.name', 'threshold': 1, 'severity': 'medium', 'cooldown_minutes': 720,
     'actions': {'email': True, 'webhook': False, 'block_ip': False}},
    {'id': 'privilege-escalation', 'name': 'Élévation de privilèges (sudo, changement de rôle)', 'type': 'threshold',
     'description': 'Logs d’audit de conformité : actions administrateur à vérifier.',
     'query': 'event.action:(sudo OR privilege_escalation OR role_change)', 'window': '15m', 'group_by': 'user.name',
     'threshold': 1, 'severity': 'high', 'cooldown_minutes': 60, 'actions': {'email': True, 'webhook': True, 'block_ip': False}},
    {'id': 'sql-injection', 'name': 'Tentative d’injection SQL dans une requête', 'type': 'pattern',
     'description': 'Logs de tentatives d’intrusion : motif d’injection SQL dans le message.',
     'query': 'event.category:web OR event.action:http_request', 'pattern': r"(?i)(union\s+select|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(\s*\d+\s*\)|;\s*drop\s+table)",
     'window': '15m', 'group_by': 'source.ip', 'threshold': 1, 'severity': 'critical', 'cooldown_minutes': 30,
     'actions': {'email': True, 'webhook': True, 'block_ip': True}},
    {'id': 'error-spike', 'name': 'Pic d’erreurs : plus de 100 ERROR/CRITICAL en 1 h', 'type': 'threshold',
     'description': 'Exemple du sujet (> 100 erreurs/heure), par service.',
     'query': 'log.level:(ERROR OR CRITICAL)', 'window': '1h', 'group_by': 'service.name', 'threshold': 100,
     'severity': 'medium', 'cooldown_minutes': 60, 'actions': {'email': True, 'webhook': False, 'block_ip': False}},
    {'id': 'auth-silence', 'name': 'Silence : aucun log d’authentification depuis 1 h', 'type': 'silence',
     'description': 'Collecte interrompue ? Désactivée par défaut : le laboratoire n’a pas de flux continu.',
     'query': 'event.category:authentication', 'window': '1h', 'threshold': 1, 'severity': 'medium',
     'cooldown_minutes': 120, 'enabled': False, 'actions': {'email': True, 'webhook': False, 'block_ip': False}},
]


class RuleStore:
    def __init__(self, db):
        self.col = db.alert_rules

    def seed_defaults(self):
        """Insert the default rules that do not exist yet (never overwrites an edited rule)."""
        created = []
        for spec in DEFAULT_RULES:
            if self.col.find_one({'_id': spec['id']}):
                continue
            rule = validate(spec)
            rule.update(created_by='system', created_at=datetime.now(timezone.utc), builtin=True)
            self.col.insert_one(rule)
            created.append(rule['_id'])
        return created

    def all(self):
        order = {s: i for i, s in enumerate(reversed(SEVERITIES))}           # critical first
        return sorted(self.col.find(), key=lambda r: (not r.get('enabled'), order.get(r.get('severity'), 9), r['_id']))

    def enabled(self):
        return list(self.col.find({'enabled': True}))

    def get(self, rule_id):
        return self.col.find_one({'_id': rule_id})

    def save(self, data, user, rule_id=None):
        rule = validate(data, existing_id=rule_id)
        now = datetime.now(timezone.utc)
        if rule_id is None and self.get(rule['_id']):
            raise RuleError([f'Une règle « {rule["_id"]} » existe déjà.'])
        rule.update(updated_by=user, updated_at=now)
        if rule_id is None:
            rule.update(created_by=user, created_at=now)
            self.col.insert_one(rule)
        else:
            self.col.update_one({'_id': rule_id}, {'$set': rule})
        return self.get(rule['_id'])

    def set_enabled(self, rule_id, enabled, user):
        self.col.update_one({'_id': rule_id}, {'$set': {'enabled': bool(enabled), 'updated_by': user,
                                                        'updated_at': datetime.now(timezone.utc)}})
        return self.get(rule_id)

    def delete(self, rule_id):
        return self.col.delete_one({'_id': rule_id}).deleted_count == 1

    def record_run(self, rule_id, status, matches=0, error=None):
        self.col.update_one({'_id': rule_id}, {'$set': {'last_run_at': datetime.now(timezone.utc), 'last_status': status,
                                                        'last_matches': matches, 'last_error': error}})


def public(rule):
    out = {k: v for k, v in rule.items() if k != '_id'}
    out['id'] = rule['_id']
    for key in ('created_at', 'updated_at', 'last_run_at'):
        if isinstance(out.get(key), datetime):
            value = out[key]
            out[key] = (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    out['severity_label'] = SEVERITY_LABELS.get(rule.get('severity'), rule.get('severity'))
    out['type_label'] = TYPE_LABELS.get(rule.get('type'), rule.get('type'))
    return out


# ---------------------------------------------------------------- Elasticsearch query
def base_filters(rule):
    filters = [{'range': {'@timestamp': {'gte': f"now-{rule['window']}"}}}]
    if rule.get('query'):
        filters.append({'query_string': {'query': rule['query'], 'default_field': 'message', 'analyze_wildcard': True}})
    if rule.get('outside_hours'):
        start, end = rule['outside_hours']
        inside = ({'range': {'hour_of_day': {'gte': start, 'lt': end}}} if start < end else
                  {'bool': {'should': [{'range': {'hour_of_day': {'gte': start}}}, {'range': {'hour_of_day': {'lt': end}}}]}})
        filters.append({'bool': {'must_not': [inside]}})
    return filters


def build_query(rule):
    """The exact Elasticsearch request run for a rule (also shown in the rule editor)."""
    body = {'size': 0, 'track_total_hits': True, 'query': {'bool': {'filter': base_filters(rule)}},
            'aggs': {'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}}}}
    if rule.get('outside_hours'):
        body['runtime_mappings'] = {'hour_of_day': RUNTIME_FIELDS['hour_of_day']}
    if rule['type'] == 'pattern':
        body.update(size=PATTERN_SCAN, sort=[{'@timestamp': {'order': 'desc'}}],
                    _source=['@timestamp', 'message', 'source.ip', 'user.name', 'service.name'])
        return body
    if rule.get('group_by') and rule['type'] in ('threshold', 'cardinality'):
        sub = {'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}},
               'sample': {'top_hits': {'size': 3, '_source': False, 'sort': [{'@timestamp': {'order': 'desc'}}]}}}
        if rule['type'] == 'cardinality':
            sub['distinct'] = {'cardinality': {'field': rule['distinct_field']}}
        else:
            sub['users'] = {'cardinality': {'field': 'user.name'}}
        terms = {'field': rule['group_by'], 'size': MAX_GROUPS, 'order': {'_count': 'desc'}}
        if rule['type'] == 'threshold':
            terms['min_doc_count'] = rule['threshold']
        body['aggs']['groups'] = {'terms': terms, 'aggs': sub}
    return body


def _total(raw):
    total = raw.get('hits', {}).get('total', {})
    return total.get('value', 0) if isinstance(total, dict) else int(total or 0)


def _dig(src, path):
    cur = src
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def matches(rule, raw):
    """Turn the Elasticsearch answer into the list of triggering groups ``[{key, count, ...}]``."""
    aggs = raw.get('aggregations', {})
    rtype, group_by = rule['type'], rule.get('group_by')
    if rtype == 'silence':
        return [{'key': '—', 'count': 0, 'value': 0}] if _total(raw) == 0 else []
    if rtype == 'pattern':
        regex = re.compile(rule['pattern'])
        groups = {}
        for hit in raw.get('hits', {}).get('hits', []):
            src = hit.get('_source', {})
            if not regex.search(src.get('message') or ''):
                continue
            key = str(_dig(src, group_by) or '—') if group_by else '—'
            g = groups.setdefault(key, {'key': key, 'count': 0, 'samples': [], 'first': None, 'last': None})
            g['count'] += 1
            stamp = src.get('@timestamp')
            g['first'] = min(filter(None, [g['first'], stamp]), default=None)
            g['last'] = max(filter(None, [g['last'], stamp]), default=None)
            if len(g['samples']) < 3:
                g['samples'].append(hit.get('_id'))
        out = [g for g in groups.values() if g['count'] >= rule['threshold']]
        for g in out:
            g['value'] = g['count']
        return sorted(out, key=lambda g: -g['count'])
    if not group_by:
        count = _total(raw)
        if count < rule['threshold']:
            return []
        return [{'key': '—', 'count': count, 'value': count, 'samples': [],
                 'first': aggs.get('first', {}).get('value_as_string'), 'last': aggs.get('last', {}).get('value_as_string')}]
    out = []
    for b in aggs.get('groups', {}).get('buckets', []):
        value = b['doc_count'] if rtype == 'threshold' else b.get('distinct', {}).get('value', 0)
        if value < rule['threshold']:
            continue
        out.append({'key': str(b['key']), 'count': b['doc_count'], 'value': value,
                    'users': b.get('users', {}).get('value'),
                    'first': b.get('first', {}).get('value_as_string'), 'last': b.get('last', {}).get('value_as_string'),
                    'samples': [h['_id'] for h in b.get('sample', {}).get('hits', {}).get('hits', [])]})
    return out


def describe(rule, group):
    """Human sentence for an alert (French)."""
    where = f" ({rule['group_by']} = {group['key']})" if rule.get('group_by') else ''
    win = rule['window']
    if rule['type'] == 'silence':
        return f"Aucun événement correspondant à « {rule['query'] or 'tous les logs'} » depuis {win}."
    if rule['type'] == 'cardinality':
        return f"{group['value']} {rule['distinct_field']} distincts en {win}{where}, {group['count']} événement(s)."
    if rule['type'] == 'pattern':
        return f"{group['count']} message(s) correspondant au motif en {win}{where}."
    return f"{group['count']} événement(s) en {win}{where} (seuil : {rule['threshold']})."
