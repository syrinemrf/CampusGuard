"""Isolation Forest dans le worker d'alertes (règle de type « anomaly »).

À chaque cycle :
1. Elasticsearch calcule, pour chaque couple (IP, fenêtre de 5 min) des 7 derniers jours, les mêmes caractéristiques que
   l'expérience S6 (échecs, comptes inexistants, comptes distincts, root, coupures avant authentification…).
2. Le modèle apprend le comportement habituel sur l'historique, en écartant les fenêtres que les règles signalent
   déjà (une attaque connue ne doit pas devenir « normale »).
3. Les fenêtres des 10 dernières minutes sont notées ; celles qui sortent du comportement habituel deviennent une
   alerte « à examiner » avec les causes probables (caractéristiques les plus éloignées de la normale).

Choix issus de l'expérience (docs/experiments) : les règles restent la réponse immédiate (blocage) ; Isolation Forest
ajoute les attaques lentes et les sondages que les seuils ne voient pas, sans blocage automatique.
"""
import logging

import numpy as np

from app.ml import anomaly as A

log = logging.getLogger('sentinel.ml')
HISTORY = 'now-7d'
RECENT_MINUTES = 10
MIN_TRAINING = 40
MAX_BUCKETS = 20000
PREAUTH_ACTIONS = sorted(A.PREAUTH)


def feature_query(rule, after=None):
    filters = [{'range': {'@timestamp': {'gte': HISTORY}}}, {'exists': {'field': 'source.ip'}}]
    if rule.get('query'):
        filters.append({'query_string': {'query': rule['query'], 'default_field': 'message', 'analyze_wildcard': True}})
    composite = {'size': 1000, 'sources': [
        {'w': {'date_histogram': {'field': '@timestamp', 'fixed_interval': f'{A.WINDOW_S // 60}m'}}},
        {'ip': {'terms': {'field': 'source.ip'}}}]}
    if after:
        composite['after'] = after
    return {'size': 0, 'query': {'bool': {'filter': filters}}, 'aggs': {'win': {'composite': composite, 'aggs': {
        'failures': {'filter': {'term': {'event.outcome': 'failure'}}},
        'successes': {'filter': {'term': {'event.outcome': 'success'}}},
        'invalid': {'filter': {'term': {'event.action': 'ssh-invalid-user'}}},
        'users': {'cardinality': {'field': 'user.name'}},
        'root': {'filter': {'bool': {'filter': [{'term': {'event.outcome': 'failure'}}, {'term': {'user.name': 'root'}}]}}},
        'preauth': {'filter': {'bool': {'filter': [{'terms': {'event.action': PREAUTH_ACTIONS}}],
                                        'must_not': [{'match_phrase': {'message': 'disconnected by user'}}]}}},
        'first': {'min': {'field': '@timestamp'}}, 'last': {'max': {'field': '@timestamp'}}}}}}


def to_windows(buckets):
    """Buckets composites (triés par fenêtre) → fenêtres avec le même vecteur que app.ml.anomaly.windows."""
    seen = {}
    out = []
    for b in sorted(buckets, key=lambda b: (b['key']['w'], b['key']['ip'])):
        ip = b['key']['ip']
        seen[ip] = seen.get(ip, 0) + 1
        fails, ok = b['failures']['doc_count'], b['successes']['doc_count']
        v = np.array([b['doc_count'], fails, ok, b['invalid']['doc_count'], b['users']['value'], b['root']['doc_count'],
                      fails / (fails + ok) if fails + ok else 0.0, b['preauth']['doc_count'], seen[ip]], dtype=float)
        w = A.Window(ip, int(b['key']['w'] // 1000), v)
        w.first, w.last = b['first'].get('value_as_string'), b['last'].get('value_as_string')
        out.append(w)
    return out


class OnlineDetector:
    def __init__(self, es, index, now_s):
        self.es, self.index, self.now_s = es, index, now_s

    def collect(self, rule):
        buckets, after = [], None
        while len(buckets) < MAX_BUCKETS:
            raw = self.es.search(self.index, feature_query(rule, after))
            agg = raw.get('aggregations', {}).get('win', {})
            page = agg.get('buckets', [])
            buckets.extend(page)
            after = agg.get('after_key')
            if not page or not after or len(page) < 1000:
                break
        return to_windows(buckets)

    def groups(self, rule):
        """Groupes déclencheurs au format des autres règles ({key, count, value, first, last, explain})."""
        ws = self.collect(rule)
        cutoff = self.now_s() - RECENT_MINUTES * 60
        history = [w for w in ws if w.start < cutoff - A.WINDOW_S]
        known = A.rule_flags(history)
        train = [w for w, k in zip(history, known) if not k]
        recent = [w for w in ws if w.start >= cutoff - A.WINDOW_S]
        if len(train) < MIN_TRAINING or not recent:
            log.info('anomaly rule %s: %d training windows, %d recent: skipped', rule['_id'], len(train), len(recent))
            return []
        det = A.IsolationDetector(n_estimators=150, contamination=max(1, rule['threshold']) / 1000).fit(A.matrix(train))
        X = A.matrix(recent)
        flags, scores = det.flags(X), det.score(X)
        best = {}
        for w, f, s in zip(recent, flags, scores):
            if f and (w.ip not in best or s > best[w.ip][1]):
                best[w.ip] = (w, s)
        out = []
        for ip, (w, s) in sorted(best.items(), key=lambda kv: -kv[1][1]):
            out.append({'key': ip, 'count': int(w.vector[0]), 'value': round(float(s), 3), 'first': w.first, 'last': w.last,
                        'samples': [], 'explain': det.explain(w.vector), 'training_windows': len(train)})
        return out
