"""Détection d'anomalies par adresse IP et fenêtre de 5 minutes : règles du worker vs Isolation Forest.

Chaque couple (IP, fenêtre) devient un vecteur de comportement. Les règles regardent un seul chiffre (5 échecs,
5 comptes) ; Isolation Forest regarde le profil entier et isole ce qui ne ressemble pas au reste, sans étiquette.
``explain`` donne les caractéristiques qui s'écartent le plus du comportement habituel (« causes probables »).
"""
from collections import defaultdict
from dataclasses import dataclass

import numpy as np

WINDOW_S = 300
FEATURES = (
    'events',            # lignes émises par l'IP dans la fenêtre
    'failures',          # mots de passe refusés (une tentative = un échec)
    'successes',         # connexions acceptées
    'invalid_users',     # comptes inexistants essayés
    'distinct_users',    # comptes différents visés
    'root_attempts',     # tentatives sur root
    'failure_ratio',     # échecs / (échecs + réussites)
    'preauth_drops',     # déconnexions avant authentification, erreurs, « break-in attempt »
    'active_windows',    # nombre de fenêtres où l'IP a déjà été vue (persistance)
)
LABELS = {
    'events': 'volume de lignes', 'failures': 'mots de passe refusés', 'successes': 'connexions réussies',
    'invalid_users': 'comptes inexistants essayés', 'distinct_users': 'comptes différents visés',
    'root_attempts': 'tentatives sur root', 'failure_ratio': 'part d’échecs', 'preauth_drops': 'coupures avant authentification',
    'active_windows': 'présence répétée',
}
PREAUTH = {'ssh-disconnect', 'ssh-reverse-mapping', 'ssh-error', 'ssh-too-many-failures'}


@dataclass
class Window:
    ip: str
    start: int
    vector: np.ndarray
    label: str = None


def windows(events, window_s=WINDOW_S, label_of=None):
    """events : dicts issus de app.ml.sshd.parse_line (ts, ip, action, outcome, user, count, message)."""
    # Seules les lignes qui portent une IP comptent : c'est aussi ce qu'Elasticsearch peut agréger en production
    # (app/ml/online.py), si bien que l'expérience et le worker calculent exactement les mêmes caractéristiques.
    groups = defaultdict(list)
    for e in events:
        if e.get('ip'):
            groups[(e['ip'], int(e['ts'].timestamp()) // window_s)].append(e)
    seen = defaultdict(int)
    out = []
    for (ip, w), evs in sorted(groups.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        seen[ip] += 1
        fails = sum(e.get('count', 1) for e in evs if e['outcome'] == 'failure')
        ok = sum(1 for e in evs if e['outcome'] == 'success')
        users = {e['user'] for e in evs if e.get('user')}
        v = np.array([
            len(evs), fails, ok, sum(1 for e in evs if e['action'] == 'ssh-invalid-user'), len(users),
            sum(e.get('count', 1) for e in evs if e['outcome'] == 'failure' and e.get('user') == 'root'),
            fails / (fails + ok) if fails + ok else 0.0,
            sum(1 for e in evs if e['action'] in PREAUTH and 'disconnected by user' not in e['message']), seen[ip],
        ], dtype=float)
        out.append(Window(ip, w * window_s, v, label_of(ip) if label_of else None))
    return out


def matrix(ws):
    return np.vstack([w.vector for w in ws]) if ws else np.zeros((0, len(FEATURES)))


def rule_flags(ws, failures=5, distinct_users=5):
    """Les deux règles du worker qui portent sur SSH : force brute (5 échecs / 5 min) et credential stuffing
    (5 comptes / 15 min, approché ici par la fenêtre de 5 min, ce qui avantage légèrement la règle)."""
    X = matrix(ws)
    if not len(X):
        return np.zeros(0, dtype=bool)
    return (X[:, FEATURES.index('failures')] >= failures) | (X[:, FEATURES.index('distinct_users')] >= distinct_users)


def transform(X):
    """Comptes très asymétriques : log1p rend une IP à 300 échecs comparable à une IP à 30, sans l'écraser."""
    return np.log1p(np.clip(X, 0, None))


class IsolationDetector:
    def __init__(self, n_estimators=200, contamination='auto', random_state=2026):
        from sklearn.ensemble import IsolationForest
        self.model = IsolationForest(n_estimators=n_estimators, contamination=contamination, random_state=random_state)
        self.center = self.scale = None

    def fit(self, X):
        Z = transform(X)
        self.model.fit(Z)
        self.center = np.median(Z, axis=0)
        mad = np.median(np.abs(Z - self.center), axis=0)
        self.scale = np.maximum(np.where(mad > 0, mad * 1.4826, Z.std(axis=0)), 0.25)   # plancher : pas de z infini
        return self

    def score(self, X):
        """Score d'anomalie dans [0, 1] environ : plus haut = plus isolé (inverse du score sklearn)."""
        return -self.model.score_samples(transform(X))

    def flags(self, X):
        return self.model.predict(transform(X)) == -1

    def explain(self, x, top=3):
        """Caractéristiques les plus éloignées du comportement médian, en écarts robustes."""
        z = (transform(x[None, :])[0] - self.center) / self.scale
        order = np.argsort(-np.abs(z))[:top]
        return [{'feature': FEATURES[i], 'label': LABELS[FEATURES[i]], 'value': float(x[i]), 'z': round(float(z[i]), 1)}
                for i in order if abs(z[i]) >= 1]


def prf(pred, truth):
    pred, truth = np.asarray(pred, bool), np.asarray(truth, bool)
    tp, fp, fn = int((pred & truth).sum()), int((pred & ~truth).sum()), int((~pred & truth).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {'tp': tp, 'fp': fp, 'fn': fn, 'precision': round(p, 3), 'recall': round(r, 3),
            'f1': round(2 * p * r / (p + r), 3) if p + r else 0.0}
