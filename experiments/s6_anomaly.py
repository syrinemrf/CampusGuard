"""Expérience 1 (S6) : règles du worker vs Isolation Forest, sur le journal sshd réel + un trafic de campus légitime.

Protocole
- Attaques : les 2 000 lignes réelles du serveur LabSZ (Loghub OpenSSH_2k). Toute IP du journal est étiquetée
  « attaque », sauf celle du compte qui s'est réellement connecté (119.137.62.142, session normale).
- Trafic légitime : campus_benign.generate(seed=2026), même plage horaire, même format syslog.
- Unité évaluée : (IP, fenêtre de 5 min), soit ce que le worker examine à chaque cycle.
- Isolation Forest est entraîné sur une AUTRE journée de trafic normal (seed=7), comme en exploitation où l'on
  apprend le comportement habituel puis on surveille. Seuil : 1 % de fenêtres d'entraînement considérées anormales.
- Les règles sont celles du worker : 5 échecs en 5 min, ou 5 comptes différents.
"""
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.ml import anomaly as A  # noqa: E402
from app.ml.sshd import parse_line  # noqa: E402
from campus_benign import generate  # noqa: E402

LEGIT_REAL = {'119.137.62.142'}


def load(real_path):
    real = [e for e in (parse_line(line) for line in Path(real_path).read_text(encoding='utf-8', errors='replace').splitlines()) if e]
    benign_lines, benign = generate(seed=2026)
    test = [e for e in (parse_line(line) for line in benign_lines) if e]
    train_lines, _ = generate(seed=7)
    train = [e for e in (parse_line(line) for line in train_lines) if e]
    label = lambda ip: 'normal' if ip in benign or ip in LEGIT_REAL else 'attack'   # noqa: E731
    return A.windows(real + test, label_of=label), A.windows(train)


def by_ip(ws, flags):
    return {w.ip for w, f in zip(ws, flags) if f}


def run(real_path, contamination=0.01):
    from sklearn.metrics import average_precision_score, precision_recall_curve
    ws, train = load(real_path)
    X, y = A.matrix(ws), np.array([w.label == 'attack' for w in ws])
    rules = A.rule_flags(ws)
    det = A.IsolationDetector(contamination=contamination).fit(A.matrix(train))
    iso, score = det.flags(X), det.score(X)
    hybrid = rules | iso
    attackers = {w.ip for w in ws if w.label == 'attack'}
    benign = {w.ip for w in ws if w.label == 'normal'}

    def summary(flags):
        found = by_ip(ws, flags)
        return {**A.prf(flags, y), 'attack_ips_found': len(found & attackers), 'attack_ips': len(attackers),
                'benign_ips_flagged': len(found & benign), 'benign_ips': len(benign)}

    # Ce que chaque méthode voit et que l'autre manque : exemples expliqués (au plus 4 de chaque)
    only_iso = [w for w, r, i in zip(ws, rules, iso) if i and not r and w.label == 'attack']
    only_rules = [w for w, r, i in zip(ws, rules, iso) if r and not i and w.label == 'attack']
    false_iso = [w for w, r, i in zip(ws, rules, iso) if i and w.label == 'normal']

    def describe(w):
        v = dict(zip(A.FEATURES, w.vector.tolist()))
        return {'ip': w.ip, 'failures': int(v['failures']), 'invalid_users': int(v['invalid_users']),
                'distinct_users': int(v['distinct_users']), 'preauth_drops': int(v['preauth_drops']),
                'why': det.explain(w.vector)}
    precision, recall, _ = precision_recall_curve(y, score)
    return {
        'windows': len(ws), 'attack_windows': int(y.sum()), 'train_windows': len(train),
        'contamination': contamination,
        'rules': summary(rules), 'isolation_forest': summary(iso), 'hybrid': summary(hybrid),
        'average_precision': round(float(average_precision_score(y, score)), 3),
        'pr_curve': {'precision': precision.tolist(), 'recall': recall.tolist()},
        'examples': {'iso_only': [describe(w) for w in only_iso[:4]], 'rules_only': [describe(w) for w in only_rules[:4]],
                     'iso_false_alarms': [describe(w) for w in false_iso[:4]]},
        'counts': {'iso_only': len(only_iso), 'rules_only': len(only_rules), 'iso_false_alarms': len(false_iso)},
        'scores': {'attack': score[y].tolist(), 'normal': score[~y].tolist(), 'threshold': float(-det.model.offset_)},
    }
