"""Expérience 2 (S6) : regrouper les messages sshd par type — TF-IDF vs MiniLM — contre la vérité terrain Loghub.

Protocole
- Données : OpenSSH_2k (2 000 messages réels). Vérité terrain : OpenSSH_2k.log_structured.csv (EventId, 27 types
  annotés par les auteurs de Loghub).
- Quatre variantes : {TF-IDF, MiniLM} × {message brut, message masqué}. Drain3 (analyseur de logs de référence) est
  ajouté s'il est installé.
- Le seuil de distance est choisi sur les 1 000 premiers messages, puis appliqué tel quel aux 1 000 suivants : le score
  publié n'est pas mesuré sur les données qui ont servi à régler.
- Mesures : GA (grouping accuracy, mesure du benchmark Loghub), ARI, NMI, nombre de groupes, temps.
- Nouveaux types : 10 tirages ; à chaque tirage 3 types sont retirés de l'apprentissage ; un message est déclaré
  nouveau si aucun groupe connu n'est assez proche. Précision et rappel de cette détection.
"""
import csv
import random
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.ml import templates as T  # noqa: E402

THRESHOLDS = [round(x, 2) for x in np.arange(0.02, 0.62, 0.02)]


def load(structured_csv):
    rows = list(csv.DictReader(open(structured_csv, encoding='utf-8')))
    return [r['Content'] for r in rows], [r['EventId'] for r in rows]


def representations(messages, minilm=None):
    masked = [T.mask(m) for m in messages]
    reps = {}
    for name, texts in (('TF-IDF, brut', messages), ('TF-IDF, masqué', masked)):
        (vecs, _), secs = T.timed(T.tfidf_vectors, texts)
        reps[name] = (vecs, secs)
    if minilm is not None:
        for name, texts in (('MiniLM, brut', messages), ('MiniLM, masqué', masked)):
            vecs, secs = T.timed(minilm.encode, texts)
            reps[name] = (vecs, secs)
    return reps, masked


def drain(messages):
    try:
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
    except ImportError:
        return None
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    miner = TemplateMiner(config=cfg)
    return [miner.add_log_message(m)['cluster_id'] for m in messages]


def run(structured_csv, minilm_dir=None, seed=2026):
    messages, truth = load(structured_csv)
    half = len(messages) // 2
    minilm = T.MiniLM(minilm_dir) if T.minilm_available(minilm_dir) else None
    reps, masked = representations(messages, minilm)
    results, curves = [], {}
    for name, (vecs, secs) in reps.items():
        tune = [(t, T.grouping_accuracy(T.cluster(vecs[:half], t), truth[:half])) for t in THRESHOLDS]
        curves[name] = tune
        best_t = max(tune, key=lambda x: (x[1], -x[0]))[0]
        (pred, csecs) = T.timed(T.cluster, vecs[half:], best_t)
        results.append({'method': name, 'threshold': best_t, **T.evaluate(pred, truth[half:]),
                        'seconds': round(secs * (len(messages) - half) / len(messages) + csecs, 3)})
    (d, dsecs) = T.timed(drain, messages[half:])
    if d is not None:
        results.append({'method': 'Drain3 (référence)', 'threshold': None, **T.evaluate(d, truth[half:]), 'seconds': dsecs})

    # nouveaux types (novelty detection) avec la meilleure représentation de chaque famille
    rng = random.Random(seed)
    kinds = sorted({t for t in truth if truth.count(t) >= 5})
    novelty = {}
    for name in [n for n in reps if 'masqué' in n]:
        vecs = reps[name][0]
        tp = fp = fn = 0
        for _ in range(10):
            held = set(rng.sample(kinds, 3))
            known = [i for i, t in enumerate(truth) if t not in held]
            train = known[::2]
            test = [i for i in range(len(truth)) if i not in set(train)]
            flags = T.novelty(vecs[train], [truth[i] for i in train], vecs[test], threshold=0.15 if 'TF' in name else 0.08)
            is_new = np.array([truth[i] in held for i in test])
            tp += int((flags & is_new).sum())
            fp += int((flags & ~is_new).sum())
            fn += int((~flags & is_new).sum())
        p = tp / (tp + fp) if tp + fp else 0
        r = tp / (tp + fn) if tp + fn else 0
        novelty[name] = {'precision': round(p, 3), 'recall': round(r, 3), 'f1': round(2 * p * r / (p + r), 3) if p + r else 0}

    best = max((r for r in results if r['threshold'] is not None), key=lambda r: r['ga'])
    pred_all = T.cluster(reps[best['method']][0], best['threshold'])
    return {'messages': len(messages), 'templates': len(set(truth)), 'minilm': minilm is not None, 'results': results,
            'curves': curves, 'novelty': novelty, 'best': best['method'],
            'examples': T.top_templates(masked, pred_all, 8)}
