"""Regroupement des messages de logs par modèle (template) : TF-IDF vs MiniLM, et détection de nouveaux types.

« Failed password for root from 183.62.75.200 port 4171 ssh2 » et « Failed password for admin from 5.188.1.6 port
33091 ssh2 » sont le même type d'événement. Regrouper les messages ainsi permet de compter les types, de repérer les
messages récurrents et de signaler un type jamais vu (souvent le signe d'un nouvel outil ou d'une panne).

- ``mask`` remplace ce qui varie (IP, ports, nombres, hexadécimal, noms d'hôtes) par <*> : étape classique du parsing
  de logs, sans apprentissage.
- TF-IDF : un message = un sac de mots pondéré ; rapide, explicable, sensible aux mots exacts.
- MiniLM (all-MiniLM-L6-v2, 384 dimensions) : plongement sémantique ; deux formulations proches se rapprochent même
  sans mots communs. Exécuté en ONNX (pas de PyTorch), modèle local désigné par MINILM_DIR.
- Regroupement : classification ascendante hiérarchique (distance cosinus, lien moyen) coupée à un seuil de distance.
"""
import os
import re
import time
from collections import Counter, defaultdict

import numpy as np

MASKS = [
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '<IP>'),
    (re.compile(r'\bec2(?:-\d{1,3}){4}\S*'), '<HOST>'),
    (re.compile(r'\b[\w-]+(?:\.[\w-]+)+\.(?:com|net|org|cn|ru|br|mx|vn|de|fr|io)\b', re.I), '<HOST>'),
    (re.compile(r'\b0x[0-9a-f]+\b', re.I), '<HEX>'),
    (re.compile(r'(?<=port )\d+'), '<NUM>'),
    (re.compile(r'\b\d+\b'), '<NUM>'),
    (re.compile(r'(?<=for invalid user )\S+|(?<=Invalid user )\S+|(?<=invalid user )\S+(?= \[preauth\])'), '<USER>'),
    (re.compile(r'(?<=Failed password for )(?!invalid user)\S+|(?<=Accepted password for )\S+|(?<=user=)\S+|(?<=for user )\S+'), '<USER>'),
]


def mask(message):
    for rx, token in MASKS:
        message = rx.sub(token, message)
    return re.sub(r'\s+', ' ', message).strip()


# ---------------------------------------------------------------- représentations
def tfidf_vectors(messages):
    from sklearn.feature_extraction.text import TfidfVectorizer
    vec = TfidfVectorizer(token_pattern=r'[A-Za-z<>_*()]+|\S', lowercase=True, sublinear_tf=True)
    return vec.fit_transform(messages).toarray(), vec


class MiniLM:
    """Encodeur all-MiniLM-L6-v2 en ONNX : moyenne des états cachés pondérée par le masque, puis normalisation L2."""

    def __init__(self, directory=None):
        import onnxruntime as ort
        from tokenizers import Tokenizer
        directory = directory or os.getenv('MINILM_DIR', '')
        self.tokenizer = Tokenizer.from_file(os.path.join(directory, 'tokenizer.json'))
        self.tokenizer.enable_padding()
        self.tokenizer.enable_truncation(128)
        self.session = ort.InferenceSession(os.path.join(directory, 'model.onnx'), providers=['CPUExecutionProvider'])
        self.inputs = {i.name for i in self.session.get_inputs()}

    def encode(self, texts, batch=64):
        out = []
        for i in range(0, len(texts), batch):
            enc = self.tokenizer.encode_batch(list(texts[i:i + batch]))
            ids = np.array([e.ids for e in enc], dtype=np.int64)
            att = np.array([e.attention_mask for e in enc], dtype=np.int64)
            feed = {'input_ids': ids, 'attention_mask': att}
            if 'token_type_ids' in self.inputs:
                feed['token_type_ids'] = np.zeros_like(ids)
            hidden = self.session.run(None, feed)[0]
            v = (hidden * att[..., None]).sum(1) / att.sum(1, keepdims=True)
            out.append(v / np.linalg.norm(v, axis=1, keepdims=True))
        return np.vstack(out)


def minilm_available(directory=None):
    directory = directory or os.getenv('MINILM_DIR', '')
    return bool(directory) and os.path.exists(os.path.join(directory, 'model.onnx'))


# ---------------------------------------------------------------- regroupement et évaluation
def cluster(vectors, threshold):
    """Regroupe les vecteurs uniques puis propage aux doublons (2 000 messages → quelques centaines de distincts)."""
    from sklearn.cluster import AgglomerativeClustering
    uniq, inverse = np.unique(np.round(vectors, 6), axis=0, return_inverse=True)
    if len(uniq) == 1:
        return np.zeros(len(vectors), dtype=int)
    model = AgglomerativeClustering(n_clusters=None, distance_threshold=threshold, metric='cosine', linkage='average')
    return model.fit_predict(uniq)[inverse.ravel()]


def grouping_accuracy(pred, truth):
    """Mesure de référence du benchmark Loghub : part des messages dont le groupe prédit est EXACTEMENT un groupe réel."""
    groups_pred, groups_true = defaultdict(set), defaultdict(set)
    for i, (p, t) in enumerate(zip(pred, truth)):
        groups_pred[p].add(i)
        groups_true[t].add(i)
    exact = {frozenset(g) for g in groups_true.values()}
    return sum(len(g) for g in groups_pred.values() if frozenset(g) in exact) / len(truth)


def evaluate(pred, truth):
    from sklearn.metrics import adjusted_rand_score, normalized_mutual_info_score
    return {'clusters': int(len(set(pred))), 'templates': int(len(set(truth))),
            'ga': round(grouping_accuracy(pred, truth), 3), 'ari': round(adjusted_rand_score(truth, pred), 3),
            'nmi': round(normalized_mutual_info_score(truth, pred), 3)}


def novelty(train_vecs, train_labels, test_vecs, threshold):
    """Un message est « nouveau » si son plus proche centre de groupe connu est à une distance cosinus > seuil."""
    centers = []
    for lab in sorted(set(train_labels)):
        c = train_vecs[np.asarray(train_labels) == lab].mean(0)
        centers.append(c / (np.linalg.norm(c) or 1))
    C = np.vstack(centers)
    t = test_vecs / np.clip(np.linalg.norm(test_vecs, axis=1, keepdims=True), 1e-9, None)
    return 1 - (t @ C.T).max(1) > threshold


def top_templates(messages, labels, n=8):
    counts = Counter(labels)
    examples = {}
    for m, lab in zip(messages, labels):
        examples.setdefault(lab, m)
    return [{'count': c, 'example': examples[lab]} for lab, c in counts.most_common(n)]


def timed(fn, *args, **kw):
    t0 = time.perf_counter()
    out = fn(*args, **kw)
    return out, round(time.perf_counter() - t0, 3)
