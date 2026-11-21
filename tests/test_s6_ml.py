"""S6 : classement sshd (Python = Logstash), caractéristiques par (IP, 5 min), Isolation Forest hors ligne et dans le
worker, regroupement des messages par type."""
import json
import shutil
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pytest

from app.alerting import rules as R
from app.alerting.engine import AlertEngine
from app.ml import anomaly as A
from app.ml import templates as T
from app.ml.online import OnlineDetector, feature_query, to_windows
from app.ml.sshd import classify, parse_line

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = [
    'reverse mapping checking getaddrinfo for ns.example.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!',
    'Invalid user webmaster from 173.234.31.186',
    'input_userauth_request: invalid user webmaster [preauth]',
    'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=ec2-52-80-34-196.cn-north-1.compute.amazonaws.com.cn',
    'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253  user=root',
    'Failed password for invalid user  0101 from 5.188.10.180 port 36279 ssh2',
    'message repeated 5 times: [ Failed password for root from 183.62.140.253 port 1 ssh2]',
    'Accepted password for fztu from 119.137.62.142 port 49116 ssh2',
    'Received disconnect from 112.95.230.3: 11: Bye Bye [preauth]',
    'error: Received disconnect from 103.99.0.122: 14: No more user authentication methods available. [preauth]',
    'Disconnecting: Too many authentication failures for admin [preauth]',
]


@pytest.mark.skipif(not shutil.which('ruby'), reason='ruby absent')
def test_python_classifier_matches_the_logstash_filter_line_for_line():
    run = subprocess.run([shutil.which('ruby'), str(ROOT / 'tests/ruby/run_filter.rb'), str(ROOT / 'ingestion/logstash/pipeline/stream.conf'),
                          'sshd_classify'], input='\n'.join(SAMPLES), capture_output=True, text=True, encoding='utf-8',
                         env={'LANG': 'C.UTF-8'}, check=True)
    for msg, line in zip(SAMPLES, run.stdout.splitlines()):
        o, p = json.loads(line), classify(msg)
        assert (o['event']['action'], o['event']['outcome'], o['log']['level'], o.get('user', {}).get('name'),
                o.get('source', {}).get('ip')) == (p['action'], p['outcome'], p['level'], p['user'], p['ip']), msg


def test_parse_line_reads_classic_and_iso_syslog():
    a = parse_line('Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186')
    b = parse_line('2026-11-20T21:47:05.684+00:00 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186')
    assert a['ts'] == datetime(2015, 12, 10, 6, 55, 46) and b['ts'].tzinfo and a['action'] == b['action'] == 'ssh-invalid-user'
    assert parse_line('garbage') is None


def ev(t, msg, ip=None):
    e = {'ts': datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc) + timedelta(seconds=t), 'message': msg, **classify(msg)}
    return e


def test_window_features():
    events = [ev(0, 'Invalid user oracle from 5.188.1.6'), ev(1, 'Failed password for invalid user oracle from 5.188.1.6 port 1 ssh2'),
              ev(2, 'Failed password for root from 5.188.1.6 port 2 ssh2'), ev(3, 'Received disconnect from 5.188.1.6: 11: Bye Bye [preauth]'),
              ev(400, 'Accepted password for etu001 from 41.230.1.2 port 3 ssh2'),
              ev(401, 'Received disconnect from 41.230.1.2: 11: disconnected by user')]
    ws = A.windows(events, label_of=lambda ip: 'attack' if ip.startswith('5.') else 'normal')
    f = {w.ip: dict(zip(A.FEATURES, w.vector)) for w in ws}
    assert f['5.188.1.6']['failures'] == 2 and f['5.188.1.6']['invalid_users'] == 1 and f['5.188.1.6']['root_attempts'] == 1
    assert f['5.188.1.6']['distinct_users'] == 2 and f['5.188.1.6']['preauth_drops'] == 1 and f['5.188.1.6']['failure_ratio'] == 1
    assert f['41.230.1.2']['successes'] == 1 and f['41.230.1.2']['preauth_drops'] == 0          # déconnexion normale


def normal_matrix(n=300, seed=1):
    rng = np.random.default_rng(seed)
    X = np.zeros((n, len(A.FEATURES)))
    X[:, 0] = rng.integers(2, 5, n)
    X[:, 2] = 1
    X[:, 1] = rng.choice([0, 0, 0, 1], n)
    X[:, 4] = 1
    X[:, 6] = X[:, 1] / (X[:, 1] + 1)
    X[:, 3] = rng.choice([0] * 40 + [1], n)
    X[:, 7] = rng.choice([0, 0, 0, 0, 1], n)
    X[:, 8] = rng.integers(1, 4, n)
    return X


def test_isolation_forest_isolates_a_slow_prober_and_explains_why():
    det = A.IsolationDetector(contamination=0.01).fit(normal_matrix())
    prober = np.array([4, 1, 0, 1, 1, 0, 1.0, 2, 1], dtype=float)
    normal = normal_matrix(5, seed=9)
    assert det.flags(prober[None, :])[0] and not det.flags(normal).any()
    assert det.score(prober[None, :])[0] > det.score(normal).max()
    why = {e['feature'] for e in det.explain(prober)}
    assert {'invalid_users', 'preauth_drops'} & why and 'successes' in why or 'failure_ratio' in why


def test_rules_and_metrics():
    ws = [A.Window('a', 0, np.array([9, 6, 0, 0, 1, 6, 1, 0, 1.])), A.Window('b', 0, np.array([9, 1, 0, 6, 6, 0, 1, 0, 1.])),
          A.Window('c', 0, np.array([3, 1, 1, 0, 1, 0, .5, 0, 1.]))]
    assert A.rule_flags(ws).tolist() == [True, True, False]
    assert A.prf([1, 1, 0], [1, 0, 1]) == {'tp': 1, 'fp': 1, 'fn': 1, 'precision': 0.5, 'recall': 0.5, 'f1': 0.5}


# ---------------------------------------------------------------- regroupement des messages
def test_mask_keeps_the_template_and_removes_what_varies():
    assert T.mask('Failed password for root from 183.62.140.253 port 4171 ssh2') == 'Failed password for <USER> from <IP> port <NUM> ssh2'
    assert T.mask('Failed password for invalid user oracle from 5.188.10.180 port 1 ssh2') == \
        'Failed password for invalid user <USER> from <IP> port <NUM> ssh2'
    assert '<HOST>' in T.mask('reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed')


def test_grouping_accuracy_and_tfidf_clustering():
    assert T.grouping_accuracy([0, 0, 1, 1], ['a', 'a', 'b', 'b']) == 1.0
    assert T.grouping_accuracy([0, 0, 0, 1], ['a', 'a', 'b', 'b']) == 0.0
    assert T.grouping_accuracy([0, 0, 1, 2], ['a', 'a', 'b', 'b']) == 0.5
    msgs = ['Failed password for root from 1.2.3.4 port 1 ssh2', 'Failed password for admin from 5.6.7.8 port 2 ssh2',
            'Invalid user test from 1.2.3.4', 'Invalid user oracle from 9.9.9.9', 'Received disconnect from 1.2.3.4: 11: Bye Bye [preauth]']
    vecs, _ = T.tfidf_vectors([T.mask(m) for m in msgs])
    pred = T.cluster(vecs, 0.1)
    assert T.evaluate(pred, ['F', 'F', 'I', 'I', 'D'])['ga'] == 1.0
    new = T.novelty(vecs[:4], ['F', 'F', 'I', 'I'], vecs[4:], threshold=0.15)
    assert new.tolist() == [True]


# ---------------------------------------------------------------- dans le worker
def bucket(minute, ip, n=3, fails=0, ok=1, invalid=0, users=1, root=0, preauth=0):
    t = int(datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc).timestamp() * 1000) + minute * 60_000
    return {'key': {'w': t, 'ip': ip}, 'doc_count': n, 'failures': {'doc_count': fails}, 'successes': {'doc_count': ok},
            'invalid': {'doc_count': invalid}, 'users': {'value': users}, 'root': {'doc_count': root},
            'preauth': {'doc_count': preauth}, 'first': {'value_as_string': 'a'}, 'last': {'value_as_string': 'b'}}


def history(now_min=600):
    rng = np.random.default_rng(3)
    out = []
    for m in range(0, now_min - 15, 5):
        for k in range(3):
            out.append(bucket(m, f'41.230.0.{k}', n=int(rng.integers(2, 5)), fails=int(rng.choice([0, 0, 0, 1]))))
    out.append(bucket(10, '183.62.75.200', n=300, fails=290, ok=0, users=1, root=290))   # attaque connue : exclue de l'apprentissage
    return out


class CompositeES:
    def __init__(self, buckets):
        self.buckets, self.calls = buckets, []

    def search(self, index, body):
        self.calls.append(body)
        return {'aggregations': {'win': {'buckets': self.buckets}}}


def test_feature_query_matches_the_offline_features():
    q = feature_query({'query': 'service.name:openssh'})
    aggs = q['aggs']['win']['aggs']
    assert set(aggs) >= {'failures', 'successes', 'invalid', 'users', 'root', 'preauth'}
    assert q['aggs']['win']['composite']['sources'][0]['w']['date_histogram']['fixed_interval'] == '5m'
    ws = to_windows([bucket(0, 'x'), bucket(5, 'x')])
    assert ws[1].vector[A.FEATURES.index('active_windows')] == 2 and len(ws[0].vector) == len(A.FEATURES)


def test_online_detector_flags_a_recent_slow_prober_with_its_causes():
    now = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc).timestamp()
    es = CompositeES(history() + [bucket(596, '52.80.1.2', n=4, fails=1, ok=0, invalid=1, preauth=2),
                                  bucket(596, '41.230.0.1', n=3, fails=0)])
    groups = OnlineDetector(es, 'logs-*', lambda: now).groups({'_id': 'ml', 'query': 'service.name:openssh', 'threshold': 10})
    assert [g['key'] for g in groups] == ['52.80.1.2']
    assert groups[0]['explain'] and groups[0]['training_windows'] > 300


def test_online_detector_waits_for_enough_history():
    now = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc).timestamp()
    es = CompositeES([bucket(596, '52.80.1.2', n=4, fails=1, ok=0, invalid=1, preauth=2)])
    assert OnlineDetector(es, 'logs-*', lambda: now).groups({'_id': 'ml', 'query': '', 'threshold': 10}) == []


def test_anomaly_rule_validation_and_alert(stores, config):
    rule = R.validate({'id': 'ml-x', 'name': 'Anomalie', 'type': 'anomaly', 'window': '1h', 'severity': 'medium',
                       'group_by': '', 'threshold': 10, 'actions': {'email': False}})
    assert rule['group_by'] == 'source.ip' and rule['window'] == '5m'
    with pytest.raises(R.RuleError):
        R.validate({**rule, 'id': 'ml-y', 'threshold': 500})
    store = R.RuleStore(stores.db)
    store.seed_defaults()
    for r in store.all():
        store.set_enabled(r['_id'], r['_id'] == 'ml-anomaly-ssh', 'test')
    stores.es = CompositeES(history() + [bucket(596, '52.80.1.2', n=4, fails=1, ok=0, invalid=1, preauth=2)])
    eng = AlertEngine(stores, config, now=lambda: datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc))
    assert eng.run_once()['created'] == 1
    alert = stores.db.alerts.find_one({'rule_id': 'ml-anomaly-ssh'})
    assert alert['group'] == '52.80.1.2' and alert['explain'] and 'Comportement inhabituel' in alert['message']
    assert alert['response'] is None                       # pas de blocage automatique sur une anomalie
