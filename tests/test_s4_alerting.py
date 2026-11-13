"""S4 — alerting (module G) and SOAR-lite response: rules, worker, silencing, cooldown, notifications, blocklist."""
import json
import struct
from datetime import datetime, timedelta, timezone

import pytest
import requests

from app.alerting import rules as R
from app.alerting.blocklist import PREFIX, Blocklist, BlockError
from app.alerting.engine import COOLDOWN_PREFIX, HEARTBEAT_KEY, LOCK_KEY, AlertEngine, fingerprint
from app.alerting.notify import Notifier, email_message, png_bar_chart, webhook_payload
from app.alerting.worker import Worker
from app.config import Config

ATTACKER = '203.0.113.77'


# ------------------------------------------------------------------ fakes
class Resp:
    def __init__(self, status=200, payload=None):
        self.status_code, self.ok, self._p = status, status < 400, payload or {}

    def json(self):
        return self._p

    def raise_for_status(self):
        if not self.ok:
            raise requests.HTTPError(str(self.status_code))


class FakeHTTP:
    """Records POSTs (webhooks, Logstash); ``fail`` = number of failures before success (-1: always)."""

    def __init__(self, fail=0):
        self.posts, self.fail = [], fail

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        if self.fail == -1 or self.fail > 0:
            self.fail = self.fail - 1 if self.fail > 0 else -1
            raise requests.ConnectionError('refused')
        return Resp(200)

    def get(self, url, timeout=None):
        raise requests.ConnectionError('not used')


class FakeSMTP:
    sent = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def send_message(self, msg):
        FakeSMTP.sent.append(msg)


def grouped(buckets, total=None):
    return {'hits': {'total': {'value': total if total is not None else sum(b['doc_count'] for b in buckets)}, 'hits': []},
            'aggregations': {'groups': {'buckets': buckets}}}


def bucket(key, n, distinct=None):
    b = {'key': key, 'doc_count': n, 'first': {'value_as_string': '2026-11-13T20:00:00.000Z'},
         'last': {'value_as_string': '2026-11-13T20:01:00.000Z'}, 'users': {'value': 1},
         'sample': {'hits': {'hits': [{'_id': f'ev{i}'} for i in range(min(n, 3))]}}}
    if distinct is not None:
        b['distinct'] = {'value': distinct}
    return b


@pytest.fixture
def cfg(config):
    return Config(**{**config.__dict__, 'smtp_host': 'mailpit', 'webhook_url': 'http://hooks.local/x', 'notify_retries': 3,
                     'webhook_demo_token': 'demo-token'})


@pytest.fixture
def rule_store(stores):
    store = R.RuleStore(stores.db)
    store.seed_defaults()
    for r in store.all():                       # keep only brute-force active for engine tests
        store.set_enabled(r['_id'], r['_id'] == 'brute-force-ip', 'test')
    return store


@pytest.fixture
def engine(stores, cfg, rule_store):
    FakeSMTP.sent = []
    http = FakeHTTP()
    eng = AlertEngine(stores, cfg, http=http, smtp_factory=FakeSMTP, sleep=lambda s: None)
    eng.fake_http = http
    return eng


@pytest.fixture
def s4app(app, cfg, stores):
    app.extensions['sentinel_config'] = cfg
    app.extensions['sentinel_http'] = FakeHTTP()
    app.extensions['sentinel_smtp'] = FakeSMTP
    app.extensions['sentinel_sleep'] = lambda s: None
    return app


# ------------------------------------------------------------------ rule validation
def test_default_rules_cover_scenario_c_and_are_valid():
    ids = {r['id'] for r in R.DEFAULT_RULES}
    assert {'brute-force-ip', 'credential-stuffing', 'unauthorized-country', 'off-hours-login', 'privilege-escalation',
            'sql-injection', 'error-spike', 'auth-silence'} == ids
    assert {R.validate(r)['type'] for r in R.DEFAULT_RULES} == set(R.RULE_TYPES)       # all 4 condition types used
    bf = R.validate(next(r for r in R.DEFAULT_RULES if r['id'] == 'brute-force-ip'))
    assert (bf['threshold'], bf['window'], bf['group_by'], bf['actions']['block_ip']) == (5, '5m', 'source.ip', True)


def test_seeding_is_idempotent_and_never_overwrites_an_edited_rule(stores):
    store = R.RuleStore(stores.db)
    assert len(store.seed_defaults()) == len(R.DEFAULT_RULES)
    stores.db.alert_rules.update_one({'_id': 'brute-force-ip'}, {'$set': {'threshold': 9}})
    assert store.seed_defaults() == [] and store.get('brute-force-ip')['threshold'] == 9


@pytest.mark.parametrize('patch, message', [
    ({'type': 'nope'}, '« type »'), ({'window': '2h'}, '« window »'), ({'severity': 'huge'}, '« severity »'),
    ({'group_by': 'message'}, '« group_by »'), ({'threshold': 0}, '« threshold »'), ({'id': 'A B'}, '« id »'),
    ({'type': 'pattern', 'pattern': '(unclosed'}, '« pattern » invalide'),
    ({'type': 'cardinality', 'group_by': '', 'distinct_field': 'user.name', 'actions': {}}, 'regroupée'),
    ({'group_by': 'user.name'}, 'blocage d’IP exige'), ({'outside_hours': [7, 7]}, '« outside_hours »'),
])
def test_invalid_rules_are_rejected_with_a_clear_message(patch, message):
    base = {**next(r for r in R.DEFAULT_RULES if r['id'] == 'brute-force-ip')}
    base.update(patch)
    with pytest.raises(R.RuleError) as err:
        R.validate(base)
    assert any(message in e for e in err.value.errors), err.value.errors


# ------------------------------------------------------------------ query building + evaluation
def rule(rid):
    return R.validate(next(r for r in R.DEFAULT_RULES if r['id'] == rid))


def test_threshold_query_groups_by_ip_with_min_doc_count():
    q = R.build_query(rule('brute-force-ip'))
    f = q['query']['bool']['filter']
    assert f[0] == {'range': {'@timestamp': {'gte': 'now-5m'}}}
    assert f[1]['query_string']['query'] == R.FAIL_AUTH
    assert q['aggs']['groups']['terms'] == {'field': 'source.ip', 'size': 50, 'order': {'_count': 'desc'}, 'min_doc_count': 5}


def test_off_hours_rule_uses_the_same_runtime_field_as_kibana():
    q = R.build_query(rule('off-hours-login'))
    assert 'hour_of_day' in q['runtime_mappings']
    assert q['query']['bool']['filter'][-1] == {'bool': {'must_not': [{'range': {'hour_of_day': {'gte': 7, 'lt': 20}}}]}}
    wrap = R.build_query({**rule('off-hours-login'), 'outside_hours': [22, 6]})
    assert 'should' in wrap['query']['bool']['filter'][-1]['bool']['must_not'][0]['bool']


def test_matches_threshold_cardinality_pattern_and_silence():
    assert [g['key'] for g in R.matches(rule('brute-force-ip'), grouped([bucket(ATTACKER, 8), bucket('10.0.0.1', 4)]))] == [ATTACKER]
    cs = R.matches(rule('credential-stuffing'), grouped([bucket('198.51.100.23', 6, distinct=6), bucket('192.0.2.1', 9, distinct=1)]))
    assert [(g['key'], g['value']) for g in cs] == [('198.51.100.23', 6)]
    hits = {'hits': {'total': {'value': 2}, 'hits': [
        {'_id': 'a', '_source': {'@timestamp': '2026-11-13T20:00:00Z', 'message': "GET /login?u=admin' OR '1'='1", 'source': {'ip': ATTACKER}}},
        {'_id': 'b', '_source': {'@timestamp': '2026-11-13T20:00:01Z', 'message': 'GET /index.html', 'source': {'ip': '192.0.2.4'}}}]}}
    sql = R.matches(rule('sql-injection'), hits)
    assert [(g['key'], g['count'], g['samples']) for g in sql] == [(ATTACKER, 1, ['a'])]
    silence = R.validate({**next(r for r in R.DEFAULT_RULES if r['id'] == 'auth-silence')})
    assert R.matches(silence, {'hits': {'total': {'value': 0}}}) and not R.matches(silence, {'hits': {'total': {'value': 3}}})
    spike = {**rule('error-spike'), 'group_by': ''}
    assert R.matches(spike, {'hits': {'total': {'value': 150}}, 'aggregations': {}})[0]['count'] == 150


# ------------------------------------------------------------------ engine: raise, silence, cooldown, respond, notify
def test_brute_force_raises_one_alert_blocks_the_ip_notifies_and_mirrors_to_es(engine, stores):
    stores.es.responses = [grouped([bucket(ATTACKER, 8)]), {'aggregations': {'h': {'buckets': [{'doc_count': n} for n in (0, 3, 5)]}}}]
    summary = engine.run_once()
    assert (summary['rules'], summary['created'], summary['errors']) == (1, 1, 0)
    alert = stores.db.alerts.find_one()
    assert alert['status'] == 'open' and alert['group'] == ATTACKER and alert['severity'] == 'high'
    assert alert['fingerprint'] == fingerprint('brute-force-ip', ATTACKER)
    assert [n['channel'] for n in alert['notifications']] == ['email', 'webhook']
    assert all(n['status'] == 'sent' for n in alert['notifications'])
    assert alert['response']['action'] == 'block_ip' and alert['response']['ip'] == ATTACKER
    assert 0 < stores.redis.ttl(PREFIX + ATTACKER) <= 15 * 60
    mail = FakeSMTP.sent[0]
    assert ATTACKER in mail['Subject'] and '[Haute]' in mail['Subject']
    attachment = next(mail.iter_attachments())
    assert attachment.get_filename() == 'evenements.png' and attachment.get_content()[:8] == b'\x89PNG\r\n\x1a\n'
    url, payload = engine.fake_http.posts[0]
    assert url == 'http://hooks.local/x' and payload['group'] == ATTACKER and payload['response']['action'] == 'block_ip'
    index, doc_id, doc = stores.es.indexed[0]
    assert index.startswith('sentinel-alerts-') and doc_id == alert['_id'] and doc['alert']['severity'] == 'high'
    actions = {a['action'] for a in stores.db.audit_actions.find()}
    assert {'alert_raised', 'ip_blocked'} <= actions


def test_same_attack_is_silenced_while_the_alert_is_open(engine, stores):
    stores.es.responses = [grouped([bucket(ATTACKER, 8)]), {}, grouped([bucket(ATTACKER, 12)])]
    engine.run_once()
    second = engine.run_once()
    assert (second['created'], second['updated']) == (0, 1)
    alert = stores.db.alerts.find_one()
    assert stores.db.alerts.count_documents({}) == 1 and alert['occurrences'] == 2 and alert['count'] == 12
    assert len(FakeSMTP.sent) == 1 and len(engine.fake_http.posts) == 1               # no second notification


def test_cooldown_prevents_a_new_alert_right_after_resolution(engine, stores):
    stores.es.responses = [grouped([bucket(ATTACKER, 8)]), {}, grouped([bucket(ATTACKER, 9)])]
    engine.run_once()
    alert_id = stores.db.alerts.find_one()['_id']
    engine.transition(alert_id, 'resolve', 'analyste', 'IP de scan')
    assert engine.run_once()['suppressed'] == 1 and stores.db.alerts.count_documents({}) == 1
    stores.redis.delete(COOLDOWN_PREFIX + fingerprint('brute-force-ip', ATTACKER))     # cooldown elapsed
    stores.es.responses = [grouped([bucket(ATTACKER, 9)]), {}]
    assert engine.run_once()['created'] == 1 and stores.db.alerts.count_documents({}) == 2


def test_protected_address_is_never_blocked_but_still_alerted(engine, stores):
    stores.es.responses = [grouped([bucket('127.0.0.1', 8)]), {}]
    engine.run_once()
    alert = stores.db.alerts.find_one()
    assert 'BLOCK_NEVER' in alert['response']['error'] and not stores.redis.exists(PREFIX + '127.0.0.1')


def test_one_failing_rule_does_not_stop_the_others(engine, stores, rule_store):
    rule_store.set_enabled('credential-stuffing', True, 'test')
    stores.es.down = True
    summary = engine.run_once()
    assert summary['errors'] == 2 and summary['rules'] == 2
    assert rule_store.get('brute-force-ip')['last_status'] == 'error'
    stores.es.down = False
    stores.es.responses = [grouped([]), grouped([])]
    assert engine.run_once()['errors'] == 0 and rule_store.get('brute-force-ip')['last_status'] == 'ok'


def test_acknowledge_resolve_lifecycle_and_mttr(engine, stores):
    stores.es.responses = [grouped([bucket(ATTACKER, 8)]), {}]
    clock = [datetime(2026, 11, 13, 20, 0, tzinfo=timezone.utc)]
    engine.now = lambda: clock[0]
    engine.run_once()
    aid = stores.db.alerts.find_one()['_id']
    assert engine.transition(aid, 'acknowledge', 'analyste')['status'] == 'acknowledged'
    clock[0] += timedelta(minutes=12)
    done = engine.transition(aid, 'resolve', 'analyste', 'bloquée, pas de compromission')
    assert done['status'] == 'resolved' and done['time_to_resolve_s'] == 720
    assert [h['status'] for h in done['history']] == ['open', 'acknowledged', 'resolved']
    with pytest.raises(Exception) as err:
        engine.transition(aid, 'acknowledge', 'analyste')
    assert getattr(err.value, 'status', None) == 409
    stats = engine.stats()
    assert stats['mttr_seconds'] == 720 and stats['top_rules'][0]['rule_id'] == 'brute-force-ip' and stats['open_total'] == 0


# ------------------------------------------------------------------ worker
def test_worker_cycle_takes_the_lock_writes_a_heartbeat_and_releases(stores, cfg, engine):
    stores.es.responses = [grouped([])]
    worker = Worker(stores, cfg, engine=engine)
    summary = worker.cycle()
    assert summary['rules'] == 1 and json.loads(stores.redis.get(HEARTBEAT_KEY))['rules'] == 1
    assert not stores.redis.exists(LOCK_KEY)
    stores.redis.set(LOCK_KEY, 'other-worker', ex=60)
    assert worker.cycle() is None                                  # another worker holds the lock: skip


def test_worker_loop_survives_an_exception(stores, cfg, engine):
    calls = []

    class Boom:
        def run_once(self):
            calls.append(1)
            raise RuntimeError('boom')
    worker = Worker(stores, cfg, engine=Boom(), sleep=lambda s: worker.stop() if len(calls) >= 2 else None)
    worker.run()
    assert len(calls) == 2 and not stores.redis.exists(LOCK_KEY)


# ------------------------------------------------------------------ notifications
def test_webhook_retries_with_backoff_then_records_success_or_failure(cfg):
    waits = []
    http = FakeHTTP(fail=2)
    result = Notifier(cfg, http=http, sleep=waits.append).webhook(sample_alert())
    assert result['status'] == 'sent' and result['attempts'] == 3 and waits == [1, 2]
    failed = Notifier(cfg, http=FakeHTTP(fail=-1), sleep=lambda s: None).webhook(sample_alert())
    assert failed['status'] == 'failed' and failed['attempts'] == 3 and 'ConnectionError' in failed['error']
    skipped = Notifier(Config(**{**cfg.__dict__, 'webhook_url': ''})).webhook(sample_alert())
    assert skipped['status'] == 'skipped'


def sample_alert(**over):
    a = {'_id': 'a1', 'rule_id': 'brute-force-ip', 'rule_name': 'Force brute', 'severity': 'critical', 'group_field': 'source.ip',
         'group': ATTACKER, 'count': 8, 'message': '8 événement(s)', 'triggered_at': '2026-11-13T20:00:00+00:00',
         'first_seen': '2026-11-13T19:59:00Z', 'last_seen': '2026-11-13T20:00:00Z', 'response': None}
    a.update(over)
    return a


def test_webhook_formats_slack_discord_teams_and_custom_template(cfg):
    a = sample_alert()
    assert 'blocks' in webhook_payload(cfg, a, 'slack') and webhook_payload(cfg, a, 'discord')['embeds'][0]['color'] == 0xD92D34
    assert webhook_payload(cfg, a, 'teams')['@type'] == 'MessageCard'
    generic = webhook_payload(cfg, a, 'generic')
    assert generic['link'].endswith('/alerts#alert-a1') and 'ip=203.0.113.77' in generic['search']
    custom = webhook_payload(cfg, sample_alert(message='quote " and \\ backslash'), 'generic',
                             template='{"text": "${severity} ${rule} ${message}", "n": "${count}"}')
    assert custom == {'text': 'critical Force brute quote " and \\ backslash', 'n': '8'}


def test_email_has_text_html_link_and_png_chart(cfg):
    png = png_bar_chart([1, 4, 2])
    width, height = struct.unpack('>II', png[16:24])
    assert png[:8] == b'\x89PNG\r\n\x1a\n' and (width, height) == (600, 180)
    msg = email_message(cfg, sample_alert(), png)
    html = msg.get_body(('html',)).get_content()
    assert 'Traiter l’alerte' in html and 'http://localhost:8000/alerts#alert-a1' in html and 'ip=203.0.113.77' in html
    assert msg['To'] == cfg.alert_email_to and next(msg.iter_attachments()).get_content_type() == 'image/png'


# ------------------------------------------------------------------ blocklist + enforcement
def test_blocklist_ttl_audit_history_and_protection(stores, cfg):
    bl = Blocklist(stores.redis, stores.db, cfg)
    rec = bl.block('203.0.113.9', 'admin', 'test', minutes=5)
    assert rec['minutes'] == 5 and 0 < stores.redis.ttl(PREFIX + '203.0.113.9') <= 300
    assert bl.active()[0]['ip'] == '203.0.113.9'
    with pytest.raises(BlockError):
        bl.block('::1', 'admin', 'x')
    with pytest.raises(BlockError):
        bl.block('not-an-ip', 'admin', 'x')
    assert bl.unblock('203.0.113.9', 'admin') and not bl.unblock('203.0.113.9', 'admin')
    assert [h['action'] for h in bl.history()] == ['unblock', 'block']
    assert {'ip_blocked', 'ip_unblocked'} <= {a['action'] for a in stores.db.audit_actions.find()}


def test_blocked_address_gets_403_everywhere_but_health(s4app, stores, cfg, users):
    Blocklist(stores.redis, stores.db, cfg).block(ATTACKER, 'alert-worker', 'règle brute-force-ip', rule='brute-force-ip')
    client = s4app.test_client()
    env = {'REMOTE_ADDR': ATTACKER}
    page = client.get('/login', environ_base=env)
    assert page.status_code == 403 and 'est bloquée jusqu’à' in page.get_data(as_text=True) and page.headers['Retry-After']
    api = client.post('/api/auth/login', json={'username': 'admin', 'password': 'x'}, environ_base=env)
    assert api.status_code == 403 and api.get_json()['error'] == 'ip_blocked'
    assert client.get('/health', environ_base=env).status_code == 200
    assert client.get('/login', environ_base={'REMOTE_ADDR': '192.0.2.1'}).status_code == 200


# ------------------------------------------------------------------ HTTP API + RBAC
def test_rbac_on_alert_actions_rules_and_blocklist(s4app, make_session, stores, cfg):
    R.RuleStore(stores.db).seed_defaults()
    admin, analyst, auditor = make_session('admin'), make_session('analyste'), make_session('auditeur')
    rule_body = {**next(r for r in R.DEFAULT_RULES if r['id'] == 'brute-force-ip'), 'id': 'ssh-root', 'name': 'Root SSH'}
    assert analyst.post('/api/alerts/rules', json=rule_body).status_code == 403
    assert admin.post('/api/alerts/rules', json=rule_body).status_code == 201
    assert admin.post('/api/alerts/rules', json=rule_body).status_code == 400                      # duplicate id
    assert admin.put('/api/alerts/rules/ssh-root', json={**rule_body, 'threshold': 3}).get_json()['threshold'] == 3
    assert admin.post('/api/alerts/rules/ssh-root/enabled', json={'enabled': False}).get_json()['enabled'] is False
    assert auditor.post('/api/blocklist', json={'ip': '203.0.113.5'}).status_code == 403
    assert admin.post('/api/blocklist', json={'ip': '203.0.113.5', 'minutes': 3, 'reason': 'scan'}).status_code == 201
    assert len(auditor.get('/api/blocklist').get_json()['active']) == 1                          # read-only view
    assert admin.delete('/api/blocklist/203.0.113.5').status_code == 200
    assert admin.delete('/api/alerts/rules/ssh-root').status_code == 200
    stores.db.alerts.insert_one({'_id': 'x1', 'fingerprint': 'f', 'rule_id': 'brute-force-ip', 'rule_name': 'BF', 'rule_type': 'threshold',
                                 'severity': 'high', 'status': 'open', 'group_field': 'source.ip', 'group': ATTACKER, 'count': 6,
                                 'triggered_at': datetime.now(timezone.utc), 'history': [], 'notifications': []})
    assert auditor.post('/api/alerts/x1/acknowledge').status_code == 403
    assert analyst.post('/api/alerts/x1/acknowledge').get_json()['status'] == 'acknowledged'
    assert analyst.post('/api/alerts/x1/resolve', json={'note': 'ok'}).get_json()['resolved_by'] == 'analyste'
    assert analyst.post('/api/alerts/x1/resolve').status_code == 409
    assert analyst.post('/api/alerts/x1/explode').status_code == 404
    summary = auditor.get('/api/alerts/summary').get_json()
    assert summary['open_total'] == 0 and 'worker' in summary


def test_rule_test_endpoint_runs_without_saving_and_shows_the_es_query(s4app, make_session, stores):
    analyst = make_session('analyste')
    stores.es.responses = [grouped([bucket(ATTACKER, 7)])]
    body = {'id': 'try-it', 'name': 'Essai', 'type': 'threshold', 'query': 'event.outcome:failure', 'window': '15m',
            'group_by': 'source.ip', 'threshold': 5, 'severity': 'low'}
    res = analyst.post('/api/alerts/rules/test', json=body).get_json()
    assert res['would_trigger'] == 1 and ATTACKER in res['descriptions'][0]
    assert res['es_query']['aggs']['groups']['terms']['min_doc_count'] == 5
    assert stores.db.alert_rules.count_documents({'_id': 'try-it'}) == 0 and stores.db.alerts.count_documents({}) == 0
    bad = analyst.post('/api/alerts/rules/test', json={**body, 'window': '3d'})
    assert bad.status_code == 400 and bad.get_json()['error'] == 'invalid_rule'


def test_run_now_is_admin_only_and_reports_the_cycle(s4app, make_session, stores):
    R.RuleStore(stores.db).seed_defaults()
    stores.es.response = grouped([])
    assert make_session('analyste').post('/api/alerts/run').status_code == 403
    summary = make_session('admin').post('/api/alerts/run').get_json()
    assert summary['rules'] == sum(1 for r in R.DEFAULT_RULES if r.get('enabled', True))


def test_demo_webhook_receiver_requires_the_token_and_keeps_the_last_payloads(s4app, make_session):
    client = s4app.test_client()
    assert client.post('/hooks/demo/wrong', json={'a': 1}).status_code == 404
    assert client.post('/hooks/demo/demo-token', json={'rule': 'x'}).status_code == 202      # CSRF-exempt, token-protected
    inbox = make_session('analyste').get('/api/notifications/demo').get_json()['webhooks']
    assert inbox[0]['payload'] == {'rule': 'x'}


def test_app_logins_are_shipped_to_logstash_without_the_password(s4app, make_session):
    session = make_session()
    session.login('admin', 'wrong password!')
    url, event = s4app.extensions['sentinel_http'].posts[-1]
    assert url == 'http://logstash:8088'
    assert (event['source_ip'], event['username'], event['outcome'], event['action']) == ('127.0.0.1', 'admin', 'failure', 'login')
    assert event['service'] == {'name': 'campusguard-web'} and 'wrong password' not in json.dumps(event)


def test_alert_pages_render_for_each_role(s4app, make_session, stores):
    R.RuleStore(stores.db).seed_defaults()
    admin_html = make_session('admin').get('/alerts/rules').get_data(as_text=True)
    assert 'Enregistrer' in admin_html and 'Force brute' in admin_html and 'role="switch"' in admin_html
    analyst_html = make_session('analyste').get('/alerts/rules').get_data(as_text=True)
    assert 'Tester sur les données actuelles' in analyst_html and '>Enregistrer<' not in analyst_html
    auditor = make_session('auditeur')
    page = auditor.get('/alerts').get_data(as_text=True)
    assert 'Alertes actives' in page and 'MTTR' in page and 'Bloquer manuellement' not in page
    assert 'Évaluer les règles maintenant' not in page
    assert 'id="nav-alert-badge"' in page
