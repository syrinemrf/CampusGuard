"""S5, module G complété : escalade N2/N3, mise en veille (snooze), commentaires d'incident."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import live
from app.alerting import rules as R
from app.alerting.engine import AlertEngine, AlertError
from test_s4_alerting import ATTACKER, FakeHTTP, FakeSMTP, bucket, cfg, grouped, rule_store, s4app  # noqa: F401


class Clock:
    def __init__(self):
        self.t = datetime(2026, 11, 20, 20, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, minutes):
        self.t += timedelta(minutes=minutes)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def eng(stores, cfg, rule_store, clock):
    FakeSMTP.sent = []
    e = AlertEngine(stores, cfg, http=FakeHTTP(), smtp_factory=FakeSMTP, sleep=lambda s: None, now=clock)
    return e


def raise_alert(eng, stores):
    stores.es.responses = [grouped([bucket(ATTACKER, 7)])]
    eng.run_once()
    return stores.db.alerts.find_one({'group': ATTACKER})


def test_unacknowledged_alert_escalates_to_level_2_then_3_with_severity_and_recipients(eng, stores, clock, cfg):
    alert = raise_alert(eng, stores)
    assert alert['severity'] == 'high' and alert['escalation_level'] == 1
    FakeSMTP.sent = []
    clock.advance(14)
    assert eng.escalate() == 0
    clock.advance(1)
    assert eng.escalate() == 1
    a = stores.db.alerts.find_one({'_id': alert['_id']})
    assert a['escalation_level'] == 2 and a['severity'] == 'critical'
    assert FakeSMTP.sent[-1]['To'] == cfg.alert_email_to_l2 and FakeSMTP.sent[-1]['Subject'].startswith('[ESCALADE N2]')
    assert a['notifications'][-1]['escalation'] == 2 and a['history'][-1]['status'] == 'escalated'
    assert eng.escalate() == 0                                  # pas deux fois le même niveau
    clock.advance(45)
    assert eng.escalate() == 1
    a = stores.db.alerts.find_one({'_id': alert['_id']})
    assert a['escalation_level'] == 3 and a['severity'] == 'critical'            # déjà au maximum
    assert FakeSMTP.sent[-1]['To'] == cfg.alert_email_to_l3
    assert [e['level'] for e in a['escalations']] == [2, 3]


def test_acknowledging_stops_escalation(eng, stores, clock):
    alert = raise_alert(eng, stores)
    eng.transition(alert['_id'], 'acknowledge', 'analyste')
    clock.advance(120)
    assert eng.escalate() == 0


def test_escalation_jumps_directly_to_level_3_after_one_hour(eng, stores, clock):
    alert = raise_alert(eng, stores)
    clock.advance(61)
    eng.escalate()
    a = stores.db.alerts.find_one({'_id': alert['_id']})
    assert a['escalation_level'] == 3 and len(a['escalations']) == 1


def test_snooze_keeps_deduplication_then_the_alert_comes_back_alone(eng, stores, clock):
    alert = raise_alert(eng, stores)
    eng.snooze(alert['_id'], 'analyste', 60)
    a = stores.db.alerts.find_one({'_id': alert['_id']})
    assert a['status'] == 'snoozed' and a['status_before_snooze'] == 'open'
    stores.es.responses = [grouped([bucket(ATTACKER, 9)])]
    clock.advance(10)
    summary = eng.run_once()
    assert summary['created'] == 0 and summary['updated'] == 1           # toujours une seule alerte
    clock.advance(100)
    assert eng.escalate() == 0                                           # en veille : pas d'escalade
    stores.es.responses = [grouped([])]
    clock.advance(1)
    summary = eng.run_once()
    a = stores.db.alerts.find_one({'_id': alert['_id']})
    assert summary['woken'] == 1 and a['status'] == 'open' and 'snoozed_until' not in a
    assert '1 nouvelle(s) occurrence(s)' in a['history'][-1]['note']
    clock.advance(14)
    assert eng.escalate() == 0                                           # le délai repart du réveil
    clock.advance(2)
    assert eng.escalate() == 1


def test_snooze_rejects_unknown_durations_and_resolved_alerts(eng, stores):
    alert = raise_alert(eng, stores)
    with pytest.raises(AlertError):
        eng.snooze(alert['_id'], 'analyste', 7)
    eng.transition(alert['_id'], 'resolve', 'analyste', 'ok')
    with pytest.raises(AlertError) as exc:
        eng.snooze(alert['_id'], 'analyste', 15)
    assert exc.value.status == 409


def test_snoozed_alert_can_be_acknowledged_or_resolved(eng, stores):
    alert = raise_alert(eng, stores)
    eng.snooze(alert['_id'], 'analyste', 15)
    assert eng.transition(alert['_id'], 'acknowledge', 'analyste')['status'] == 'acknowledged'


def test_comments_are_kept_audited_and_validated(eng, stores):
    alert = raise_alert(eng, stores)
    out = eng.comment(alert['_id'], 'analyste', '  IP déjà vue hier, scan Shodan.  ')
    assert out['comments'][0]['text'] == 'IP déjà vue hier, scan Shodan.' and out['comments'][0]['by'] == 'analyste'
    assert stores.db.audit_actions.find_one({'action': 'alert_commented', 'target': alert['_id']})
    with pytest.raises(AlertError):
        eng.comment(alert['_id'], 'analyste', '   ')
    with pytest.raises(AlertError):
        eng.comment(alert['_id'], 'analyste', 'x' * 1001)


def test_escalation_is_pushed_to_live_screens(eng, stores, clock):
    p = stores.redis.pubsub(ignore_subscribe_messages=True)
    p.subscribe(live.ALERTS_CHANNEL)
    raise_alert(eng, stores)
    clock.advance(16)
    eng.escalate()
    events = []
    for _ in range(10):
        m = p.get_message(timeout=0.05)
        if m:
            events.append(json.loads(m['data']))
    assert [e.get('escalation_level') for e in events] == [1, 2]


def test_api_snooze_and_comment(analyst, auditor, stores, s4app, rule_store):
    eng = AlertEngine(stores, s4app.extensions['sentinel_config'], http=FakeHTTP(), smtp_factory=FakeSMTP, sleep=lambda s: None)
    alert = raise_alert(eng, stores)
    url = f"/api/alerts/{alert['_id']}"
    r = analyst.client.post(url + '/snooze', json={'minutes': 15}, headers={'X-CSRF-Token': analyst.csrf})
    assert r.status_code == 200 and r.get_json()['status'] == 'snoozed'
    r = analyst.client.post(url + '/comments', json={'text': 'en attente du réseau'}, headers={'X-CSRF-Token': analyst.csrf})
    assert r.status_code == 201 and r.get_json()['comments'][0]['text'] == 'en attente du réseau'
    assert auditor.client.post(url + '/comments', json={'text': 'x'}, headers={'X-CSRF-Token': auditor.csrf}).status_code == 403
    html = analyst.get('/alerts').get_data(as_text=True)
    assert 'En veille' in html and 'en attente du réseau' in html and 'escaladée N' not in html
