"""Per-user dashboard customisation (« dashboards personnalisés »)."""
from app.services.prefs import WIDGETS


def test_defaults_show_every_widget(analyst):
    body = analyst.get('/api/dashboard/prefs').get_json()
    assert body['widgets'] == {w: True for w in WIDGETS} and body['period'] == '24h'


def test_hide_and_restore_a_widget_persists_in_mongodb(analyst, stores):
    res = analyst.client.put('/api/dashboard/prefs', json={'widgets': {'health': False}}, headers={'X-CSRF-Token': analyst.csrf})
    assert res.status_code == 200 and res.get_json()['widgets']['health'] is False
    assert stores.db.dashboard_prefs.find_one({'username': 'analyste'})['widgets']['health'] is False
    assert analyst.get('/api/dashboard/prefs').get_json()['widgets']['kpis'] is True
    html = analyst.get('/').get_data(as_text=True)
    assert '<h2>Santé de la plateforme</h2>' not in html and '<h2>IP à examiner en priorité</h2>' in html
    reset = analyst.delete('/api/dashboard/prefs')
    assert reset.get_json()['widgets']['health'] is True
    assert stores.db.dashboard_prefs.count_documents({'username': 'analyste'}) == 0


def test_preferences_are_per_user(make_session):
    a, b = make_session('analyste'), make_session('admin')
    a.client.put('/api/dashboard/prefs', json={'widgets': {'kpis': False}}, headers={'X-CSRF-Token': a.csrf})
    assert b.get('/api/dashboard/prefs').get_json()['widgets']['kpis'] is True


def test_invalid_preferences_are_rejected(analyst):
    h = {'X-CSRF-Token': analyst.csrf}
    for body in ({'widgets': {'nope': True}}, {'widgets': {'kpis': 'yes'}}, {'widgets': {}}, {}, {'period': '2y'}):
        res = analyst.client.put('/api/dashboard/prefs', json=body, headers=h)
        assert res.status_code == 400 and res.get_json()['error'] == 'invalid_parameters'


def test_put_requires_csrf_and_authentication(analyst, app):
    assert analyst.client.put('/api/dashboard/prefs', json={'widgets': {'kpis': False}}).status_code == 403
    assert app.test_client().get('/api/dashboard/prefs').status_code == 401


def test_auditor_can_customise_own_view(auditor):
    res = auditor.client.put('/api/dashboard/prefs', json={'widgets': {'searches': False}, 'period': '7d'}, headers={'X-CSRF-Token': auditor.csrf})
    assert res.status_code == 200
