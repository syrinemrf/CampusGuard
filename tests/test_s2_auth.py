"""Authentication, Redis sessions, CSRF, RBAC and login throttling."""
import re

import pytest

from conftest import PASSWORD
from app.services.users import UserStore


def csrf_from(html):
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_protected_pages_redirect_to_login(app):
    client = app.test_client()
    res = client.get('/search')
    assert res.status_code == 302 and '/login' in res.headers['Location']


def test_protected_api_returns_401_json(app):
    res = app.test_client().get('/api/search')
    assert res.status_code == 401 and res.get_json()['error'] == 'unauthenticated'


def test_html_login_flow_sets_redis_session_and_cookie_flags(app, users, stores):
    client = app.test_client()
    page = client.get('/login')
    assert page.status_code == 200 and b'Se connecter' in page.data
    token = csrf_from(page.get_data(as_text=True))
    res = client.post('/login', data={'username': 'Analyste', 'password': PASSWORD, 'csrf_token': token})
    assert res.status_code == 302 and res.headers['Location'].endswith('/')
    cookie = res.headers.get_all('Set-Cookie')[-1]
    assert 'sentinel_session=' in cookie and 'HttpOnly' in cookie and 'SameSite=Lax' in cookie
    sid = re.search(r'sentinel_session=([^;]+)', cookie).group(1)
    assert stores.redis.exists('sentinel:session:' + sid) == 1
    assert 0 < stores.redis.ttl('sentinel:session:' + sid) <= 7200
    assert client.get('/search').status_code == 200


def test_session_id_is_rotated_on_login(app, users, stores):
    client = app.test_client()
    page = client.get('/login')
    before = client.get_cookie('sentinel_session').value
    token = csrf_from(page.get_data(as_text=True))
    client.post('/login', data={'username': 'admin', 'password': PASSWORD, 'csrf_token': token})
    after = client.get_cookie('sentinel_session').value
    assert before != after
    assert stores.redis.exists('sentinel:session:' + before) == 0   # old id is destroyed (session fixation)
    assert stores.redis.exists('sentinel:session:' + after) == 1


def test_wrong_password_and_unknown_user_give_same_generic_error(app, users):
    client = app.test_client()
    token = csrf_from(client.get('/login').get_data(as_text=True))
    a = client.post('/login', data={'username': 'admin', 'password': 'wrong-password-xx', 'csrf_token': token})
    b = client.post('/login', data={'username': 'ghost', 'password': 'wrong-password-xx', 'csrf_token': token})
    assert a.status_code == b.status_code == 401
    assert b'Identifiants incorrects' in a.data and b'Identifiants incorrects' in b.data


def test_login_requires_csrf_token_on_form(app, users):
    res = app.test_client().post('/login', data={'username': 'admin', 'password': PASSWORD})
    assert res.status_code == 403


def test_open_redirect_is_blocked(app, users):
    client = app.test_client()
    token = csrf_from(client.get('/login?next=//evil.example').get_data(as_text=True))
    res = client.post('/login?next=//evil.example', data={'username': 'admin', 'password': PASSWORD, 'csrf_token': token})
    assert res.status_code == 302 and 'evil.example' not in res.headers['Location']


def test_json_login_returns_role_and_csrf(app, users):
    res = app.test_client().post('/api/auth/login', json={'username': 'auditeur', 'password': PASSWORD})
    body = res.get_json()
    assert res.status_code == 200 and body['role'] == 'auditor' and body['csrf_token']


def test_unsafe_api_call_without_csrf_header_is_refused(make_session):
    s = make_session('analyste')
    res = s.client.post('/api/uploads')           # no X-CSRF-Token
    assert res.status_code == 403 and res.get_json()['error'] == 'csrf'


def test_logout_destroys_session(app, users, stores):
    client = app.test_client()
    token = csrf_from(client.get('/login').get_data(as_text=True))
    client.post('/login', data={'username': 'admin', 'password': PASSWORD, 'csrf_token': token})
    sid = client.get_cookie('sentinel_session').value
    page = client.get('/search').get_data(as_text=True)
    csrf = re.search(r'name="csrf-token" content="([^"]+)"', page).group(1)
    res = client.post('/logout', data={'csrf_token': csrf})
    assert res.status_code == 302
    assert stores.redis.exists('sentinel:session:' + sid) == 0
    assert client.get('/search').status_code == 302


def test_login_throttling_blocks_after_five_failures_then_429(app, users, stores):
    client = app.test_client()
    for _ in range(5):
        assert client.post('/api/auth/login', json={'username': 'admin', 'password': 'nope-nope-nope'}).status_code == 401
    res = client.post('/api/auth/login', json={'username': 'admin', 'password': PASSWORD})   # correct password, still blocked
    assert res.status_code == 429 and int(res.headers['Retry-After']) > 0
    assert 0 < stores.redis.ttl('sentinel:login:fail:user:admin') <= 300


def test_failed_logins_are_audited_without_the_password(app, users, stores):
    app.test_client().post('/api/auth/login', json={'username': 'admin', 'password': 'super-secret-guess'})
    entry = stores.db.audit_actions.find_one({'action': 'login_failure'})
    assert entry['actor'] == 'admin' and 'super-secret-guess' not in str(entry)


def test_successful_login_audited(app, users, stores):
    app.test_client().post('/api/auth/login', json={'username': 'admin', 'password': PASSWORD})
    assert stores.db.audit_actions.count_documents({'action': 'login_success', 'actor': 'admin'}) == 1


def test_auditor_cannot_upload_but_can_search(auditor, stores):
    assert auditor.post('/api/uploads', data={}).status_code == 403
    assert auditor.get('/api/search').status_code == 200


def test_sessions_do_not_leak_between_clients(make_session):
    a, b = make_session('analyste'), make_session()
    assert b.get('/api/auth/me').status_code == 401
    assert a.get('/api/auth/me').get_json()['username'] == 'analyste'


def test_security_headers_present(app):
    res = app.test_client().get('/login')
    assert res.headers['X-Content-Type-Options'] == 'nosniff' and res.headers['X-Frame-Options'] == 'DENY'
    assert "script-src 'self'" in res.headers['Content-Security-Policy']


def test_password_hashes_are_not_plaintext_and_policy_enforced(stores):
    store = UserStore(stores.db)
    store.create('nouveau', 'un-mot-de-passe-long', 'analyst')
    assert 'un-mot-de-passe-long' not in stores.db.users.find_one({'username': 'nouveau'})['password_hash']
    with pytest.raises(ValueError):
        store.create('court', 'abc', 'analyst')
    with pytest.raises(ValueError):
        store.create('nouveau', 'un-mot-de-passe-long', 'analyst')     # duplicate
    with pytest.raises(ValueError):
        store.create('x', 'un-mot-de-passe-long', 'root')               # unknown role


def test_inactive_account_cannot_login(app, users, stores):
    stores.db.users.update_one({'username': 'admin'}, {'$set': {'active': False}})
    assert app.test_client().post('/api/auth/login', json={'username': 'admin', 'password': PASSWORD}).status_code == 401


def test_seed_users_generates_passwords_once(stores):
    store = UserStore(stores.db)
    specs = [('admin', 'admin', 'SEED_ADMIN_PASSWORD'), ('analyste', 'analyst', 'SEED_ANALYST_PASSWORD')]
    created = store.seed(specs, {'SEED_ADMIN_PASSWORD': 'mot-de-passe-fourni-1'})
    by_name = {c[0]: c for c in created}
    assert by_name['admin'][2] is None                       # provided via env: never echoed
    assert len(by_name['analyste'][2]) >= 12                 # generated: shown once
    assert store.seed(specs, {}) == []                       # idempotent
    assert store.authenticate('admin', 'mot-de-passe-fourni-1')


def test_cli_set_password_replaces_a_lost_password_and_is_audited(app, users, stores):
    from conftest import Session
    runner = app.test_cli_runner()
    res = runner.invoke(args=['set-password', 'analyste'], input='brand new password\nbrand new password\n')
    assert res.exit_code == 0 and 'modifié' in res.output
    assert Session(app).login('analyste', 'brand new password').status_code == 200
    assert stores.db.audit_actions.find_one({'action': 'password_reset', 'target': 'analyste'})
    assert runner.invoke(args=['set-password', 'nobody'], input='brand new password\nbrand new password\n').exit_code != 0
    assert runner.invoke(args=['set-password', 'analyste'], input='short\nshort\n').exit_code != 0
