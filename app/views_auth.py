"""Authentication: HTML login form, JSON login, logout, current user."""
from urllib.parse import urlparse

from flask import Blueprint, current_app, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user

from app.security import LoginThrottle, ROLE_LABELS, csrf_token, error_response, roles_required
from app.services.auth_events import build_event, ship
from app.services.users import UserStore, record_audit

bp = Blueprint('auth', __name__)


def _ctx():
    app = current_app
    stores = app.extensions['sentinel_stores']
    cfg = app.extensions['sentinel_config']
    return stores, cfg, UserStore(stores.db), LoginThrottle(stores.redis, cfg.login_max_failures, cfg.login_window_seconds)


def _safe_next(target):
    """Only same-site relative paths are accepted as post-login redirects."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith('/') or target.startswith('//'):
        return None
    return target


def _attempt(username, password):
    """Shared login logic. Returns (user | None, error_code | None, retry_after)."""
    stores, _cfg, users, throttle = _ctx()
    ip = request.remote_addr or 'unknown'
    username = (username or '').strip().lower()[:64]
    wait = throttle.retry_after(ip, username)
    if wait:
        record_audit(stores.db, username or None, 'login_blocked', ip=ip, reason='trop de tentatives')
        ship(current_app, build_event('login_blocked', 'failure', ip, username, 'trop de tentatives'))
        return None, 'too_many_attempts', wait
    user = users.authenticate(username, password)
    if user is None:
        throttle.failure(ip, username)
        record_audit(stores.db, username or None, 'login_failure', ip=ip)  # never the attempted password (BR06)
        ship(current_app, build_event('login', 'failure', ip, username))
        return None, 'invalid_credentials', 0
    throttle.success(ip, username)
    session.clear()
    session.rotate = True  # new session id after authentication (anti session fixation)
    login_user(user)
    csrf_token()
    record_audit(stores.db, user.username, 'login_success', ip=ip)
    ship(current_app, build_event('login', 'success', ip, user.username))
    return user, None, 0


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('web.home'))
    error = None
    if request.method == 'POST':
        user, code, wait = _attempt(request.form.get('username'), request.form.get('password'))
        if user:
            return redirect(_safe_next(request.args.get('next')) or url_for('web.home'))
        error = ('Trop de tentatives échouées. Réessayez dans %d min.' % max(1, -(-wait // 60))
                 if code == 'too_many_attempts' else 'Identifiants incorrects.')
        status = 429 if code == 'too_many_attempts' else 401
        response = current_app.make_response((render_template('login.html', error=error, next=request.args.get('next', '')), status))
        if wait:
            response.headers['Retry-After'] = str(wait)
        return response
    return render_template('login.html', error=None, next=request.args.get('next', ''))


@bp.post('/logout')
def logout():
    stores = current_app.extensions['sentinel_stores']
    if current_user.is_authenticated:
        record_audit(stores.db, current_user.username, 'logout', ip=request.remote_addr)
    logout_user()
    session.clear()
    session.rotate = True  # the old session id is destroyed in Redis; the flash message lives in a fresh one
    flash('Vous êtes déconnecté(e). À bientôt !', 'ok')
    return redirect(url_for('auth.login'))


@bp.post('/api/auth/login')
def api_login():
    """JSON login (CSRF-exempt: no cookie is trusted before authentication). Returns the CSRF token."""
    data = request.get_json(silent=True) or {}
    user, code, wait = _attempt(data.get('username'), data.get('password'))
    if user:
        return jsonify(username=user.username, role=user.role, role_label=ROLE_LABELS[user.role], csrf_token=csrf_token())
    if code == 'too_many_attempts':
        response, status = error_response(429, code, 'Trop de tentatives échouées.', retry_after=wait)
        response.headers['Retry-After'] = str(wait)
        return response, status
    return error_response(401, code, 'Identifiants incorrects.')


@bp.get('/api/auth/me')
@roles_required()
def api_me():
    return jsonify(username=current_user.username, role=current_user.role, role_label=ROLE_LABELS[current_user.role],
                   csrf_token=csrf_token())
