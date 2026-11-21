"""Server-side sessions in Redis, CSRF protection, RBAC and login throttling."""
import hmac
import json
import re
import secrets
from functools import wraps

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for
from flask.sessions import SessionInterface, SessionMixin
from flask_login import current_user
from werkzeug.datastructures import CallbackDict

SESSION_PREFIX = 'sentinel:session:'
_SID_RE = re.compile(r'^[A-Za-z0-9_-]{43}$')
ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR = 'admin', 'analyst', 'auditor'
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR)
ROLE_LABELS = {ROLE_ADMIN: 'Administrateur', ROLE_ANALYST: 'Analyste SOC', ROLE_AUDITOR: 'Auditeur'}
CSRF_EXEMPT_ENDPOINTS = {'auth.api_login', 'alerts.demo_webhook'}  # demo webhook: token in the URL, no cookie


class RedisSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        def on_update(self_):
            self_.modified = True
        super().__init__(initial, on_update)
        self.sid = sid
        self.new = new
        self.modified = False
        self.rotate = False


class RedisSessionInterface(SessionInterface):
    """Cookie holds only an opaque id; the data lives in ``sentinel:session:{id}`` with a TTL."""

    def __init__(self, redis_getter, ttl):
        self._redis = redis_getter
        self.ttl = ttl

    @staticmethod
    def _new_sid():
        return secrets.token_urlsafe(32)

    def open_session(self, app, request_):
        sid = request_.cookies.get(self.get_cookie_name(app))
        if sid and _SID_RE.match(sid):
            raw = self._redis().get(SESSION_PREFIX + sid)
            if raw:
                try:
                    return RedisSession(json.loads(raw), sid=sid)
                except ValueError:
                    pass
        return RedisSession(sid=self._new_sid(), new=True)

    def save_session(self, app, session_, response):
        name = self.get_cookie_name(app)
        redis = self._redis()
        if not session_:
            if session_.modified and not session_.new:
                redis.delete(SESSION_PREFIX + session_.sid)
                response.delete_cookie(name, path=self.get_cookie_path(app))
            return
        if session_.rotate:
            if not session_.new:
                redis.delete(SESSION_PREFIX + session_.sid)
            session_.sid = self._new_sid()
        redis.setex(SESSION_PREFIX + session_.sid, self.ttl, json.dumps(dict(session_)))
        response.set_cookie(
            name, session_.sid, httponly=True, secure=app.config['SESSION_COOKIE_SECURE'],
            samesite='Lax', path=self.get_cookie_path(app))
        response.vary.add('Cookie')


# ------------------------------------------------------------------ CSRF

def csrf_token():
    token = session.get('csrf')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf'] = token
    return token


def check_csrf():
    """before_request hook: unsafe methods need the session token (header or form field)."""
    if request.method in {'GET', 'HEAD', 'OPTIONS'} or request.endpoint in CSRF_EXEMPT_ENDPOINTS:
        return None
    expected = session.get('csrf')
    supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        return error_response(403, 'csrf', 'Jeton CSRF manquant ou invalide : rechargez la page.')
    return None


# ------------------------------------------------------------------ errors / RBAC

def wants_json():
    return request.path.startswith('/api/')


def error_response(status, code, message, **extra):
    if wants_json():
        payload = {'error': code, 'message': message}
        payload.update(extra)
        return jsonify(payload), status
    from flask import render_template
    return render_template('error.html', status=status, message=message), status


def unauthorized():
    if wants_json():
        return error_response(401, 'unauthenticated', 'Authentification requise.')
    return redirect(url_for('auth.login', next=request.full_path.rstrip('?')))


def roles_required(*roles):
    """Authenticated + one of ``roles`` (all roles when none given)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return unauthorized()
            if roles and current_user.role not in roles:
                return error_response(403, 'forbidden', 'Votre rôle ne permet pas cette action.')
            return view(*args, **kwargs)
        return wrapped
    return decorator


# ------------------------------------------------------------------ login throttling

class LoginThrottle:
    """Fixed-window counters in Redis: ``sentinel:login:fail:{ip|user}:{value}``."""

    def __init__(self, redis, max_failures, window):
        self.redis = redis
        self.max = max_failures
        self.window = window

    @staticmethod
    def _keys(ip, username):
        keys = [f'sentinel:login:fail:ip:{ip}']
        if username:
            keys.append(f'sentinel:login:fail:user:{username.lower()[:64]}')
        return keys

    def retry_after(self, ip, username):
        """Seconds to wait if blocked, else 0."""
        wait = 0
        for key in self._keys(ip, username):
            count = self.redis.get(key)
            if count and int(count) >= self.max:
                wait = max(wait, self.redis.ttl(key) or self.window)
        return wait

    def failure(self, ip, username):
        for key in self._keys(ip, username):
            if self.redis.incr(key) == 1:
                self.redis.expire(key, self.window)

    def success(self, ip, username):
        # Only the per-user counter is reset: a valid login must not erase an IP's failed attempts
        # made against other accounts.
        if username:
            self.redis.delete(self._keys(ip, username)[1])
