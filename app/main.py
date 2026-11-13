"""CampusGuard / Sentinel web application (S2: authentication, upload, ingestion status, search)."""
import logging
import os
import time
from contextlib import closing
from datetime import datetime, timezone
from urllib.parse import urlencode

import click
import requests
from flask import Flask, jsonify, request
from flask_login import LoginManager
from pymongo import MongoClient
from redis import Redis

from app.config import Config
from app.kibana import origin as kibana_origin
from app.security import (ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR, ROLE_LABELS, RedisSessionInterface, check_csrf,
                          csrf_token, error_response, unauthorized)
from app.stores import build_stores, ensure_indexes

log = logging.getLogger('sentinel')

SEED_ACCOUNTS = [
    ('admin', ROLE_ADMIN, 'SEED_ADMIN_PASSWORD'),
    ('analyste', ROLE_ANALYST, 'SEED_ANALYST_PASSWORD'),
    ('auditeur', ROLE_AUDITOR, 'SEED_AUDITOR_PASSWORD'),
]


def create_app(config=None, stores=None):
    """Application factory. ``stores`` lets tests inject fakes (Mongo / Redis / Elasticsearch)."""
    config = config or Config()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key,
        SESSION_COOKIE_NAME='sentinel_session',
        SESSION_COOKIE_SECURE=config.session_cookie_secure,
        MAX_CONTENT_LENGTH=(config.max_upload_mb + 1) * 1024 * 1024,
        JSON_AS_ASCII=False,
        TESTING=config.testing,
    )
    app.extensions['sentinel_config'] = config
    app.extensions['sentinel_stores'] = stores or build_stores(config)
    app.extensions['sentinel_indexes_ready'] = bool(stores)  # injected fakes manage their own schema
    st = app.extensions['sentinel_stores']
    app.session_interface = RedisSessionInterface(lambda: app.extensions['sentinel_stores'].redis, config.session_ttl)

    from app.services.users import UserStore

    login_manager = LoginManager()
    login_manager.session_protection = 'basic'
    login_manager.user_loader(lambda uid: UserStore(app.extensions['sentinel_stores'].db).get(uid))
    login_manager.unauthorized_handler(unauthorized)
    login_manager.init_app(app)

    from app.views_auth import bp as auth_bp
    from app.views_api import bp as api_bp, v1 as v1_bp
    from app.views_web import bp as web_bp
    from app.views_alerts import bp as alerts_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(v1_bp)
    app.register_blueprint(web_bp)

    app.jinja_env.globals.update(csrf_token=csrf_token, ROLE_LABELS=ROLE_LABELS, spark=sparkline_points)
    app.jinja_env.filters['urlencode_filters'] = lambda f: urlencode(
        [(k, ','.join(v) if isinstance(v, list) else v) for k, v in f.items()])

    @app.before_request
    def _prepare():
        if request.endpoint in {'health', 'ready', 'static'}:
            return None
        blocked = blocked_response(app, config)
        if blocked:
            return blocked
        if not app.extensions['sentinel_indexes_ready']:
            try:
                ensure_indexes(app.extensions['sentinel_stores'].db)
                app.extensions['sentinel_indexes_ready'] = True
            except Exception:  # noqa: BLE001 - MongoDB not reachable yet; retried on the next request
                log.warning('MongoDB indexes not created yet (MongoDB unavailable)')
        limited = rate_limit(app, config)
        return limited or check_csrf()

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        response.headers.setdefault(
            'Content-Security-Policy',
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            f"frame-src {kibana_origin(config.kibana_public_url)}; frame-ancestors 'none'")
        if request.path.startswith('/api/'):
            response.headers.setdefault('Cache-Control', 'no-store')
        return response

    @app.errorhandler(404)
    def _not_found(_):
        return error_response(404, 'not_found', 'Ressource introuvable.')

    @app.errorhandler(405)
    def _method_not_allowed(_):
        return error_response(405, 'method_not_allowed', 'Méthode non autorisée.')

    @app.errorhandler(413)
    def _too_large(_):
        return error_response(413, 'too_large', f'Fichier trop volumineux (maximum {config.max_upload_mb} Mo).')

    @app.errorhandler(500)
    def _server_error(exc):
        log.exception('unhandled error: %s', exc)
        return error_response(500, 'server_error', 'Erreur interne. Consultez les journaux du service.')

    register_health(app)
    register_cli(app)
    return app


def sparkline_points(values, width=120, height=34, pad=3):
    """SVG polyline points for a small trend line (rendered server-side: no inline script, CSP-safe)."""
    values = list(values or [])
    if len(values) < 2:
        return ''
    top = max(values) or 1
    step = (width - 2 * pad) / (len(values) - 1)
    return ' '.join(f'{pad + i * step:.1f},{height - pad - (v / top) * (height - 2 * pad):.1f}' for i, v in enumerate(values))


def blocked_response(app, config):
    """SOAR-lite enforcement: an address in the Redis blocklist gets 403 everywhere (fails open if Redis is down)."""
    from app.alerting.blocklist import Blocklist
    ip = request.remote_addr or ''
    try:
        record = Blocklist(app.extensions['sentinel_stores'].redis, app.extensions['sentinel_stores'].db, config).get(ip)
    except Exception:  # noqa: BLE001 - never lock everybody out because Redis is unavailable
        log.warning('blocklist check skipped (Redis unavailable)')
        return None
    if not record:
        return None
    until = record['until'][:16].replace('T', ' ')
    from flask import make_response
    body, status = error_response(
        403, 'ip_blocked', f"Votre adresse IP {ip} est bloquée jusqu’à {until} UTC ({record['reason']}). "
                           "Ce blocage est temporaire ; un administrateur peut le lever.",
        until=record['until'], rule=record.get('rule'))
    response = make_response(body, status)
    response.headers['Retry-After'] = str(record['remaining_seconds'])
    return response, status


def rate_limit(app, config):
    """Per-user (or per-IP) fixed-window limit on /api/* in Redis: ``sentinel:ratelimit:{who}:{minute}``."""
    if not request.path.startswith('/api/') or request.endpoint == 'auth.api_login' or config.api_rate_limit <= 0:
        return None
    from flask_login import current_user
    who = f'user:{current_user.id}' if current_user.is_authenticated else f'ip:{request.remote_addr}'
    redis = app.extensions['sentinel_stores'].redis
    window = int(time.time() // 60)
    key = f'sentinel:ratelimit:{who}:{window}'
    count = redis.incr(key)
    if count == 1:
        redis.expire(key, 70)
    if count > config.api_rate_limit:
        retry = 60 - int(time.time() % 60)
        response, status = error_response(429, 'rate_limited', 'Trop de requêtes : réessayez dans quelques secondes.', retry_after=retry)
        response.headers['Retry-After'] = str(retry)
        return response, status
    return None


def register_health(app):
    @app.get('/health')
    def health():
        return jsonify(status='ok', timestamp=datetime.now(timezone.utc).isoformat())

    @app.get('/ready')
    def ready():
        status = {}
        try:
            elasticsearch_url = os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200').rstrip('/')
            response = requests.get(
                f'{elasticsearch_url}/_cluster/health',
                params={'wait_for_status': 'yellow', 'timeout': '2s', 'master_timeout': '2s'},
                timeout=3,
            )
            response.raise_for_status()
            cluster_health = response.json()
            if not isinstance(cluster_health, dict):
                raise ValueError('Invalid Elasticsearch cluster health response')
            if cluster_health.get('status') not in {'yellow', 'green'} or cluster_health.get('timed_out') is not False:
                raise ValueError('Elasticsearch cluster is not ready')
            status['elasticsearch'] = 'ok'
        except (requests.RequestException, ValueError):
            status['elasticsearch'] = 'error'
        try:
            with closing(MongoClient(os.getenv('MONGO_URI', 'mongodb://mongodb:27017/'),
                                     serverSelectionTimeoutMS=3000)) as client:
                client.admin.command('ping')
            status['mongodb'] = 'ok'
        except Exception:  # noqa: BLE001
            status['mongodb'] = 'error'
        try:
            with closing(Redis.from_url(os.getenv('REDIS_URL', 'redis://redis:6379/0'), socket_timeout=3)) as client:
                client.ping()
            status['redis'] = 'ok'
        except Exception:  # noqa: BLE001
            status['redis'] = 'error'
        healthy = all(v == 'ok' for v in status.values())
        return jsonify(status='ready' if healthy else 'degraded', services=status), (200 if healthy else 503)


def register_cli(app):
    from app.services.users import UserStore

    @app.cli.command('init-db')
    def init_db():
        """Create MongoDB indexes."""
        ensure_indexes(app.extensions['sentinel_stores'].db)
        click.echo('Index MongoDB créés.')

    @app.cli.command('seed-users')
    def seed_users():
        """Create the default admin / analyste / auditeur accounts if they do not exist.

        Passwords come from SEED_ADMIN_PASSWORD, SEED_ANALYST_PASSWORD, SEED_AUDITOR_PASSWORD
        (12 characters minimum). Otherwise a random one is generated and shown ONCE."""
        db = app.extensions['sentinel_stores'].db
        ensure_indexes(db)
        created = UserStore(db).seed(SEED_ACCOUNTS, os.environ)
        if not created:
            click.echo('Aucun compte créé : les comptes par défaut existent déjà.')
        for username, role, password in created:
            shown = password if password else '(défini via la variable d’environnement)'
            click.echo(f'Compte créé : {username} [{role}] mot de passe : {shown}')

    @app.cli.command('seed-rules')
    def seed_rules():
        """Create the default scenario-C alert rules that do not exist yet."""
        from app.alerting.rules import RuleStore
        db = app.extensions['sentinel_stores'].db
        ensure_indexes(db)
        created = RuleStore(db).seed_defaults()
        click.echo('Règles créées : ' + (', '.join(created) if created else 'aucune (déjà présentes)'))

    @app.cli.command('unblock-ip')
    @click.argument('ip')
    def unblock_ip(ip):
        """Lift a block immediately (recovery if your own address was blocked during a demo)."""
        from app.alerting.blocklist import Blocklist
        stores = app.extensions['sentinel_stores']
        done = Blocklist(stores.redis, stores.db, app.extensions['sentinel_config']).unblock(ip, 'cli')
        click.echo(f'{ip} débloquée.' if done else f'{ip} n’était pas bloquée.')

    @app.cli.command('create-user')
    @click.argument('username')
    @click.argument('role', type=click.Choice([ROLE_ADMIN, ROLE_ANALYST, ROLE_AUDITOR]))
    @click.password_option()
    def create_user(username, role, password):
        """Create one account (interactive password prompt)."""
        db = app.extensions['sentinel_stores'].db
        ensure_indexes(db)
        try:
            UserStore(db).create(username, password, role)
        except ValueError as exc:
            raise click.ClickException(str(exc))
        click.echo(f'Compte créé : {username} [{role}]')


app = create_app()
