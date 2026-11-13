"""S4 — alerting: alert pages, incident actions, rule editor + test, IP blocklist, demo webhook receiver."""
import hmac
import json
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify, render_template, request
from flask_login import current_user

from app.alerting import rules as R
from app.alerting.blocklist import BlockError
from app.alerting.engine import AlertEngine, AlertError
from app.alerting.worker import Worker
from app.security import ROLE_ADMIN, ROLE_ANALYST, error_response, roles_required
from app.services.users import record_audit

bp = Blueprint('alerts', __name__)
DEMO_INBOX = 'sentinel:webhook:demo'


def _engine():
    return AlertEngine(current_app.extensions['sentinel_stores'], current_app.extensions['sentinel_config'],
                       http=current_app.extensions.get('sentinel_http'),
                       smtp_factory=current_app.extensions.get('sentinel_smtp'),
                       sleep=current_app.extensions.get('sentinel_sleep'))


@bp.app_errorhandler(AlertError)
def _alert_error(exc):
    return error_response(exc.status, 'alert_error', str(exc))


@bp.app_errorhandler(R.RuleError)
def _rule_error(exc):
    return error_response(400, 'invalid_rule', 'Règle invalide.', details=exc.errors)


@bp.app_errorhandler(BlockError)
def _block_error(exc):
    return error_response(400, 'invalid_block', str(exc))


# ------------------------------------------------------------------ pages
@bp.get('/alerts')
@roles_required()
def alerts_page():
    engine = _engine()
    return render_template('alerts.html', page='alerts', stats=engine.stats(), active=engine.list('active', limit=100),
                           history=engine.list('resolved', limit=30), blocked=engine.blocklist.active(),
                           block_history=engine.blocklist.history(10), heartbeat=engine.heartbeat(),
                           can_act=current_user.role in (ROLE_ADMIN, ROLE_ANALYST), is_admin=current_user.role == ROLE_ADMIN,
                           severities=R.SEVERITY_LABELS, block_ttl=current_app.extensions['sentinel_config'].block_ttl_minutes)


@bp.get('/alerts/rules')
@roles_required()
def rules_page():
    cfg = current_app.extensions['sentinel_config']
    engine = _engine()
    return render_template('rules.html', page='rules', rules=[R.public(r) for r in engine.rules.all()],
                           is_admin=current_user.role == ROLE_ADMIN, can_test=current_user.role in (ROLE_ADMIN, ROLE_ANALYST),
                           types=R.TYPE_LABELS, windows=list(R.WINDOWS), severities=R.SEVERITY_LABELS,
                           group_fields=R.GROUP_FIELDS, distinct_fields=R.DISTINCT_FIELDS,
                           smtp=bool(cfg.smtp_host), webhook=bool(cfg.webhook_url), webhook_format=cfg.webhook_format,
                           heartbeat=engine.heartbeat())


# ------------------------------------------------------------------ alerts API
@bp.get('/api/alerts')
@roles_required()
def list_alerts():
    try:
        limit = int(request.args.get('limit', 50))
    except ValueError:
        limit = 50
    return jsonify(alerts=_engine().list(request.args.get('status'), request.args.get('severity'),
                                         request.args.get('rule') or None, limit))


@bp.get('/api/alerts/summary')
@roles_required()
def alerts_summary():
    """Small payload polled by every page (badge in the navigation, tab title, desktop notification)."""
    engine = _engine()
    latest = engine.list('open', limit=1)
    stats = engine.stats(days=1)
    return jsonify(open_total=stats['open_total'], open_by_severity=stats['open_by_severity'],
                   latest_open=latest[0] if latest else None, worker=engine.heartbeat())


@bp.get('/api/alerts/stats')
@roles_required()
def alerts_stats():
    try:
        days = max(1, min(int(request.args.get('days', 14)), 90))
    except ValueError:
        days = 14
    return jsonify(_engine().stats(days))


@bp.get('/api/alerts/<alert_id>')
@roles_required()
def get_alert(alert_id):
    alert = current_app.extensions['sentinel_stores'].db.alerts.find_one({'_id': alert_id})
    if not alert:
        return error_response(404, 'not_found', 'Alerte introuvable.')
    return jsonify(_engine().public(alert))


@bp.post('/api/alerts/<alert_id>/<action>')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def alert_action(alert_id, action):
    if action not in ('acknowledge', 'resolve'):
        return error_response(404, 'not_found', 'Action inconnue.')
    note = (request.get_json(silent=True) or {}).get('note', '')
    return jsonify(_engine().transition(alert_id, action, current_user.username, note))


@bp.post('/api/alerts/run')
@roles_required(ROLE_ADMIN)
def run_now():
    """Run one evaluation cycle immediately (demonstration); respects the worker lock."""
    stores, cfg = current_app.extensions['sentinel_stores'], current_app.extensions['sentinel_config']
    summary = Worker(stores, cfg, engine=_engine()).cycle()
    record_audit(stores.db, current_user.username, 'alerting_run_now', ip=request.remote_addr)
    if summary is None:
        return error_response(409, 'busy', 'Le worker évalue déjà les règles : réessayez dans quelques secondes.')
    return jsonify(summary)


# ------------------------------------------------------------------ rules API
@bp.get('/api/alerts/rules')
@roles_required()
def list_rules():
    return jsonify(rules=[R.public(r) for r in _engine().rules.all()])


@bp.post('/api/alerts/rules')
@roles_required(ROLE_ADMIN)
def create_rule():
    rule = _engine().rules.save(request.get_json(silent=True), current_user.username)
    record_audit(current_app.extensions['sentinel_stores'].db, current_user.username, 'rule_created', target=rule['_id'])
    return jsonify(R.public(rule)), 201


@bp.put('/api/alerts/rules/<rule_id>')
@roles_required(ROLE_ADMIN)
def update_rule(rule_id):
    store = _engine().rules
    if not store.get(rule_id):
        return error_response(404, 'not_found', 'Règle introuvable.')
    rule = store.save(request.get_json(silent=True), current_user.username, rule_id=rule_id)
    record_audit(current_app.extensions['sentinel_stores'].db, current_user.username, 'rule_updated', target=rule_id)
    return jsonify(R.public(rule))


@bp.post('/api/alerts/rules/<rule_id>/enabled')
@roles_required(ROLE_ADMIN)
def toggle_rule(rule_id):
    store = _engine().rules
    if not store.get(rule_id):
        return error_response(404, 'not_found', 'Règle introuvable.')
    enabled = bool((request.get_json(silent=True) or {}).get('enabled'))
    rule = store.set_enabled(rule_id, enabled, current_user.username)
    record_audit(current_app.extensions['sentinel_stores'].db, current_user.username,
                 'rule_enabled' if enabled else 'rule_disabled', target=rule_id)
    return jsonify(R.public(rule))


@bp.delete('/api/alerts/rules/<rule_id>')
@roles_required(ROLE_ADMIN)
def delete_rule(rule_id):
    if not _engine().rules.delete(rule_id):
        return error_response(404, 'not_found', 'Règle introuvable.')
    record_audit(current_app.extensions['sentinel_stores'].db, current_user.username, 'rule_deleted', target=rule_id)
    return jsonify(deleted=rule_id)


@bp.post('/api/alerts/rules/test')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def test_rule():
    """Validate a rule and run it NOW without saving it nor raising anything (« tester avant activation »)."""
    data = dict(request.get_json(silent=True) or {})
    data.setdefault('id', 'rule-under-test')
    rule = R.validate(data, existing_id=data['id'])
    groups = _engine().evaluate(rule)
    return jsonify(valid=True, would_trigger=len(groups), matches=groups[:20],
                   descriptions=[R.describe(rule, g) for g in groups[:20]], es_query=R.build_query(rule))


# ------------------------------------------------------------------ blocklist API
@bp.get('/api/blocklist')
@roles_required()
def get_blocklist():
    bl = _engine().blocklist
    return jsonify(active=bl.active(), history=bl.history(20))


@bp.post('/api/blocklist')
@roles_required(ROLE_ADMIN)
def add_block():
    data = request.get_json(silent=True) or {}
    reason = (data.get('reason') or 'blocage manuel').strip() or 'blocage manuel'
    record = _engine().blocklist.block(data.get('ip'), current_user.username, reason, data.get('minutes'))
    return jsonify(record), 201


@bp.delete('/api/blocklist/<ip>')
@roles_required(ROLE_ADMIN)
def remove_block(ip):
    if not _engine().blocklist.unblock(ip, current_user.username):
        return error_response(404, 'not_found', 'Cette IP n’est pas bloquée.')
    return jsonify(unblocked=ip)


# ------------------------------------------------------------------ demo webhook receiver (laboratory)
@bp.post('/hooks/demo/<token>')
def demo_webhook(token):
    """Receives the webhook notifications in the lab (instead of Slack/Discord/Teams). Token-protected."""
    expected = current_app.extensions['sentinel_config'].webhook_demo_token
    if not expected or not hmac.compare_digest(token, expected):
        return error_response(404, 'not_found', 'Ressource introuvable.')
    payload = request.get_json(silent=True)
    if payload is None:
        return error_response(400, 'invalid_payload', 'JSON attendu.')
    redis = current_app.extensions['sentinel_stores'].redis
    redis.lpush(DEMO_INBOX, json.dumps({'received_at': datetime.now(timezone.utc).isoformat(), 'payload': payload}))
    redis.ltrim(DEMO_INBOX, 0, 19)
    return jsonify(received=True), 202


@bp.get('/api/notifications/demo')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def demo_inbox():
    redis = current_app.extensions['sentinel_stores'].redis
    return jsonify(webhooks=[json.loads(x) for x in redis.lrange(DEMO_INBOX, 0, 19)])
