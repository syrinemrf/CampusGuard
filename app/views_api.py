"""REST API (JSON): uploads, ingestion status, search, event detail, CSV export, history."""
from flask import Blueprint, Response, current_app, jsonify, request
from flask_login import current_user

from app.security import ROLE_ADMIN, ROLE_ANALYST, error_response, roles_required
from app.services.prefs import DashboardPrefs, PrefsError
from app.services.search import SearchService, ValidationError, parse_params
from app.services.uploads import UploadError, UploadService
from app.services.users import record_audit
from app.openapi import build_spec
from app.stores import ElasticError

bp = Blueprint('api', __name__, url_prefix='/api')
v1 = Blueprint('v1', __name__, url_prefix='/api/v1')


def _stores():
    return current_app.extensions['sentinel_stores']


def _cfg():
    return current_app.extensions['sentinel_config']


def _uploads():
    return UploadService(_stores().db, _stores().es, _cfg())


def _search():
    s = _stores()
    return SearchService(s.db, s.redis, s.es, _cfg())


@bp.app_errorhandler(UploadError)
def _upload_error(exc):
    return error_response(exc.status, exc.code, exc.message, **exc.extra)


@bp.app_errorhandler(ValidationError)
def _validation_error(exc):
    return error_response(400, 'invalid_parameters', 'Paramètres invalides.', details=exc.errors)


@bp.app_errorhandler(ElasticError)
def _elastic_error(exc):
    code = 'invalid_query' if exc.status == 400 else 'elasticsearch_unavailable'
    return error_response(exc.status, code, str(exc))


# ------------------------------------------------------------------ uploads

@bp.post('/uploads')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def create_upload():
    """Upload + validate (state: validated or rejected). Ingestion starts only on /confirm."""
    storage = request.files.get('file')
    if storage is None or not storage.filename:
        return error_response(400, 'missing_file', 'Aucun fichier reçu (champ « file »).')
    try:
        doc, rejected = _uploads().receive(storage, current_user, (request.form.get('source_type') or '').lower() or None)
    except UploadError as exc:
        record_audit(_stores().db, current_user.username, 'upload_refused', reason=exc.code,
                     details={'name': storage.filename[:200]}, ip=request.remote_addr)
        raise
    record_audit(_stores().db, current_user.username, 'upload_rejected' if rejected else 'upload_validated',
                 target=doc['id'], reason=doc.get('failure_reason'), ip=request.remote_addr,
                 details={'name': doc['original_name'], 'sha256': doc['sha256']})
    return jsonify(doc), (422 if rejected else 201)


@bp.get('/uploads')
@roles_required()
def list_uploads():
    return jsonify(uploads=_uploads().list(current_user))


@bp.get('/uploads/<upload_id>')
@roles_required()
def get_upload(upload_id):
    return jsonify(_uploads().get(upload_id, current_user, refresh=request.args.get('refresh', '1') != '0'))


@bp.post('/uploads/<upload_id>/confirm')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def confirm_upload(upload_id):
    doc = _uploads().confirm(upload_id, current_user)
    record_audit(_stores().db, current_user.username, 'upload_confirmed', target=upload_id, ip=request.remote_addr)
    return jsonify(doc), 202


@bp.delete('/uploads/<upload_id>')
@roles_required(ROLE_ADMIN, ROLE_ANALYST)
def cancel_upload(upload_id):
    doc = _uploads().cancel(upload_id, current_user)
    record_audit(_stores().db, current_user.username, 'upload_cancelled', target=upload_id, ip=request.remote_addr)
    return jsonify(doc)


# ------------------------------------------------------------------ search

@bp.get('/search')
@roles_required()
def search():
    params = parse_params(request.args)
    service = _search()
    result = service.search(params, nocache=request.args.get('nocache') == '1')
    if params.page == 1 and request.args.get('record', '1') != '0':
        service.record_history(current_user, params)
    return jsonify(result)


@bp.get('/stats')
@roles_required()
def stats():
    return jsonify(_search().stats(_uploads().count_imported()))


@bp.get('/search/facets')
@roles_required()
def facets():
    return jsonify(_search().facets())


@bp.get('/search/history')
@roles_required()
def history():
    try:
        limit = max(1, min(int(request.args.get('limit', 5)), 20))
    except ValueError:
        limit = 5
    return jsonify(history=_search().history(current_user, limit))


@bp.get('/search/export')
@roles_required()
def export():
    params = parse_params(request.args)
    text, truncated, rows = _search().export_csv(params)
    record_audit(_stores().db, current_user.username, 'export_csv', ip=request.remote_addr,
                 details={'rows': rows, 'truncated': truncated, 'filters': params.criteria()})
    response = Response(text, mimetype='text/csv; charset=utf-8')
    response.headers['Content-Disposition'] = 'attachment; filename="sentinel-export.csv"'
    response.headers['X-Export-Rows'] = str(rows)
    response.headers['X-Export-Truncated'] = 'true' if truncated else 'false'
    return response


@bp.get('/events/<event_id>')
@roles_required()
def event_detail(event_id):
    event = _search().get_event(event_id)
    if event is None:
        return error_response(404, 'not_found', 'Événement introuvable.')
    return jsonify(event)


# ------------------------------------------------------------------ dashboard customisation

@bp.get('/dashboard/prefs')
@roles_required()
def get_dashboard_prefs():
    return jsonify(widgets=DashboardPrefs(_stores().db).get(current_user.username))


@bp.put('/dashboard/prefs')
@roles_required()
def put_dashboard_prefs():
    data = request.get_json(silent=True) or {}
    try:
        widgets = DashboardPrefs(_stores().db).save(current_user.username, data.get('widgets'))
    except PrefsError as exc:
        return error_response(400, 'invalid_parameters', str(exc))
    return jsonify(widgets=widgets)


@bp.delete('/dashboard/prefs')
@roles_required()
def reset_dashboard_prefs():
    return jsonify(widgets=DashboardPrefs(_stores().db).reset(current_user.username))


# ------------------------------------------------------------------ OpenAPI + stable /api/v1 aliases

@bp.get('/openapi.json')
@roles_required()
def openapi():
    return jsonify(build_spec())


@v1.get('/logs')
@roles_required()
def v1_logs():
    """Paginated log list (same parameters and response as /api/search, without history recording)."""
    params = parse_params(request.args)
    return jsonify(_search().search(params, nocache=request.args.get('nocache') == '1'))


@v1.get('/logs/<event_id>')
@roles_required()
def v1_log(event_id):
    return event_detail(event_id)


@v1.get('/files')
@roles_required()
def v1_files():
    return list_uploads()


@v1.get('/stats')
@roles_required()
def v1_stats():
    return stats()
