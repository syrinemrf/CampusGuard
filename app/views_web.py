"""Server-rendered pages (Jinja2). Data loading is done by the JSON API via small JS files."""
from flask import Blueprint, current_app, render_template, request
from flask_login import current_user

from app.kibana import dashboard_url, discover_url
from app.security import ROLE_ADMIN, ROLE_ANALYST, ROLE_LABELS, roles_required
from app.services.overview import PERIODS, OverviewService, fmt_age
from app.services.prefs import WIDGET_LABELS, DashboardPrefs
from app.services.search import SearchService
from app.services.uploads import UploadService

bp = Blueprint('web', __name__)
SERVICE_NAMES = {'elasticsearch': 'Elasticsearch', 'mongodb': 'MongoDB', 'redis': 'Redis', 'logstash': 'Logstash',
                 'kibana': 'Kibana', 'alert_worker': 'Worker d’alertes'}


@bp.get('/')
@roles_required()
def home():
    stores = current_app.extensions['sentinel_stores']
    cfg = current_app.extensions['sentinel_config']
    prefs = DashboardPrefs(stores.db)
    period = request.args.get('period')
    if period in PERIODS:
        prefs.save(current_user.username, period=period)      # the chosen period is remembered (MongoDB)
    else:
        period = prefs.period(current_user.username)
    overview = OverviewService(stores, cfg, http=current_app.extensions.get('sentinel_http')).build(period)
    search = SearchService(stores.db, stores.redis, stores.es, cfg)
    upload_service = UploadService(stores.db, stores.es, cfg)
    return render_template('home.html', ov=overview, es_error=overview['es_error'], fmt_age=fmt_age,
                           uploads=upload_service.list(current_user, limit=5),
                           history=search.history(current_user, 5), page='home',
                           widgets=prefs.get(current_user.username), widget_labels=WIDGET_LABELS,
                           kibana_url=dashboard_url(cfg.kibana_public_url),
                           service_names=SERVICE_NAMES)


@bp.get('/upload')
@roles_required()
def upload():
    cfg = current_app.extensions['sentinel_config']
    can_upload = current_user.role in (ROLE_ADMIN, ROLE_ANALYST)
    return render_template('upload.html', page='upload', can_upload=can_upload, max_mb=cfg.max_upload_mb)


@bp.get('/search')
@roles_required()
def search_page():
    from app.services.search import SEARCHABLE_FIELDS
    return render_template('search.html', page='search', fields=SEARCHABLE_FIELDS)


@bp.get('/kibana')
@roles_required()
def kibana_page():
    base = current_app.extensions['sentinel_config'].kibana_public_url
    return render_template('kibana.html', page='kibana', embed_url=dashboard_url(base, embed=True),
                           open_url=dashboard_url(base), discover_url=discover_url(base))


@bp.get('/api/docs')
@roles_required()
def api_docs():
    return render_template('docs.html', page='docs')


@bp.get('/events/<event_id>')
@roles_required()
def event_page(event_id):
    return render_template('event.html', page='search', event_id=event_id)
