"""Kibana integration constants and URL helpers (ids shared with scripts/build_kibana_objects.py)."""
from urllib.parse import quote, urlparse

DATA_VIEW_ID = 'campusguard-logs'
ALERTS_DATA_VIEW_ID = 'campusguard-alerts'
DASHBOARD_ID = 'sentinel-security-overview'          # main dashboard (kept id: earlier exports stay importable)
# Three themed dashboards, each readable on one landscape screen. Key -> (id, tab label).
DASHBOARDS = {
    'overview': (DASHBOARD_ID, 'Vue d’ensemble'),
    'threats': ('sentinel-auth-threats', 'Menaces sur l’authentification'),
    'alerts': ('sentinel-alerts-overview', 'Alertes'),
}
VISUALIZATION_IDS = {
    # vue d'ensemble : uniquement des tendances (les chiffres du moment sont sur l'accueil de l'application)
    'activity': 'sentinel-vis-activity-by-outcome', 'outcome': 'sentinel-vis-outcome-split',
    'timeline': 'sentinel-vis-events-over-time', 'by_source': 'sentinel-vis-volume-by-source',
    'top_ips': 'sentinel-vis-top-failing-ips',
    # menaces
    'heatmap': 'sentinel-vis-failures-heatmap', 'failure_share': 'sentinel-vis-failure-share',
    'top_users': 'sentinel-vis-top-targeted-users', 'countries': 'sentinel-vis-failure-countries',
    'services': 'sentinel-vis-failures-by-service',
    # alertes
    'a_total': 'sentinel-vis-metric-alerts-total', 'a_critical': 'sentinel-vis-metric-alerts-critical',
    'a_blocked': 'sentinel-vis-metric-ip-blocks', 'a_rules': 'sentinel-vis-metric-rules-fired',
    'alerts_timeline': 'sentinel-vis-alerts-over-time', 'alerts_severity': 'sentinel-vis-alerts-severity',
    'alerts_rules': 'sentinel-vis-alerts-top-rules', 'alerts_targets': 'sentinel-vis-alerts-top-targets',
}
TIMEZONE = 'Africa/Tunis'
# Runtime fields of the data view (computed at query time, nothing re-indexed): hour of day and weekday in local time.
RUNTIME_FIELDS = {
    'hour_of_day': {'type': 'long', 'script': {'source': (
        "if (doc['@timestamp'].size() == 0) { return; } "
        f"emit(doc['@timestamp'].value.withZoneSameInstant(ZoneId.of('{TIMEZONE}')).getHour());")}},
    'day_of_week': {'type': 'keyword', 'script': {'source': (
        "if (doc['@timestamp'].size() == 0) { return; } "
        "String[] d = new String[] {'1 lun', '2 mar', '3 mer', '4 jeu', '5 ven', '6 sam', '7 dim'}; "
        f"emit(d[doc['@timestamp'].value.withZoneSameInstant(ZoneId.of('{TIMEZONE}')).getDayOfWeekEnum().getValue() - 1]);")}},
}
DEFAULT_PUBLIC_URL = 'http://localhost:5601'
DEFAULT_RANGE = ('now-90d', 'now')


def origin(url):
    """Scheme + host[:port] of a configured Kibana URL; falls back to the default if it is not http(s)."""
    parsed = urlparse((url or '').strip())
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        parsed = urlparse(DEFAULT_PUBLIC_URL)
    return f'{parsed.scheme}://{parsed.netloc}'


def _time(rng=DEFAULT_RANGE):
    return f"(refreshInterval:(pause:!t,value:0),time:(from:{rng[0]},to:{rng[1]}))"


def dashboard_url(base, embed=False, dashboard_id=DASHBOARD_ID):
    query = '?embed=true&show-time-filter=true&_g=' if embed else '?_g='
    return f"{origin(base)}/app/dashboards#/view/{dashboard_id}{query}{quote(_time(), safe='(),:!')}"


def discover_url(base):
    return f"{origin(base)}/app/discover#/?_g={quote(_time(), safe='(),:!')}"
