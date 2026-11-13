"""Kibana integration constants and URL helpers (ids shared with scripts/build_kibana_objects.py)."""
from urllib.parse import quote, urlparse

DATA_VIEW_ID = 'campusguard-logs'
ALERTS_DATA_VIEW_ID = 'campusguard-alerts'
DASHBOARD_ID = 'sentinel-security-overview'
# The 4 S3 visualizations keep their ids (3 required + 1 indicator); the others make the dashboard an
# analysis tool (patterns, targets, geography, alerts) instead of a copy of the home page.
VISUALIZATION_IDS = {
    'guide': 'sentinel-vis-guide',
    'controls': 'sentinel-vis-controls',
    'total': 'sentinel-vis-total-events',
    'outcome': 'sentinel-vis-outcome-split',
    'failure_share': 'sentinel-vis-failure-share',
    'heatmap': 'sentinel-vis-failures-heatmap',
    'top_ips': 'sentinel-vis-top-failing-ips',
    'top_users': 'sentinel-vis-top-targeted-users',
    'timeline': 'sentinel-vis-events-over-time',
    'countries': 'sentinel-vis-failure-countries',
    'alerts_severity': 'sentinel-vis-alerts-severity',
    'alerts_timeline': 'sentinel-vis-alerts-over-time',
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


def dashboard_url(base, embed=False):
    query = '?embed=true&_g=' if embed else '?_g='
    return f"{origin(base)}/app/dashboards#/view/{DASHBOARD_ID}{query}{quote(_time(), safe='(),:!')}"


def discover_url(base):
    return f"{origin(base)}/app/discover#/?_g={quote(_time(), safe='(),:!')}"
