"""Kibana integration constants and URL helpers (ids shared with scripts/build_kibana_objects.py)."""
from urllib.parse import quote, urlparse

DATA_VIEW_ID = 'campusguard-logs'
DASHBOARD_ID = 'sentinel-security-overview'
VISUALIZATION_IDS = {
    'total': 'sentinel-vis-total-events',
    'timeline': 'sentinel-vis-events-over-time',
    'outcome': 'sentinel-vis-outcome-split',
    'top_ips': 'sentinel-vis-top-failing-ips',
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
