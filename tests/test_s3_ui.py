"""S3 UI states (KAN-44 / KAN-45): detail modal, 404 page, breadcrumb, flash messages, mobile navigation."""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_search_page_has_an_accessible_detail_modal(analyst):
    html = analyst.get('/search').get_data(as_text=True)
    assert '<dialog id="event-dialog" class="modal" aria-labelledby="dlg-title">' in html
    assert 'id="dlg-page"' in html and 'Ouvrir la page dédiée' in html
    assert '<title>Explorateur de logs · Sentinel</title>' in html and html.index('<dialog') > html.index('id="results"')
    js = (ROOT / 'app/static/js/search.js').read_text(encoding='utf-8')
    assert 'showModal' in js and "api('/api/events/'" in js and 'lastRow.focus()' in js
    assert 'innerHTML' not in js                                  # dynamic text only through textContent


def test_dedicated_event_page_stays_available_as_a_permalink(analyst):
    html = analyst.get('/events/doc000001abc').get_data(as_text=True)
    assert 'data-event-id="doc000001abc"' in html
    assert 'Explorateur de logs</a><span aria-current="page">Détail</span>' in html


def test_unknown_page_renders_a_helpful_404(analyst):
    res = analyst.get('/nope/nothing')
    html = res.get_data(as_text=True)
    assert res.status_code == 404 and 'Page introuvable' in html and 'Explorateur de logs' in html
    assert analyst.get('/api/nope').get_json()['error'] == 'not_found'          # API keeps JSON errors


def test_breadcrumb_on_inner_pages_but_not_on_home(analyst, stores):
    assert 'Fil d’Ariane' in analyst.get('/upload').get_data(as_text=True)
    assert 'aria-current="page">Envoi de fichiers' in analyst.get('/upload').get_data(as_text=True)
    assert 'Fil d’Ariane' not in analyst.get('/').get_data(as_text=True)


def test_logout_shows_a_flash_message_once(analyst):
    res = analyst.post('/logout', follow_redirects=True)
    assert 'Vous êtes déconnecté(e)' in res.get_data(as_text=True)
    assert 'Vous êtes déconnecté(e)' not in analyst.get('/login').get_data(as_text=True)


def test_mobile_layout_keeps_logout_reachable():
    css = (ROOT / 'app/static/css/app.css').read_text(encoding='utf-8')
    mobile = css[css.index('/* S3 — fil d'):]
    assert 'aside .me{display:flex' in mobile and '.who{display:none}' in mobile
