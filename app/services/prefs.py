"""Per-user dashboard customisation (blocks shown + analysis period), stored in MongoDB ``dashboard_prefs``."""
from datetime import datetime, timezone

from app.services.overview import DEFAULT_PERIOD, PERIODS

WIDGETS = ('kpis', 'alerts', 'priorities', 'health', 'imports', 'searches')
WIDGET_LABELS = {
    'kpis': 'Indicateurs d’authentification', 'alerts': 'Alertes à traiter', 'priorities': 'IP à examiner en priorité',
    'health': 'Santé de la plateforme et de l’ingestion', 'imports': 'Mes derniers imports',
    'searches': 'Mes dernières recherches',
}


class PrefsError(ValueError):
    pass


class DashboardPrefs:
    def __init__(self, db):
        self.col = db.dashboard_prefs

    def _doc(self, username):
        return self.col.find_one({'username': username}) or {}

    def get(self, username):
        stored = self._doc(username).get('widgets', {})
        return {w: bool(stored.get(w, True)) for w in WIDGETS}

    def period(self, username):
        value = self._doc(username).get('period')
        return value if value in PERIODS else DEFAULT_PERIOD

    def save(self, username, widgets=None, period=None):
        if widgets is None and period is None:
            raise PrefsError('Objet « widgets » ou « period » requis.')
        update = {'username': username, 'updated_at': datetime.now(timezone.utc).isoformat()}
        if widgets is not None:
            if not isinstance(widgets, dict) or not widgets:
                raise PrefsError('Objet « widgets » requis.')
            unknown = sorted(set(widgets) - set(WIDGETS))
            if unknown:
                raise PrefsError('Widgets inconnus : ' + ', '.join(unknown))
            if any(not isinstance(v, bool) for v in widgets.values()):
                raise PrefsError('Chaque valeur doit être un booléen.')
            update['widgets'] = {**self.get(username), **widgets}
        if period is not None:
            if period not in PERIODS:
                raise PrefsError('Période inconnue : ' + ', '.join(PERIODS) + ' attendu.')
            update['period'] = period
        self.col.update_one({'username': username}, {'$set': update}, upsert=True)
        return self.get(username)

    def reset(self, username):
        self.col.delete_one({'username': username})
        return self.get(username)
