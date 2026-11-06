"""Per-user dashboard customisation (which widgets are shown), stored in MongoDB ``dashboard_prefs``."""
from datetime import datetime, timezone

WIDGETS = ('kpis', 'timeline', 'levels', 'services', 'imports', 'searches')
WIDGET_LABELS = {
    'kpis': 'Indicateurs clés', 'timeline': 'Événements dans le temps', 'levels': 'Répartition par niveau',
    'services': 'Services les plus actifs', 'imports': 'Mes derniers imports', 'searches': 'Dernières recherches',
}


class PrefsError(ValueError):
    pass


class DashboardPrefs:
    def __init__(self, db):
        self.col = db.dashboard_prefs

    def get(self, username):
        doc = self.col.find_one({'username': username}) or {}
        stored = doc.get('widgets', {})
        return {w: bool(stored.get(w, True)) for w in WIDGETS}

    def save(self, username, widgets):
        if not isinstance(widgets, dict) or not widgets:
            raise PrefsError('Objet « widgets » requis.')
        unknown = sorted(set(widgets) - set(WIDGETS))
        if unknown:
            raise PrefsError('Widgets inconnus : ' + ', '.join(unknown))
        if any(not isinstance(v, bool) for v in widgets.values()):
            raise PrefsError('Chaque valeur doit être un booléen.')
        merged = {**self.get(username), **widgets}
        self.col.update_one({'username': username},
                            {'$set': {'username': username, 'widgets': merged,
                                      'updated_at': datetime.now(timezone.utc).isoformat()}}, upsert=True)
        return merged

    def reset(self, username):
        self.col.delete_one({'username': username})
        return self.get(username)
