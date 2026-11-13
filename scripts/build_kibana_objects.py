#!/usr/bin/env python3
"""Generate ingestion/kibana/sentinel-dashboard.ndjson (Kibana saved objects).

    python scripts/build_kibana_objects.py            # rewrite the file
    python scripts/build_kibana_objects.py --check    # exit 1 if the committed file is out of date

Contents: 2 data views (logs-* with 2 runtime fields, sentinel-alerts*), 22 visualizations, 3 dashboards
(« Vue d'ensemble », « Menaces sur l'authentification », « Alertes »), each readable on one landscape screen.

Role of this dashboard (it does NOT copy the web home page):
- the web home page (« centre de pilotage ») answers « what needs an action now? » on a short window;
- this Kibana dashboard is for ANALYSIS: interactive filters, long trends, hour x weekday patterns,
  targeted accounts, geography, alerts by severity, and Discover / drill-down from any panel.

The file is the exported/re-importable artefact required by the project statement. It is generated from
code so that every field name can be checked against the Elasticsearch templates (tests/test_s3_kibana.py).
Import:  scripts/setup-kibana.sh (done automatically by the kibana-init container) or Kibana UI
Stack Management > Saved Objects > Import.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.kibana import (ALERTS_DATA_VIEW_ID, DASHBOARDS, DATA_VIEW_ID, DEFAULT_RANGE, RUNTIME_FIELDS,  # noqa: E402
                        VISUALIZATION_IDS)

OUT = ROOT / 'ingestion' / 'kibana' / 'sentinel-dashboard.ndjson'
INDEX_REF = 'kibanaSavedObjectMeta.searchSourceJSON.index'
VERSION = '8.19.10'
FAILURE = 'event.outcome : "failure"'


def _search_source(query='', with_index=True):
    src = {'query': {'query': query, 'language': 'kuery'}, 'filter': []}
    if with_index:
        src['indexRefName'] = INDEX_REF
    return json.dumps(src, ensure_ascii=False)


def _terms(agg_id, field, schema, size, order_by='1', order='desc', label=None):
    params = {'field': field, 'orderBy': order_by, 'order': order, 'size': size, 'otherBucket': False,
              'otherBucketLabel': 'Autres', 'missingBucket': False, 'missingBucketLabel': 'Manquant'}
    if label:
        params['customLabel'] = label
    return {'id': agg_id, 'enabled': True, 'type': 'terms', 'schema': schema, 'params': params}


def _count(label=None):
    return {'id': '1', 'enabled': True, 'type': 'count', 'schema': 'metric',
            'params': {'customLabel': label} if label else {}}


def _date_histogram(agg_id='2', schema='segment'):
    return {'id': agg_id, 'enabled': True, 'type': 'date_histogram', 'schema': schema,
            'params': {'field': '@timestamp', 'useNormalizedEsInterval': True, 'scaleMetricValues': False,
                       'interval': 'auto', 'drop_partials': False, 'min_doc_count': 1, 'extended_bounds': {},
                       'customLabel': 'Date'}}


def _visualization(key, title, description, vis_type, aggs, params, query='', data_view=DATA_VIEW_ID, refs=None):
    state = {'title': title, 'type': vis_type, 'aggs': aggs, 'params': params}
    with_index = data_view is not None
    references = refs if refs is not None else ([{'name': INDEX_REF, 'type': 'index-pattern', 'id': data_view}]
                                                if with_index else [])
    return {
        'id': VISUALIZATION_IDS[key], 'type': 'visualization',
        'attributes': {'title': title, 'description': description, 'version': 1, 'uiStateJSON': '{}',
                       'visState': json.dumps(state, ensure_ascii=False),
                       'kibanaSavedObjectMeta': {'searchSourceJSON': _search_source(query, with_index)}},
        'references': references,
    }


def _xy(vis_type, mode='stacked', scale_mode='normal', y_title='Événements', legend='bottom'):
    return {'type': vis_type, 'grid': {'categoryLines': False},
            'categoryAxes': [{'id': 'CategoryAxis-1', 'type': 'category', 'position': 'bottom', 'show': True, 'style': {},
                              'scale': {'type': 'linear'}, 'labels': {'show': True, 'filter': True, 'truncate': 100}, 'title': {}}],
            'valueAxes': [{'id': 'ValueAxis-1', 'name': 'LeftAxis-1', 'type': 'value', 'position': 'left', 'show': True,
                           'style': {}, 'scale': {'type': 'linear', 'mode': scale_mode},
                           'labels': {'show': True, 'rotate': 0, 'filter': False, 'truncate': 100}, 'title': {'text': y_title}}],
            'seriesParams': [{'show': True, 'type': 'area' if vis_type == 'area' else 'histogram', 'mode': mode,
                              'data': {'label': y_title, 'id': '1'}, 'valueAxis': 'ValueAxis-1',
                              'drawLinesBetweenPoints': True, 'lineWidth': 2, 'showCircles': False, 'interpolate': 'linear'}],
            'addTooltip': True, 'addLegend': True, 'legendPosition': legend, 'times': [], 'addTimeMarker': False,
            'labels': {'show': False}, 'thresholdLine': {'show': False, 'value': 10, 'width': 1, 'style': 'full', 'color': '#E7664C'}}


TABLE = {'perPage': 8, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'showTotal': False, 'totalFunc': 'sum',
         'percentageCol': '', 'autoFitRowToContent': False}
# Same colours as the web application (identity: night / cyan / ultraviolet + semantic state colours).
OUTCOME_COLORS = {'success': '#18D6C8', 'failure': '#FF4D6D', 'unknown': '#8B9AB5'}
SEVERITY_COLORS = {'critical': '#FF4D6D', 'high': '#FF8A3D', 'medium': '#F5C04A', 'low': '#4DA3FF'}
LEVEL_COLORS = {'CRITICAL': '#FF4D6D', 'ERROR': '#FF8A3D', 'WARNING': '#F5C04A', 'INFO': '#4DA3FF', 'DEBUG': '#8B9AB5'}


def _colors(obj, colors):
    obj['attributes']['uiStateJSON'] = json.dumps({'vis': {'colors': colors}})
    return obj


def _metric(key, title, description, agg, query='', data_view=DATA_VIEW_ID):
    return _visualization(key, title, description, 'metric', [agg],
                          {'addTooltip': True, 'addLegend': False, 'type': 'metric',
                           'metric': {'percentageMode': False, 'useRanges': False, 'colorSchema': 'Green to Red',
                                      'metricColorMode': 'None', 'colorsRange': [{'from': 0, 'to': 10000}],
                                      'labels': {'show': True}, 'invertColors': False,
                                      'style': {'bgFill': '#000', 'bgColor': False, 'labelColor': False, 'subText': '',
                                                'fontSize': 34}}},
                          query=query, data_view=data_view)


def _cardinality(field, label):
    return {'id': '1', 'enabled': True, 'type': 'cardinality', 'schema': 'metric', 'params': {'field': field, 'customLabel': label}}


def _pie(key, title, description, field, label, size, colors, data_view=DATA_VIEW_ID, query=''):
    return _colors(_visualization(key, title, description, 'pie', [_count(), _terms('2', field, 'segment', size, label=label)],
                                  {'type': 'pie', 'addTooltip': True, 'addLegend': True, 'legendPosition': 'right', 'isDonut': True,
                                   'labels': {'show': True, 'values': True, 'last_level': True, 'truncate': 100}},
                                  query=query, data_view=data_view), colors)


def build():
    objects = [
        {'id': DATA_VIEW_ID, 'type': 'index-pattern', 'references': [],
         'attributes': {'title': 'logs-*', 'name': 'CampusGuard logs', 'timeFieldName': '@timestamp',
                        'allowNoIndex': True, 'fields': '[]', 'fieldFormatMap': '{}', 'fieldAttrs': '{}',
                        'runtimeFieldMap': json.dumps(RUNTIME_FIELDS), 'sourceFilters': '[]', 'typeMeta': '{}'}},
        {'id': ALERTS_DATA_VIEW_ID, 'type': 'index-pattern', 'references': [],
         'attributes': {'title': 'sentinel-alerts*', 'name': 'CampusGuard alertes', 'timeFieldName': '@timestamp',
                        'allowNoIndex': True, 'fields': '[]', 'fieldFormatMap': '{}', 'fieldAttrs': '{}',
                        'runtimeFieldMap': '{}', 'sourceFilters': '[]', 'typeMeta': '{}'}},
    ]
    add = objects.append
    A = ALERTS_DATA_VIEW_ID

    # ---------------- vue d'ensemble : volumes et tendance
    add(_metric('m_events', 'Événements', 'Nombre d’événements dans la période.', _count('Événements')))
    add(_metric('m_failures', 'Échecs de connexion', 'Événements dont le résultat est un échec.', _count('Échecs'), query=FAILURE))
    add(_metric('m_fail_ips', 'IP en échec', 'Adresses source distinctes ayant au moins un échec.', _cardinality('source.ip', 'IP en échec'), query=FAILURE))
    add(_metric('m_users', 'Comptes visés', 'Comptes distincts ayant subi au moins un échec.', _cardinality('user.name', 'Comptes visés'), query=FAILURE))
    add(_metric('m_alerts', 'Alertes levées', 'Alertes levées par le worker dans la période.', _count('Alertes'), data_view=A))
    add(_colors(_visualization(
        'activity', 'Activité par résultat', 'Connexions réussies et échouées dans le temps.', 'area',
        [_count(), _date_histogram(), _terms('3', 'event.outcome', 'group', 3, label='Résultat')],
        _xy('area', mode='stacked', y_title='Événements', legend='top')), OUTCOME_COLORS))
    add(_pie('outcome', 'Succès et échecs', 'Répartition de event.outcome.', 'event.outcome', 'Résultat', 3, OUTCOME_COLORS))
    add(_colors(_visualization(
        'timeline', 'Événements par niveau', 'Histogramme empilé par niveau de log (log.level).', 'histogram',
        [_count(), _date_histogram(), _terms('3', 'log.level', 'group', 5, label='Niveau')], _xy('histogram', legend='top')),
        LEVEL_COLORS))
    add(_visualization(
        'top_ips', 'IP sources les plus en échec', 'Adresses (source.ip) avec le plus d’échecs.', 'table',
        [_count('Échecs'), _terms('2', 'source.ip', 'bucket', 8, label='IP source')], TABLE, query=FAILURE))

    # ---------------- menaces sur l'authentification : quand, qui, d'où, quoi
    add(_visualization(
        'heatmap', 'Quand ont lieu les échecs ? (heure × jour, Africa/Tunis)',
        'Carte de chaleur des échecs : une tache la nuit ou le week-end signale une attaque automatisée.', 'heatmap',
        [_count('Échecs'), _terms('2', 'hour_of_day', 'segment', 24, order_by='_key', order='asc', label='Heure'),
         _terms('3', 'day_of_week', 'group', 7, order_by='_key', order='asc', label='Jour')],
        {'type': 'heatmap', 'addTooltip': True, 'addLegend': True, 'enableHover': False, 'legendPosition': 'right',
         'times': [], 'colorsNumber': 5, 'colorSchema': 'Reds', 'setColorRange': False, 'colorsRange': [],
         'invertColors': False, 'percentageMode': False,
         'valueAxes': [{'show': False, 'id': 'ValueAxis-1', 'type': 'value', 'scale': {'type': 'linear', 'defaultYExtents': False},
                        'labels': {'show': False, 'rotate': 0, 'overwriteColor': False, 'color': 'black'}}]},
        query=FAILURE))
    add(_colors(_visualization(
        'failure_share', 'Part des échecs dans le temps (%)',
        'Une hausse de la part rouge signale une campagne d’attaque, même si le volume total ne bouge pas.',
        'area', [_count(), _date_histogram(), _terms('3', 'event.outcome', 'group', 3, label='Résultat')],
        _xy('area', mode='stacked', scale_mode='percentage', y_title='Part', legend='top')), OUTCOME_COLORS))
    add(_visualization(
        'top_users', 'Comptes les plus visés', 'Comptes (user.name) avec le plus d’échecs.', 'table',
        [_count('Échecs'), _terms('2', 'user.name', 'bucket', 8, label='Compte')], TABLE, query=FAILURE))
    add(_visualization(
        'countries', 'Pays d’origine des échecs (GeoIP)',
        'Pays des IP en échec ; les adresses privées ou de documentation n’ont pas de pays.', 'table',
        [_count('Échecs'), _terms('2', 'source.geo.country_iso_code', 'bucket', 8, label='Pays')], TABLE, query=FAILURE))
    add(_visualization(
        'services', 'Services attaqués', 'Échecs par service (SSH, VPN, webmail, application…).', 'table',
        [_count('Échecs'), _terms('2', 'service.name', 'bucket', 8, label='Service')], TABLE, query=FAILURE))

    # ---------------- alertes : volume, gravité, règles, cibles
    add(_metric('a_total', 'Alertes levées', 'Alertes levées dans la période.', _count('Alertes'), data_view=A))
    add(_metric('a_critical', 'Alertes critiques', 'Alertes de gravité critique.', _count('Critiques'), query='alert.severity : "critical"', data_view=A))
    add(_metric('a_blocked', 'IP bloquées', 'Alertes ayant déclenché un blocage d’IP.', _count('Blocages'), query='response.action : "block_ip"', data_view=A))
    add(_metric('a_rules', 'Règles déclenchées', 'Règles distinctes ayant levé au moins une alerte.', _cardinality('rule.id', 'Règles'), data_view=A))
    add(_colors(_visualization(
        'alerts_timeline', 'Alertes dans le temps par gravité', 'Alertes levées par jour, empilées par gravité.', 'histogram',
        [_count('Alertes'), _date_histogram(), _terms('3', 'alert.severity', 'group', 4, label='Gravité')],
        _xy('histogram', y_title='Alertes', legend='top'), data_view=A), SEVERITY_COLORS))
    add(_pie('alerts_severity', 'Répartition par gravité', 'Alertes par gravité.', 'alert.severity', 'Gravité', 4,
             SEVERITY_COLORS, data_view=A))
    add(_visualization(
        'alerts_rules', 'Règles les plus déclenchées', 'Nombre d’alertes par règle de détection.', 'table',
        [_count('Alertes'), _terms('2', 'rule.name', 'bucket', 8, label='Règle')], TABLE, data_view=A))
    add(_visualization(
        'alerts_targets', 'Cibles les plus alertées', 'IP ou comptes concernés par le plus d’alertes.', 'table',
        [_count('Alertes'), _terms('2', 'alert.group', 'bucket', 8, label='IP / compte')], TABLE, data_view=A))

    # ---------------- 3 dashboards, grille de 48 colonnes, lisibles sur un écran paysage
    layouts = {
        'overview': [('m_events', 0, 0, 10, 6), ('m_failures', 10, 0, 10, 6), ('m_fail_ips', 20, 0, 10, 6),
                     ('m_users', 30, 0, 9, 6), ('m_alerts', 39, 0, 9, 6),
                     ('activity', 0, 6, 32, 13), ('outcome', 32, 6, 16, 13),
                     ('timeline', 0, 19, 32, 12), ('top_ips', 32, 19, 16, 12)],
        'threats': [('heatmap', 0, 0, 30, 15), ('failure_share', 30, 0, 18, 15),
                    ('top_users', 0, 15, 16, 13), ('countries', 16, 15, 16, 13), ('services', 32, 15, 16, 13)],
        'alerts': [('a_total', 0, 0, 12, 6), ('a_critical', 12, 0, 12, 6), ('a_blocked', 24, 0, 12, 6), ('a_rules', 36, 0, 12, 6),
                   ('alerts_timeline', 0, 6, 32, 13), ('alerts_severity', 32, 6, 16, 13),
                   ('alerts_rules', 0, 19, 24, 12), ('alerts_targets', 24, 19, 24, 12)],
    }
    descriptions = {
        'overview': 'Volumes, tendance succès / échecs, niveaux et IP les plus en échec.',
        'threats': 'Quand, qui, d’où et sur quel service ont lieu les échecs de connexion.',
        'alerts': 'Alertes du worker : volume, gravité, règles et cibles.',
    }
    for key, (dash_id, label) in DASHBOARDS.items():
        panels, refs = [], []
        for i, (vis, x, y, w, h) in enumerate(layouts[key], start=1):
            panels.append({'version': VERSION, 'type': 'visualization', 'gridData': {'x': x, 'y': y, 'w': w, 'h': h, 'i': str(i)},
                           'panelIndex': str(i), 'embeddableConfig': {'enhancements': {}}, 'panelRefName': f'panel_{i}'})
            refs.append({'name': f'panel_{i}', 'type': 'visualization', 'id': VISUALIZATION_IDS[vis]})
        objects.append({
            'id': dash_id, 'type': 'dashboard', 'references': refs,
            'attributes': {'title': f'Sentinel · {label}', 'description': descriptions[key],
                           'hits': 0, 'version': 1, 'timeRestore': True, 'timeFrom': DEFAULT_RANGE[0], 'timeTo': DEFAULT_RANGE[1],
                           'refreshInterval': {'pause': True, 'value': 0},
                           'optionsJSON': json.dumps({'useMargins': True, 'syncColors': True, 'syncCursor': True,
                                                      'syncTooltips': False, 'hidePanelTitles': False}),
                           'panelsJSON': json.dumps(panels),
                           'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({'query': {'query': '', 'language': 'kuery'}, 'filter': []})}}})
    return objects


def render():
    return ''.join(json.dumps(o, ensure_ascii=False, sort_keys=True) + '\n' for o in build())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    text = render()
    if args.check:
        current = OUT.read_text(encoding='utf-8') if OUT.exists() else ''
        if current.replace('\r\n', '\n') != text:
            print('sentinel-dashboard.ndjson is out of date: run python scripts/build_kibana_objects.py')
            return 1
        print('sentinel-dashboard.ndjson is up to date')
        return 0
    OUT.write_text(text, encoding='utf-8', newline='\n')
    print(f'wrote {OUT.relative_to(ROOT)} ({len(build())} objects)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
