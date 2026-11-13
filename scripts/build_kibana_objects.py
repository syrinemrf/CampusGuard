#!/usr/bin/env python3
"""Generate ingestion/kibana/sentinel-dashboard.ndjson (Kibana saved objects).

    python scripts/build_kibana_objects.py            # rewrite the file
    python scripts/build_kibana_objects.py --check    # exit 1 if the committed file is out of date

Contents: 2 data views (logs-* with 2 runtime fields, sentinel-alerts*), 12 visualizations, 1 dashboard.

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
from app.kibana import (ALERTS_DATA_VIEW_ID, DASHBOARD_ID, DATA_VIEW_ID, DEFAULT_RANGE, RUNTIME_FIELDS,  # noqa: E402
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


TABLE = {'perPage': 10, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'showTotal': False, 'totalFunc': 'sum',
         'percentageCol': '', 'autoFitRowToContent': False}

GUIDE = """### Sentinel · analyse sécurité

**À quoi sert ce tableau de bord ?** Comprendre et explorer. Les actions immédiates
(IP prioritaires, santé de l'ingestion, alertes à traiter) sont dans l'application, page *Centre de pilotage*.

- **Filtres** (à droite) : service, niveau, résultat — ils s'appliquent à tous les panneaux.
- **Cliquer** une barre, une part ou une ligne de tableau ajoute un filtre ; *Discover* montre les logs bruts.
- **Carte de chaleur** : heure (Africa/Tunis) × jour des échecs, pour repérer les attaques nocturnes ou automatisées.
- **Alertes** : panneaux du bas, alimentés par le worker d'alertes (S4).

Période par défaut : 90 jours (données de laboratoire synthétiques ou importées)."""


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

    add(_visualization('guide', 'Sentinel · Mode d’emploi', 'Rôle du dashboard et manière de l’utiliser.', 'markdown', [],
                       {'fontSize': 11, 'openLinksInNewTab': False, 'markdown': GUIDE}, data_view=None))

    controls = []
    for i, (field, label) in enumerate([('service.name', 'Service'), ('log.level', 'Niveau'), ('event.outcome', 'Résultat')]):
        controls.append({'id': str(i + 1), 'fieldName': field, 'label': label, 'type': 'list', 'parent': '',
                         'indexPatternRefName': f'control_{i}_index_pattern',
                         'options': {'type': 'terms', 'multiselect': True, 'dynamicOptions': True, 'size': 10, 'order': 'desc'}})
    add(_visualization('controls', 'Sentinel · Filtres', 'Filtres interactifs appliqués à tout le dashboard.',
                       'input_control_vis', [], {'controls': controls, 'updateFiltersOnChange': True, 'useTimeFilter': True,
                                                 'pinFilters': False}, data_view=None,
                       refs=[{'name': f'control_{i}_index_pattern', 'type': 'index-pattern', 'id': DATA_VIEW_ID}
                             for i in range(len(controls))]))

    add(_visualization(
        'total', 'Sentinel · Événements indexés', 'Nombre total d’événements dans la période et les filtres.', 'metric',
        [_count('Événements')],
        {'addTooltip': True, 'addLegend': False, 'type': 'metric',
         'metric': {'percentageMode': False, 'useRanges': False, 'colorSchema': 'Green to Red', 'metricColorMode': 'None',
                    'colorsRange': [{'from': 0, 'to': 10000}], 'labels': {'show': True}, 'invertColors': False,
                    'style': {'bgFill': '#000', 'bgColor': False, 'labelColor': False, 'subText': '', 'fontSize': 48}}}))

    add(_visualization(
        'outcome', 'Sentinel · Succès et échecs d’authentification', 'Répartition de event.outcome (success / failure / unknown).',
        'pie', [_count(), _terms('2', 'event.outcome', 'segment', 5, label='Résultat')],
        {'type': 'pie', 'addTooltip': True, 'addLegend': True, 'legendPosition': 'right', 'isDonut': True,
         'labels': {'show': True, 'values': True, 'last_level': True, 'truncate': 100}}))

    add(_visualization(
        'failure_share', 'Sentinel · Part des échecs dans le temps (%)',
        'Aire empilée à 100 % par résultat : une hausse de la part rouge signale une campagne d’attaque, même à volume constant.',
        'area', [_count(), _date_histogram(), _terms('3', 'event.outcome', 'group', 3, label='Résultat')],
        _xy('area', mode='stacked', scale_mode='percentage', y_title='Part des événements')))

    add(_visualization(
        'heatmap', 'Sentinel · Échecs par heure et jour (Africa/Tunis)',
        'Carte de chaleur heure × jour de semaine des échecs (champs runtime hour_of_day / day_of_week du data view).',
        'heatmap',
        [_count('Échecs'), _terms('2', 'hour_of_day', 'segment', 24, order_by='_key', order='asc', label='Heure'),
         _terms('3', 'day_of_week', 'group', 7, order_by='_key', order='asc', label='Jour')],
        {'type': 'heatmap', 'addTooltip': True, 'addLegend': True, 'enableHover': False, 'legendPosition': 'right',
         'times': [], 'colorsNumber': 5, 'colorSchema': 'Reds', 'setColorRange': False, 'colorsRange': [],
         'invertColors': False, 'percentageMode': False,
         'valueAxes': [{'show': False, 'id': 'ValueAxis-1', 'type': 'value', 'scale': {'type': 'linear', 'defaultYExtents': False},
                        'labels': {'show': False, 'rotate': 0, 'overwriteColor': False, 'color': 'black'}}]},
        query=FAILURE))

    add(_visualization(
        'top_ips', 'Sentinel · Top 10 des IP sources en échec',
        'Adresses source (source.ip) ayant le plus d’échecs (event.outcome : failure).', 'table',
        [_count('Échecs'), _terms('2', 'source.ip', 'bucket', 10, label='IP source')], TABLE, query=FAILURE))

    add(_visualization(
        'top_users', 'Sentinel · Comptes les plus visés',
        'Comptes (user.name) ayant subi le plus d’échecs : cible d’une force brute ou d’un mot de passe expiré.', 'table',
        [_count('Échecs'), _terms('2', 'user.name', 'bucket', 10, label='Compte')], TABLE, query=FAILURE))

    add(_visualization(
        'timeline', 'Sentinel · Événements dans le temps par niveau', 'Histogramme empilé par niveau de log (log.level).',
        'histogram', [_count(), _date_histogram(), _terms('3', 'log.level', 'group', 5, label='Niveau')], _xy('histogram')))

    add(_visualization(
        'countries', 'Sentinel · Pays d’origine des échecs (GeoIP)',
        'Code pays GeoIP (source.geo.country_iso_code) des échecs. Les IP privées ou de documentation n’ont pas de pays.',
        'table', [_count('Échecs'), _terms('2', 'source.geo.country_iso_code', 'bucket', 10, label='Pays')], TABLE,
        query=FAILURE))

    add(_visualization(
        'alerts_severity', 'Sentinel · Alertes par gravité', 'Alertes levées par le worker (index sentinel-alerts*), par gravité.',
        'pie', [_count('Alertes'), _terms('2', 'alert.severity', 'segment', 4, label='Gravité')],
        {'type': 'pie', 'addTooltip': True, 'addLegend': True, 'legendPosition': 'right', 'isDonut': True,
         'labels': {'show': True, 'values': True, 'last_level': True, 'truncate': 100}}, data_view=ALERTS_DATA_VIEW_ID))

    add(_visualization(
        'alerts_timeline', 'Sentinel · Alertes dans le temps par règle', 'Alertes levées par jour et par règle de détection.',
        'histogram', [_count('Alertes'), _date_histogram(), _terms('3', 'rule.name', 'group', 8, label='Règle')],
        _xy('histogram', y_title='Alertes'), data_view=ALERTS_DATA_VIEW_ID))

    # 48-column grid. Order = reading order: how to use it, filters, volume, then patterns, targets, alerts.
    grid = [('guide', 0, 0, 22, 11), ('controls', 22, 0, 14, 11), ('total', 36, 0, 12, 11),
            ('failure_share', 0, 11, 30, 13), ('outcome', 30, 11, 18, 13),
            ('heatmap', 0, 24, 30, 15), ('top_ips', 30, 24, 18, 15),
            ('timeline', 0, 39, 30, 13), ('top_users', 30, 39, 18, 13),
            ('alerts_timeline', 0, 52, 22, 13), ('alerts_severity', 22, 52, 14, 13), ('countries', 36, 52, 12, 13)]
    panels, refs = [], []
    for i, (key, x, y, w, h) in enumerate(grid, start=1):
        panels.append({'version': VERSION, 'type': 'visualization', 'gridData': {'x': x, 'y': y, 'w': w, 'h': h, 'i': str(i)},
                       'panelIndex': str(i), 'embeddableConfig': {'enhancements': {}}, 'panelRefName': f'panel_{i}'})
        refs.append({'name': f'panel_{i}', 'type': 'visualization', 'id': VISUALIZATION_IDS[key]})
    objects.append({
        'id': DASHBOARD_ID, 'type': 'dashboard', 'references': refs,
        'attributes': {'title': 'Sentinel · Analyse sécurité',
                       'description': ('CampusGuard / Sentinel : analyse et exploration (filtres, tendances, motifs horaires, '
                                       'comptes visés, géographie, alertes). Les actions immédiates sont dans l’application.'),
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
