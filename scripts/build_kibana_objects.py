#!/usr/bin/env python3
"""Generate ingestion/kibana/sentinel-dashboard.ndjson (Kibana saved objects: 1 data view, 4 visualizations, 1 dashboard).

    python scripts/build_kibana_objects.py            # rewrite the file
    python scripts/build_kibana_objects.py --check    # exit 1 if the committed file is out of date

The file is the exported/re-importable artefact required by the project statement. It is generated from
code so that every field name can be checked against the Elasticsearch template (tests/test_s3_kibana.py).
Import:  scripts/setup-kibana.sh (done automatically by the kibana-init container) or Kibana UI
Stack Management > Saved Objects > Import.
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.kibana import DASHBOARD_ID, DATA_VIEW_ID, DEFAULT_RANGE, VISUALIZATION_IDS  # noqa: E402

OUT = ROOT / 'ingestion' / 'kibana' / 'sentinel-dashboard.ndjson'
INDEX_REF = 'kibanaSavedObjectMeta.searchSourceJSON.index'


def _search_source(query=''):
    return json.dumps({'query': {'query': query, 'language': 'kuery'}, 'filter': [], 'indexRefName': INDEX_REF})


def _terms(agg_id, field, schema, size, order_by='1'):
    return {'id': agg_id, 'enabled': True, 'type': 'terms', 'schema': schema,
            'params': {'field': field, 'orderBy': order_by, 'order': 'desc', 'size': size, 'otherBucket': False,
                       'otherBucketLabel': 'Autres', 'missingBucket': False, 'missingBucketLabel': 'Manquant'}}


COUNT = {'id': '1', 'enabled': True, 'type': 'count', 'params': {}, 'schema': 'metric'}


def _visualization(vis_id, title, description, vis_type, aggs, params, query=''):
    state = {'title': title, 'type': vis_type, 'aggs': aggs, 'params': params}
    return {
        'id': vis_id, 'type': 'visualization',
        'attributes': {'title': title, 'description': description, 'version': 1, 'uiStateJSON': '{}',
                       'visState': json.dumps(state),
                       'kibanaSavedObjectMeta': {'searchSourceJSON': _search_source(query)}},
        'references': [{'name': INDEX_REF, 'type': 'index-pattern', 'id': DATA_VIEW_ID}],
    }


def build():
    objects = [{
        'id': DATA_VIEW_ID, 'type': 'index-pattern', 'references': [],
        'attributes': {'title': 'logs-*', 'name': 'CampusGuard logs', 'timeFieldName': '@timestamp',
                       'allowNoIndex': True, 'fields': '[]', 'fieldFormatMap': '{}', 'fieldAttrs': '{}',
                       'runtimeFieldMap': '{}', 'sourceFilters': '[]', 'typeMeta': '{}'}}]

    objects.append(_visualization(
        VISUALIZATION_IDS['total'], 'Sentinel · Événements indexés', 'Nombre total d’événements dans la période.',
        'metric', [COUNT],
        {'addTooltip': True, 'addLegend': False, 'type': 'metric',
         'metric': {'percentageMode': False, 'useRanges': False, 'colorSchema': 'Green to Red', 'metricColorMode': 'None',
                    'colorsRange': [{'from': 0, 'to': 10000}], 'labels': {'show': True}, 'invertColors': False,
                    'style': {'bgFill': '#000', 'bgColor': False, 'labelColor': False, 'subText': '', 'fontSize': 48}}}))

    objects.append(_visualization(
        VISUALIZATION_IDS['timeline'], 'Sentinel · Événements dans le temps par niveau',
        'Histogramme empilé par niveau de log (log.level).', 'histogram',
        [COUNT,
         {'id': '2', 'enabled': True, 'type': 'date_histogram', 'schema': 'segment',
          'params': {'field': '@timestamp', 'useNormalizedEsInterval': True, 'scaleMetricValues': False, 'interval': 'auto',
                     'drop_partials': False, 'min_doc_count': 1, 'extended_bounds': {}}},
         _terms('3', 'log.level', 'group', 5)],
        {'type': 'histogram', 'grid': {'categoryLines': False},
         'categoryAxes': [{'id': 'CategoryAxis-1', 'type': 'category', 'position': 'bottom', 'show': True, 'style': {},
                           'scale': {'type': 'linear'}, 'labels': {'show': True, 'filter': True, 'truncate': 100}, 'title': {}}],
         'valueAxes': [{'id': 'ValueAxis-1', 'name': 'LeftAxis-1', 'type': 'value', 'position': 'left', 'show': True,
                        'style': {}, 'scale': {'type': 'linear', 'mode': 'normal'},
                        'labels': {'show': True, 'rotate': 0, 'filter': False, 'truncate': 100}, 'title': {'text': 'Événements'}}],
         'seriesParams': [{'show': True, 'type': 'histogram', 'mode': 'stacked', 'data': {'label': 'Événements', 'id': '1'},
                           'valueAxis': 'ValueAxis-1', 'drawLinesBetweenPoints': True, 'lineWidth': 2, 'showCircles': True}],
         'addTooltip': True, 'addLegend': True, 'legendPosition': 'bottom', 'times': [], 'addTimeMarker': False,
         'labels': {'show': False}, 'thresholdLine': {'show': False, 'value': 10, 'width': 1, 'style': 'full', 'color': '#E7664C'}}))

    objects.append(_visualization(
        VISUALIZATION_IDS['outcome'], 'Sentinel · Succès et échecs d’authentification',
        'Répartition de event.outcome (success / failure / unknown).', 'pie',
        [COUNT, _terms('2', 'event.outcome', 'segment', 5)],
        {'type': 'pie', 'addTooltip': True, 'addLegend': True, 'legendPosition': 'right', 'isDonut': True,
         'labels': {'show': True, 'values': True, 'last_level': True, 'truncate': 100}}))

    objects.append(_visualization(
        VISUALIZATION_IDS['top_ips'], 'Sentinel · Top 10 des IP sources en échec',
        'Adresses source (source.ip) ayant le plus d’échecs (event.outcome : failure).', 'table',
        [COUNT, _terms('2', 'source.ip', 'bucket', 10)],
        {'perPage': 10, 'showPartialRows': False, 'showMetricsAtAllLevels': False, 'showTotal': False, 'totalFunc': 'sum',
         'percentageCol': '', 'autoFitRowToContent': False},
        query='event.outcome : "failure"'))

    grid = [('total', 0, 0, 12, 8), ('outcome', 12, 0, 18, 8), ('top_ips', 30, 0, 18, 15),
            ('timeline', 0, 8, 30, 15)]
    panels, refs = [], []
    for i, (key, x, y, w, h) in enumerate(grid, start=1):
        panels.append({'version': '8.19.10', 'type': 'visualization', 'gridData': {'x': x, 'y': y, 'w': w, 'h': h, 'i': str(i)},
                       'panelIndex': str(i), 'embeddableConfig': {'enhancements': {}}, 'panelRefName': f'panel_{i}'})
        refs.append({'name': f'panel_{i}', 'type': 'visualization', 'id': VISUALIZATION_IDS[key]})
    objects.append({
        'id': DASHBOARD_ID, 'type': 'dashboard', 'references': refs,
        'attributes': {'title': 'Sentinel · Vue d’ensemble sécurité',
                       'description': 'CampusGuard / Sentinel : volumétrie, niveaux, succès/échecs et IP les plus actives en échec.',
                       'hits': 0, 'version': 1, 'timeRestore': True, 'timeFrom': DEFAULT_RANGE[0], 'timeTo': DEFAULT_RANGE[1],
                       'refreshInterval': {'pause': True, 'value': 0},
                       'optionsJSON': json.dumps({'useMargins': True, 'syncColors': False, 'syncCursor': True,
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
