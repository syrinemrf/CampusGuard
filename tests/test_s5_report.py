"""S5 : rapport mensuel de conformité (données mesurées → contrôles → PDF)."""
from datetime import datetime, timezone

import pytest

from app.services.report import MonthlyReport, ReportError, build_logs_query, month_bounds, render_pdf, shape_logs

LOGS = {'hits': {'total': {'value': 4210}}, 'aggregations': {
    'levels': {'buckets': [{'key': 'INFO', 'doc_count': 3000}, {'key': 'WARNING', 'doc_count': 1100}, {'key': 'ERROR', 'doc_count': 110}]},
    'services': {'buckets': [{'key': 'openssh', 'doc_count': 2000}, {'key': 'authentication', 'doc_count': 2210}]},
    'auth': {'doc_count': 900, 'outcomes': {'buckets': [{'key': 'failure', 'doc_count': 523}, {'key': 'success', 'doc_count': 377}]},
             'daily': {'buckets': [{'key_as_string': f'2026-10-{d:02d}T00:00:00.000Z', 'o': {'buckets': [
                 {'key': 'success', 'doc_count': 10 + d % 4}, {'key': 'failure', 'doc_count': (60 if d == 12 else d % 7)}]}} for d in range(1, 32)]}},
    'failures': {'doc_count': 523, 'ips': {'value': 41},
                 'countries': {'buckets': [{'key': 'CN', 'doc_count': 380}, {'key': 'MX', 'doc_count': 80}, {'key': 'RU', 'doc_count': 20}]},
                 'top_ips': {'buckets': [{'key': '183.62.75.200', 'doc_count': 286, 'users': {'value': 1}, 'country': {'buckets': [{'key': 'CN'}]}},
                                         {'key': '187.141.25.159', 'doc_count': 80, 'users': {'value': 27}, 'country': {'buckets': [{'key': 'MX'}]}}]},
                 'top_users': {'buckets': [{'key': 'root', 'doc_count': 370}, {'key': 'admin', 'doc_count': 45}]}}}}


def oct(day, hour=10, minute=0):
    return datetime(2026, 10, day, hour, minute, tzinfo=timezone.utc)


@pytest.fixture
def seeded(stores):
    db = stores.db
    db.alerts.insert_many([
        {'_id': 'a1', 'rule_name': 'Force brute', 'severity': 'high', 'status': 'resolved', 'group': '183.62.75.200',
         'triggered_at': oct(12), 'acknowledged_at': oct(12, 10, 5), 'resolved_at': oct(12, 10, 40), 'time_to_resolve_s': 2400},
        {'_id': 'a2', 'rule_name': 'Pays non autorisé', 'severity': 'critical', 'status': 'resolved', 'group': '119.137.1.2',
         'triggered_at': oct(14), 'resolved_at': oct(14, 11, 30), 'time_to_resolve_s': 5400, 'escalation_level': 3},
        {'_id': 'a3', 'rule_name': 'Force brute', 'severity': 'medium', 'status': 'open', 'group': '5.188.1.6', 'triggered_at': oct(30)},
        {'_id': 'old', 'rule_name': 'x', 'severity': 'low', 'status': 'resolved', 'triggered_at': datetime(2026, 9, 3, tzinfo=timezone.utc)}])
    db.ip_blocks.insert_many([{'ip': '183.62.75.200', 'action': 'block', 'at': oct(12)}, {'ip': '183.62.75.200', 'action': 'unblock', 'at': oct(12, 11)}])
    db.audit_actions.insert_many([{'action': 'login_success', 'timestamp': oct(2)}, {'action': 'export_csv', 'timestamp': oct(3)},
                                  {'action': 'ip_unblocked', 'timestamp': oct(12, 11)}])
    db.uploaded_files.insert_many([{'state': 'indexed', 'created_at': oct(5)}, {'state': 'partial', 'created_at': oct(6)}])
    stores.es.responses = [LOGS]
    return stores


def test_month_bounds_and_validation():
    start, end, days = month_bounds('2026-12')
    assert (start.month, end.year, end.month, days) == (12, 2027, 1, 31)
    for bad in ('2026-13', '26-01', '2026/01', None):
        with pytest.raises(ReportError):
            month_bounds(bad)
    q = build_logs_query(*month_bounds('2026-10')[:2])
    assert q['query']['range']['@timestamp'] == {'gte': '2026-10-01T00:00:00+00:00', 'lt': '2026-11-01T00:00:00+00:00'}


def test_logs_are_summarised():
    L = shape_logs(LOGS)
    assert L['success_rate'] == 41.9 and L['failing_ips'] == 41 and len(L['daily']) == 31
    assert L['top_ips'][1] == {'ip': '187.141.25.159', 'failures': 80, 'users': 27, 'country': 'MX'}


def test_collect_measures_alerts_response_audit_and_controls(seeded, app):
    d = MonthlyReport(seeded, app.extensions['sentinel_config']).collect('2026-10', now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    a = d['alerts']
    assert a['total'] == 3 and a['by_severity']['critical'] == 1 and a['open'] == 1           # septembre exclu
    assert a['mttr_min'] == 65.0 and a['escalated'] == 1 and a['escalated_l3'] == 1
    assert a['ack_within_sla_pct'] == 33.3                       # a1 en 5 min ; a2 en 90 min ; a3 jamais
    assert d['blocks'] == {'total': 1, 'manual_unblocks': 1, 'ips': ['183.62.75.200']}
    assert d['audit']['sensitive'] == 2 and d['uploads']['partial'] == 1 and not d['partial']
    verdicts = {c['label']: c['ok'] for c in d['controls']}
    assert verdicts['Alertes prises en compte en moins de 15 min'] is False
    assert verdicts['Alertes critiques escaladées jusqu’au RSSI (N3)'] is False and verdicts['Imports en échec'] is True


def test_pdf_is_produced(seeded, app):
    d = MonthlyReport(seeded, app.extensions['sentinel_config']).collect('2026-10', now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    pdf = render_pdf(d, author='auditeur')
    assert pdf.startswith(b'%PDF') and len(pdf) > 3000


def test_empty_month_still_gives_a_readable_report(stores, app):
    stores.es.responses = [{'hits': {'total': {'value': 0}}, 'aggregations': {}}]
    d = MonthlyReport(stores, app.extensions['sentinel_config']).collect('2026-01', now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    assert d['logs']['success_rate'] is None and d['alerts']['total'] == 0
    assert render_pdf(d).startswith(b'%PDF')


def test_api_returns_the_pdf_and_audits_it(auditor, seeded):
    r = auditor.get('/api/reports/monthly?month=2026-10')
    assert r.status_code == 200 and r.mimetype == 'application/pdf'
    assert 'sentinel-conformite-2026-10.pdf' in r.headers['Content-Disposition'] and r.data.startswith(b'%PDF')
    assert seeded.db.audit_actions.find_one({'action': 'report_monthly', 'target': '2026-10', 'actor': 'auditeur'})
    assert auditor.get('/api/reports/monthly?month=2026-99').status_code == 400


def test_reports_page_previews_the_controls(analyst, stores):
    stores.es.responses = [LOGS]
    html = analyst.get('/reports').get_data(as_text=True)
    assert 'Contrôles du mois' in html and 'Télécharger le PDF' in html and '183.62.75.200' in html
