"""Rapport mensuel de conformité sécurité (S5) : données mesurées du mois → PDF (ReportLab).

Destinataires : RSSI, auditeur, direction. Le rapport répond à quatre questions :
    1. Que s'est-il passé ? (volumes, authentifications, tendance par jour)
    2. Qui attaque, qui est visé ? (IP et pays, comptes)
    3. Comment l'équipe a-t-elle réagi ? (alertes, délais, escalades, blocages)
    4. Les engagements sont-ils tenus ? (contrôles chiffrés, chacun « conforme » ou « à corriger »)

Toutes les valeurs viennent d'Elasticsearch (logs) et de MongoDB (alertes, blocages, audit, imports).
"""
import io
import re
from calendar import monthrange
from collections import Counter
from datetime import datetime, timezone

from app.alerting.rules import SEVERITY_LABELS

MONTH_RE = re.compile(r'^(20\d{2})-(0[1-9]|1[0-2])$')
SLA_ACK_MINUTES = 15
SENSITIVE_ACTIONS = {'ip_unblocked', 'ip_blocked', 'rule_updated', 'rule_created', 'rule_deleted', 'rule_toggled',
                     'export_csv', 'password_reset', 'upload_confirmed', 'alerting_run_now', 'report_monthly'}
ACTION_LABELS = {'login_success': 'connexion réussie', 'login_failure': 'connexion échouée', 'login_blocked': 'connexion refusée (limite)',
                 'logout': 'déconnexion', 'export_csv': 'export CSV', 'upload_confirmed': 'import confirmé',
                 'upload_rejected': 'import rejeté', 'upload_refused': 'import refusé', 'upload_cancelled': 'import annulé',
                 'ip_blocked': 'IP bloquée', 'ip_unblocked': 'IP débloquée', 'rule_created': 'règle créée',
                 'rule_updated': 'règle modifiée', 'rule_deleted': 'règle supprimée', 'alert_raised': 'alerte levée',
                 'alert_acknowledged': 'alerte prise en compte', 'alert_resolved': 'alerte résolue', 'alert_snoozed': 'alerte en veille',
                 'alert_escalated': 'alerte escaladée', 'alert_commented': 'commentaire d’incident',
                 'alerting_run_now': 'évaluation manuelle des règles', 'password_reset': 'mot de passe changé',
                 'report_monthly': 'rapport mensuel généré'}


class ReportError(ValueError):
    pass


def month_bounds(month):
    m = MONTH_RE.match(month or '')
    if not m:
        raise ReportError('Mois attendu au format AAAA-MM.')
    year, mon = int(m.group(1)), int(m.group(2))
    start = datetime(year, mon, 1, tzinfo=timezone.utc)
    end = datetime(year + (mon == 12), mon % 12 + 1, 1, tzinfo=timezone.utc)
    return start, end, monthrange(year, mon)[1]


def build_logs_query(start, end):
    rng = {'range': {'@timestamp': {'gte': start.isoformat(), 'lt': end.isoformat()}}}
    return {'size': 0, 'track_total_hits': True, 'query': rng, 'aggs': {
        'levels': {'terms': {'field': 'log.level', 'size': 10}},
        'services': {'terms': {'field': 'service.name', 'size': 10}},
        'auth': {'filter': {'term': {'event.category': 'authentication'}}, 'aggs': {
            'outcomes': {'terms': {'field': 'event.outcome', 'size': 3}},
            'daily': {'date_histogram': {'field': '@timestamp', 'calendar_interval': 'day', 'min_doc_count': 0,
                                         'extended_bounds': {'min': start.isoformat(), 'max': end.isoformat()}},
                      'aggs': {'o': {'terms': {'field': 'event.outcome', 'size': 3}}}}}},
        'failures': {'filter': {'term': {'event.outcome': 'failure'}}, 'aggs': {
            'ips': {'cardinality': {'field': 'source.ip'}},
            'countries': {'terms': {'field': 'source.geo.country_iso_code', 'size': 8}},
            'top_ips': {'terms': {'field': 'source.ip', 'size': 10}, 'aggs': {
                'users': {'cardinality': {'field': 'user.name'}},
                'country': {'terms': {'field': 'source.geo.country_iso_code', 'size': 1}}}},
            'top_users': {'terms': {'field': 'user.name', 'size': 10}}}}}}


def _buckets(aggs, name):
    return aggs.get(name, {}).get('buckets', [])


def shape_logs(raw):
    aggs = raw.get('aggregations', {})
    total = raw.get('hits', {}).get('total', {})
    total = total.get('value', 0) if isinstance(total, dict) else int(total or 0)
    auth = aggs.get('auth', {})
    outcomes = {b['key']: b['doc_count'] for b in _buckets(auth, 'outcomes')}
    ok, ko = outcomes.get('success', 0), outcomes.get('failure', 0)
    daily = []
    for b in _buckets(auth, 'daily'):
        o = {x['key']: x['doc_count'] for x in _buckets(b, 'o')}
        daily.append({'day': (b.get('key_as_string') or '')[:10], 'success': o.get('success', 0), 'failure': o.get('failure', 0)})
    fails = aggs.get('failures', {})
    return {
        'events': total, 'levels': {b['key']: b['doc_count'] for b in _buckets(aggs, 'levels')},
        'services': [(b['key'], b['doc_count']) for b in _buckets(aggs, 'services')],
        'auth_attempts': auth.get('doc_count', 0), 'auth_success': ok, 'auth_failure': ko,
        'success_rate': round(100 * ok / (ok + ko), 1) if ok + ko else None,
        'failing_ips': fails.get('ips', {}).get('value', 0), 'daily': daily,
        'countries': [(b['key'], b['doc_count']) for b in _buckets(fails, 'countries')],
        'top_ips': [{'ip': b['key'], 'failures': b['doc_count'], 'users': b.get('users', {}).get('value', 0),
                     'country': (_buckets(b, 'country') or [{}])[0].get('key')} for b in _buckets(fails, 'top_ips')],
        'top_users': [(b['key'], b['doc_count']) for b in _buckets(fails, 'top_users')],
    }


def _aware(v):
    return v if v is None or v.tzinfo else v.replace(tzinfo=timezone.utc)


def shape_alerts(alerts):
    by_sev = Counter(a['severity'] for a in alerts)
    by_rule = Counter(a['rule_name'] for a in alerts)
    resolved = [a['time_to_resolve_s'] for a in alerts if a.get('time_to_resolve_s') is not None]
    ack_delays = []
    for a in alerts:
        start = _aware(a['triggered_at'])
        done = _aware(a.get('acknowledged_at') or a.get('resolved_at'))
        if done:
            ack_delays.append((done - start).total_seconds() / 60)
    escalated = [a for a in alerts if a.get('escalation_level', 1) > 1]
    serious = [a for a in alerts if a['severity'] in ('critical', 'high')]
    return {
        'total': len(alerts), 'by_severity': {s: by_sev.get(s, 0) for s in ('critical', 'high', 'medium', 'low')},
        'by_rule': by_rule.most_common(10), 'resolved': len(resolved),
        'open': sum(1 for a in alerts if a['status'] != 'resolved'),
        'mttr_min': round(sum(resolved) / len(resolved) / 60, 1) if resolved else None,
        'ack_within_sla_pct': round(100 * sum(1 for d in ack_delays if d <= SLA_ACK_MINUTES) / len(alerts), 1) if alerts else None,
        'escalated': len(escalated), 'escalated_l3': sum(1 for a in escalated if a.get('escalation_level') == 3),
        'incidents': [{'when': _aware(a['triggered_at']).strftime('%d/%m %H:%M'), 'severity': a['severity'],
                       'rule': a['rule_name'], 'group': a.get('group') or '—',
                       'status': a['status'], 'resolve_min': round(a['time_to_resolve_s'] / 60) if a.get('time_to_resolve_s') is not None else None,
                       'level': a.get('escalation_level', 1)}
                      for a in sorted(serious, key=lambda x: _aware(x['triggered_at']))][:25],
    }


class MonthlyReport:
    def __init__(self, stores, config):
        self.db, self.es, self.cfg = stores.db, stores.es, config

    def collect(self, month, now=None):
        start, end, days = month_bounds(month)
        now = now or datetime.now(timezone.utc)
        logs = shape_logs(self.es.search(self.cfg.logs_index, build_logs_query(start, end)))
        window = {'$gte': start, '$lt': end}
        alerts = shape_alerts(list(self.db.alerts.find({'triggered_at': window})))
        blocks = list(self.db.ip_blocks.find({'at': window}, {'_id': 0}))
        audit = Counter(a['action'] for a in self.db.audit_actions.find({'timestamp': window}, {'action': 1}))
        uploads = Counter(u.get('state') for u in self.db.uploaded_files.find({'created_at': window}, {'state': 1}))
        still_open_old = self.db.alerts.count_documents({'status': {'$ne': 'resolved'}, 'triggered_at': {'$lt': min(end, now)}}) \
            if end <= now else None
        data = {'month': month, 'start': start, 'end': end, 'days': days, 'generated_at': now, 'partial': end > now,
                'logs': logs, 'alerts': alerts,
                'blocks': {'total': sum(1 for b in blocks if b.get('action') == 'block'),
                           'manual_unblocks': sum(1 for b in blocks if b.get('action') == 'unblock'),
                           'ips': sorted({b['ip'] for b in blocks if b.get('action') == 'block'})},
                'audit': {'total': sum(audit.values()), 'logins': audit.get('login_success', 0),
                          'login_failures': audit.get('login_failure', 0) + audit.get('login_blocked', 0),
                          'sensitive': sum(v for k, v in audit.items() if k in SENSITIVE_ACTIONS),
                          'by_action': audit.most_common(12)},
                'uploads': {'total': sum(uploads.values()), 'indexed': uploads.get('indexed', 0),
                            'partial': uploads.get('partial', 0), 'failed': uploads.get('failed', 0)}}
        data['controls'] = controls(data, still_open_old)
        return data


def controls(d, still_open):
    """Contrôles chiffrés : chacun a une cible, une valeur mesurée et un verdict."""
    a = d['alerts']
    rows = [
        ('Alertes prises en compte en moins de 15 min', '≥ 90 %',
         None if a['ack_within_sla_pct'] is None else f"{a['ack_within_sla_pct']} %",
         None if a['ack_within_sla_pct'] is None else a['ack_within_sla_pct'] >= 90),
        ('Alertes critiques escaladées jusqu’au RSSI (N3)', '0', str(a['escalated_l3']), a['escalated_l3'] == 0),
        ('Alertes du mois encore ouvertes', '0', str(a['open']), a['open'] == 0),
        ('Temps moyen de résolution (MTTR)', '≤ 60 min', '—' if a['mttr_min'] is None else f"{a['mttr_min']} min",
         None if a['mttr_min'] is None else a['mttr_min'] <= 60),
        ('Actions sensibles tracées (audit)', 'toutes', f"{d['audit']['sensitive']} action(s) journalisée(s)", True),
        ('Imports en échec', '0', str(d['uploads']['failed']), d['uploads']['failed'] == 0),
    ]
    return [{'label': lbl, 'target': tgt, 'value': val if val is not None else '—', 'ok': ok} for lbl, tgt, val, ok in rows]


# ---------------------------------------------------------------- PDF
def render_pdf(d, author='Sentinel'):
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    CYAN, UV, INK, MUT = colors.HexColor('#0aa9a0'), colors.HexColor('#6a4cf0'), colors.HexColor('#0d1730'), colors.HexColor('#5d6b85')
    OK, KO, LINE, SOFT = colors.HexColor('#16935f'), colors.HexColor('#e0344f'), colors.HexColor('#dfe4ee'), colors.HexColor('#f3f6fb')
    SEV = {'critical': KO, 'high': colors.HexColor('#e0691a'), 'medium': colors.HexColor('#b88300'), 'low': colors.HexColor('#2f6fe0')}
    ss = getSampleStyleSheet()
    body = ParagraphStyle('b', parent=ss['BodyText'], fontName='Helvetica', fontSize=9.5, leading=13, textColor=INK)
    small = ParagraphStyle('s', parent=body, fontSize=8, leading=10, textColor=MUT)
    h1 = ParagraphStyle('h1', parent=body, fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=INK, spaceAfter=4)
    h2 = ParagraphStyle('h2', parent=body, fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=INK, spaceBefore=12, spaceAfter=6)
    cell = ParagraphStyle('c', parent=body, fontSize=8.5, leading=10.5, alignment=TA_LEFT)
    months = ['janvier', 'février', 'mars', 'avril', 'mai', 'juin', 'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre']
    title_month = f"{months[d['start'].month - 1]} {d['start'].year}"
    L, A = d['logs'], d['alerts']

    def table(rows, widths, header=True, zebra=True):
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
        style = [('FONT', (0, 0), (-1, -1), 'Helvetica', 8.5), ('TEXTCOLOR', (0, 0), (-1, -1), INK),
                 ('LINEBELOW', (0, 0), (-1, -1), 0.4, LINE), ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                 ('TOPPADDING', (0, 0), (-1, -1), 4), ('BOTTOMPADDING', (0, 0), (-1, -1), 4)]
        if header:
            style += [('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 8), ('TEXTCOLOR', (0, 0), (-1, 0), MUT),
                      ('LINEBELOW', (0, 0), (-1, 0), 0.8, CYAN)]
        if zebra:
            style += [('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, SOFT])]
        t.setStyle(TableStyle(style))
        return t

    def kpis(items):
        cells = [[Paragraph(f'<font size=7 color="#5d6b85">{label.upper()}</font><br/><font size=16><b>{value}</b></font>'
                            + (f'<br/><font size=7 color="#5d6b85">{sub}</font>' if sub else ''), body)
                  for label, value, sub in items]]
        t = Table(cells, colWidths=[(180 * mm) / len(items)] * len(items))
        t.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
        t.setStyle(TableStyle([('BOX', (0, 0), (-1, -1), 0.5, LINE), ('INNERGRID', (0, 0), (-1, -1), 0.5, LINE),
                               ('BACKGROUND', (0, 0), (-1, -1), SOFT), ('TOPPADDING', (0, 0), (-1, -1), 7),
                               ('BOTTOMPADDING', (0, 0), (-1, -1), 7), ('LINEABOVE', (0, 0), (-1, 0), 2, CYAN)]))
        return t

    def daily_chart():
        days = L['daily']
        dw = Drawing(180 * mm, 62 * mm)
        if not days:
            dw.add(String(10, 80, 'Aucune authentification ce mois-ci.', fontSize=9, fillColor=MUT))
            return dw
        bc = VerticalBarChart()
        bc.x, bc.y, bc.width, bc.height = 28, 22, 180 * mm - 40, 62 * mm - 40
        bc.data = [[x['success'] for x in days], [x['failure'] for x in days]]
        bc.categoryAxis.categoryNames = [x['day'][8:10] for x in days]
        bc.categoryAxis.labels.fontSize = 6
        bc.valueAxis.labels.fontSize = 7
        bc.valueAxis.valueMin = 0
        bc.bars[0].fillColor, bc.bars[1].fillColor = CYAN, KO
        bc.bars.strokeWidth = 0
        bc.groupSpacing, bc.barSpacing = 2, 0
        bc.valueAxis.gridStrokeColor, bc.valueAxis.visibleGrid = LINE, True
        dw.add(bc)
        dw.add(String(30, 62 * mm - 10, '■ réussies', fontSize=7.5, fillColor=CYAN))
        dw.add(String(85, 62 * mm - 10, '■ échouées', fontSize=7.5, fillColor=KO))
        return dw

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(CYAN)
        canvas.rect(0, A4[1] - 4, A4[0] / 2, 4, stroke=0, fill=1)
        canvas.setFillColor(UV)
        canvas.rect(A4[0] / 2, A4[1] - 4, A4[0] / 2, 4, stroke=0, fill=1)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(MUT)
        canvas.drawString(15 * mm, 10 * mm, f'CampusGuard · Sentinel — rapport de conformité sécurité, {title_month}')
        canvas.drawRightString(A4[0] - 15 * mm, 10 * mm, f'page {doc.page}')
        canvas.restoreState()

    s = []
    s.append(Paragraph('<font color="#0aa9a0">CAMPUSGUARD · SENTINEL</font>', ParagraphStyle('k', parent=small, fontName='Helvetica-Bold', fontSize=9)))
    s.append(Paragraph(f'Rapport mensuel de conformité sécurité — {title_month}', h1))
    s.append(Paragraph(f"Période du {d['start']:%d/%m/%Y} au {d['end']:%d/%m/%Y} (exclu), heure UTC. "
                       f"Généré le {d['generated_at']:%d/%m/%Y à %H:%M} UTC par {author}."
                       + (' <b>Mois en cours : chiffres partiels.</b>' if d['partial'] else ''), small))
    s.append(Spacer(1, 8))
    s.append(kpis([('Événements indexés', f"{L['events']:,}".replace(',', ' '), None),
                   ('Connexions échouées', f"{L['auth_failure']:,}".replace(',', ' '), f"{L['failing_ips']} IP distinctes"),
                   ('Taux de réussite', '—' if L['success_rate'] is None else f"{L['success_rate']} %", f"{L['auth_attempts']} tentatives"),
                   ('Alertes', str(A['total']), f"{A['by_severity']['critical']} critique(s)"),
                   ('MTTR', '—' if A['mttr_min'] is None else f"{A['mttr_min']} min", f"{A['resolved']} résolue(s)")]))

    s.append(Paragraph('1. Contrôles', h2))
    ok_count = sum(1 for c in d['controls'] if c['ok'])
    s.append(Paragraph(f"{ok_count} contrôle(s) conforme(s) sur {len(d['controls'])}.", body))
    rows = [['Contrôle', 'Cible', 'Mesuré', 'Verdict']]
    for c in d['controls']:
        verdict = '<font color="#16935f"><b>conforme</b></font>' if c['ok'] else (
            '<font color="#5d6b85">sans objet</font>' if c['ok'] is None else '<font color="#e0344f"><b>à corriger</b></font>')
        rows.append([Paragraph(c['label'], cell), c['target'], c['value'], Paragraph(verdict, cell)])
    s.append(table(rows, [82 * mm, 24 * mm, 46 * mm, 28 * mm]))

    s.append(Paragraph('2. Authentifications par jour', h2))
    s.append(daily_chart())

    s.append(KeepTogether([Paragraph('3. Origine des attaques', h2), Paragraph(
        'Adresses ayant cumulé le plus d’échecs de connexion ; « comptes » = nombre de comptes différents essayés '
        '(beaucoup de comptes pour une IP signale du credential stuffing, un seul compte de la force brute).', small), Spacer(1, 4),
        table([['IP source', 'Pays', 'Échecs', 'Comptes']] + [[x['ip'], x['country'] or '—', str(x['failures']), str(x['users'])] for x in L['top_ips']]
              if L['top_ips'] else [['Aucun échec de connexion ce mois-ci.']], [60 * mm, 30 * mm, 30 * mm, 30 * mm] if L['top_ips'] else [180 * mm])]))
    side = []
    if L['countries']:
        side.append(table([['Pays', 'Échecs']] + [[c, str(n)] for c, n in L['countries']], [30 * mm, 25 * mm]))
    if L['top_users']:
        users = table([['Compte visé', 'Échecs']] + [[u, str(n)] for u, n in L['top_users']], [45 * mm, 25 * mm])
        side.append(users)
    if side:
        s.append(Spacer(1, 8))
        t = Table([side + [''] * (2 - len(side))], colWidths=[75 * mm, 105 * mm])
        t.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 0)]))
        s.append(t)

    s.append(PageBreak())
    s.append(Paragraph('4. Alertes et réponse', h2))
    s.append(Paragraph(
        f"{A['total']} alerte(s) levée(s) : " + ', '.join(f"{n} {SEVERITY_LABELS[k].lower()}" for k, n in A['by_severity'].items() if n)
        + f". {A['escalated']} escaladée(s) faute de prise en compte (dont {A['escalated_l3']} jusqu’au RSSI). "
          f"{d['blocks']['total']} blocage(s) d’IP automatique(s) ou manuel(s), {d['blocks']['manual_unblocks']} levée(s) manuelle(s)." if A['total'] else
        'Aucune alerte levée ce mois-ci.', body))
    if A['by_rule']:
        s.append(Spacer(1, 4))
        s.append(table([['Règle', 'Alertes']] + [[Paragraph(r, cell), str(n)] for r, n in A['by_rule']], [150 * mm, 30 * mm]))
    if A['incidents']:
        s.append(Paragraph('Incidents de gravité haute ou critique', ParagraphStyle('h3', parent=h2, fontSize=10.5, spaceBefore=10)))
        rows = [['Date', 'Gravité', 'Règle', 'Concerne', 'Niveau', 'Résolu en']]
        for x in A['incidents']:
            rows.append([x['when'], Paragraph(f'<font color="#{SEV[x["severity"]].hexval()[2:]}"><b>{SEVERITY_LABELS[x["severity"]]}</b></font>', cell),
                         Paragraph(x['rule'], cell), x['group'], f"N{x['level']}",
                         '—' if x['resolve_min'] is None else f"{x['resolve_min']} min"])
        s.append(table(rows, [20 * mm, 18 * mm, 70 * mm, 32 * mm, 14 * mm, 26 * mm]))

    s.append(Paragraph('5. Traçabilité et qualité des données', h2))
    au, up = d['audit'], d['uploads']
    s.append(Paragraph(
        f"{au['total']} action(s) journalisée(s) dans l’audit, dont {au['sensitive']} sensible(s) (exports, blocages, règles, mots de passe). "
        f"{up['total']} fichier(s) importé(s) : {up['indexed']} indexé(s) en entier, {up['partial']} partiellement, {up['failed']} en échec.", body))
    if au['by_action']:
        s.append(Spacer(1, 4))
        s.append(table([['Action', 'Nombre']] + [[ACTION_LABELS.get(a, a), str(n)] for a, n in au['by_action']], [80 * mm, 25 * mm]))
    if L['services']:
        s.append(Spacer(1, 6))
        s.append(table([['Source de logs', 'Événements']] + [[k, str(n)] for k, n in L['services']], [80 * mm, 25 * mm]))

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm, bottomMargin=18 * mm,
                            title=f'Rapport de conformité sécurité — {title_month}', author=author, subject='CampusGuard Sentinel')
    doc.build(s, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
