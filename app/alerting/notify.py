"""Alert notifications: e-mail (SMTP, HTML template + PNG chart + link) and webhook (generic, Slack, Discord,
Microsoft Teams or a custom JSON template) with automatic retry and exponential back-off.

In the laboratory, e-mails go to Mailpit (a local SMTP catcher, web UI on http://localhost:8025) and the
default webhook targets the application's own demo receiver (/hooks/demo/<token>): nothing leaves the machine.
Every attempt is recorded on the alert (channel, status, attempts, last error) so a failed delivery is visible.
"""
import json
import os
import smtplib
import struct
import time
import zlib
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlencode

import requests
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.alerting.rules import SEVERITY_LABELS

_TEMPLATES = Environment(loader=FileSystemLoader(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'templates', 'email')),
                         autoescape=select_autoescape(['html']))
SEVERITY_COLORS = {'low': (42, 111, 214), 'medium': (168, 117, 0), 'high': (217, 98, 15), 'critical': (217, 45, 52)}


# ---------------------------------------------------------------- tiny PNG bar chart (no extra dependency)
def png_bar_chart(values, color=(217, 45, 52), width=600, height=180, pad=12):
    """Bars for ``values`` as a PNG (bytes). Pure Python: zlib + struct, enough for an e-mail attachment."""
    values = list(values) or [0]
    top = max(values) or 1
    pixels = [[(255, 255, 255)] * width for _ in range(height)]
    for y in range(pad, height - pad, max(1, (height - 2 * pad) // 4)):      # light grid lines
        for x in range(pad, width - pad):
            pixels[y][x] = (235, 239, 245)
    n = len(values)
    slot = (width - 2 * pad) / n
    bar = max(1, int(slot * 0.7))
    for i, v in enumerate(values):
        h = int((height - 2 * pad) * v / top)
        x0 = int(pad + i * slot + (slot - bar) / 2)
        for y in range(height - pad - h, height - pad):
            row = pixels[y]
            for x in range(x0, min(width - pad, x0 + bar)):
                row[x] = color
    for x in range(pad, width - pad):                                          # baseline
        pixels[height - pad][x] = (100, 114, 139)
    raw = b''.join(b'\x00' + bytes(c for px in row for c in px) for row in pixels)

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))


def search_link(cfg, alert):
    params = {}
    if alert.get('group_field') == 'source.ip':
        params['ip'] = alert['group']
    elif alert.get('group_field') == 'user.name':
        params['user'] = alert['group']
    elif alert.get('group_field') == 'service.name':
        params['service'] = alert['group']
    if alert.get('first_seen'):
        params['start'] = alert['first_seen'][:10]
    return f"{cfg.app_public_url}/search?{urlencode(params)}" if params else f'{cfg.app_public_url}/search'


def alert_link(cfg, alert):
    return f"{cfg.app_public_url}/alerts#alert-{alert['_id']}"


# ---------------------------------------------------------------- payloads
def _context(cfg, alert):
    return {'alert': alert, 'severity': SEVERITY_LABELS.get(alert['severity'], alert['severity']),
            'search_url': search_link(cfg, alert), 'alert_url': alert_link(cfg, alert)}


def webhook_payload(cfg, alert, fmt=None, template=None):
    fmt = fmt or cfg.webhook_format
    template = cfg.webhook_template if template is None else template
    ctx = _context(cfg, alert)
    title = f"[{ctx['severity']}] {alert['rule_name']}"
    text = f"{title} — {alert['message']}"
    if template:
        values = {'rule': alert['rule_name'], 'severity': alert['severity'], 'group': alert['group'],
                  'count': str(alert['count']), 'message': alert['message'], 'link': ctx['alert_url'],
                  'search': ctx['search_url'], 'id': alert['_id']}
        out = template
        for key, value in values.items():
            out = out.replace('${' + key + '}', json.dumps(str(value))[1:-1])     # JSON-escaped, quotes provided by the template
        return json.loads(out)
    if fmt == 'slack':
        return {'text': text, 'blocks': [
            {'type': 'section', 'text': {'type': 'mrkdwn', 'text': f"*{title}*\n{alert['message']}"}},
            {'type': 'context', 'elements': [{'type': 'mrkdwn', 'text': f"<{ctx['alert_url']}|Voir l’alerte> · <{ctx['search_url']}|Logs>"}]}]}
    if fmt == 'discord':
        r, g, b = SEVERITY_COLORS.get(alert['severity'], (100, 100, 100))
        return {'content': title, 'embeds': [{'title': alert['rule_name'], 'description': alert['message'],
                                              'url': ctx['alert_url'], 'color': (r << 16) + (g << 8) + b}]}
    if fmt == 'teams':
        return {'@type': 'MessageCard', '@context': 'https://schema.org/extensions', 'summary': title,
                'themeColor': '%02X%02X%02X' % SEVERITY_COLORS.get(alert['severity'], (100, 100, 100)),
                'title': title, 'text': alert['message'],
                'potentialAction': [{'@type': 'OpenUri', 'name': 'Voir l’alerte', 'targets': [{'os': 'default', 'uri': ctx['alert_url']}]}]}
    return {'id': alert['_id'], 'rule': alert['rule_id'], 'rule_name': alert['rule_name'], 'severity': alert['severity'],
            'group_field': alert.get('group_field'), 'group': alert['group'], 'count': alert['count'],
            'message': alert['message'], 'triggered_at': alert['triggered_at'], 'link': ctx['alert_url'],
            'search': ctx['search_url'], 'response': alert.get('response')}


def email_message(cfg, alert, chart_png=None):
    ctx = _context(cfg, alert)
    msg = EmailMessage()
    msg['Subject'] = f"[Sentinel][{ctx['severity']}] {alert['rule_name']} — {alert['group']}"
    msg['From'] = cfg.smtp_from
    msg['To'] = cfg.alert_email_to
    msg.set_content(f"{alert['rule_name']}\n{alert['message']}\n\nAlerte : {ctx['alert_url']}\nLogs : {ctx['search_url']}\n")
    msg.add_alternative(_TEMPLATES.get_template('alert.html').render(**ctx, has_chart=bool(chart_png)), subtype='html')
    if chart_png:
        msg.add_attachment(chart_png, maintype='image', subtype='png', filename='evenements.png')
    return msg


# ---------------------------------------------------------------- delivery with retry
class Notifier:
    def __init__(self, cfg, http=None, smtp_factory=None, sleep=time.sleep):
        self.cfg = cfg
        self.http = http or requests
        self.smtp_factory = smtp_factory or (lambda: smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=10))
        self.sleep = sleep

    def _retry(self, channel, send):
        attempts, error = 0, None
        for attempt in range(1, max(1, self.cfg.notify_retries) + 1):
            attempts = attempt
            try:
                send()
                return {'channel': channel, 'status': 'sent', 'attempts': attempts, 'error': None,
                        'at': datetime.now(timezone.utc).isoformat()}
            except Exception as exc:  # noqa: BLE001 - any delivery failure is retried then recorded
                error = f'{exc.__class__.__name__}: {str(exc)[:160]}'
                if attempt < self.cfg.notify_retries:
                    self.sleep(2 ** (attempt - 1))          # 1 s, 2 s, 4 s…
        return {'channel': channel, 'status': 'failed', 'attempts': attempts, 'error': error,
                'at': datetime.now(timezone.utc).isoformat()}

    def email(self, alert, chart_png=None):
        if not self.cfg.smtp_host:
            return {'channel': 'email', 'status': 'skipped', 'attempts': 0, 'error': 'SMTP_HOST non configuré',
                    'at': datetime.now(timezone.utc).isoformat()}
        msg = email_message(self.cfg, alert, chart_png)

        def send():
            with self.smtp_factory() as smtp:
                smtp.send_message(msg)
        return self._retry('email', send)

    def webhook(self, alert):
        if not self.cfg.webhook_url:
            return {'channel': 'webhook', 'status': 'skipped', 'attempts': 0, 'error': 'ALERT_WEBHOOK_URL non configuré',
                    'at': datetime.now(timezone.utc).isoformat()}
        payload = webhook_payload(self.cfg, alert)

        def send():
            response = self.http.post(self.cfg.webhook_url, json=payload, timeout=5)
            if response.status_code >= 400:
                raise RuntimeError(f'HTTP {response.status_code}')
        return self._retry('webhook', send)
