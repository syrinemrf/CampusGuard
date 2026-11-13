"""Ships the web application's own authentication events to Logstash (HTTP input, json-security pipeline).

The CampusGuard login page is itself a monitored « laboratory service »: its failed / successful logins
go through the same pipeline as any other source (validation, GeoIP, fingerprint) into ``logs-auth-*``.
The alerting worker can then detect a brute force against it and the blocklist protects it: a complete,
real loop (attack -> logs -> detection -> alert -> local block) without any simulated shortcut.

Best effort: a Logstash outage never blocks a login (short timeout, background thread, error logged).
"""
import logging
import threading
from datetime import datetime, timezone

import requests

log = logging.getLogger('sentinel.auth_events')


def build_event(action, outcome, ip, username, reason=None):
    level = 'INFO' if outcome == 'success' else 'WARNING'
    text = {'login': 'Connexion réussie' if outcome == 'success' else 'Échec de connexion',
            'login_blocked': 'Connexion refusée (trop de tentatives)'}.get(action, action)
    message = f"{text} pour {username or '(vide)'} depuis {ip} sur l'application CampusGuard"
    if reason:
        message += f' ({reason})'
    return {'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            'source_ip': ip, 'username': username or 'unknown', 'outcome': outcome, 'action': action,
            'level': level, 'message': message, 'service': {'name': 'campusguard-web'},
            'event': {'category': 'authentication'}, 'labels': {'provenance': 'campusguard-web'}}


def ship(app, event):
    cfg = app.extensions['sentinel_config']
    http = app.extensions.get('sentinel_http')
    if not cfg.ship_auth_events or (cfg.testing and http is None):
        return
    http = http or requests

    def send():
        try:
            http.post(cfg.logstash_http_url, json=event, timeout=2)
        except Exception as exc:  # noqa: BLE001 - shipping must never break a login
            log.warning('auth event not shipped to Logstash: %s', exc.__class__.__name__)
    if cfg.testing:
        send()
    else:
        threading.Thread(target=send, daemon=True).start()
