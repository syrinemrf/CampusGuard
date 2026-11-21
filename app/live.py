"""Temps réel (S5, module H) : diffusion WebSocket des logs et des alertes, métriques en direct.

Chemin d'un événement :
    sshd → fichier → Filebeat → Kafka → Logstash → Elasticsearch, puis Redis Pub/Sub ``sentinel:live:logs``
    worker d'alertes → Redis Pub/Sub ``sentinel:live:alerts``
    → ce module (abonné Redis) → WebSocket ``/ws/live`` → page « Temps réel ».

Aucune interrogation périodique côté navigateur : le serveur pousse les événements dès leur publication.
Les métriques sont calculées sur le flux reçu par la connexion (débit, erreurs, latence) et dans Redis pour ce qui
concerne toute l'application (requêtes en cours, utilisateurs connectés, écrans « Temps réel » ouverts).
"""
import json
import logging
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

log = logging.getLogger('sentinel.live')

LOGS_CHANNEL = 'sentinel:live:logs'
ALERTS_CHANNEL = 'sentinel:live:alerts'
INFLIGHT_KEY = 'sentinel:metrics:inflight'      # zset requête → horodatage (requêtes HTTP en cours)
USERS_KEY = 'sentinel:metrics:users'            # zset utilisateur → dernière activité
CLIENTS_KEY = 'sentinel:live:clients'           # zset connexion WebSocket → dernier battement
LATENCY_KEY = 'sentinel:metrics:latency'        # liste des dernières latences mesurées (ms)
USER_WINDOW_S = 300
BATCH_S = 0.25
METRICS_EVERY_S = 1.0
ERROR_LEVELS = frozenset({'ERROR', 'CRITICAL'})


def _get(doc, dotted):
    for part in dotted.split('.'):
        if not isinstance(doc, dict):
            return None
        doc = doc.get(part)
    return doc


def _epoch_ms(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp() * 1000
    except ValueError:
        return None


def shape_log(raw, now_ms=None):
    """Document Logstash → ligne compacte pour l'écran. ``latency_ms`` : écriture de la ligne → réception ici."""
    now_ms = now_ms if now_ms is not None else time.time() * 1000
    stamp = raw.get('@timestamp')
    emitted = _epoch_ms(stamp)
    level = str(_get(raw, 'log.level') or 'INFO').upper()
    return {
        'ts': stamp, 'level': level, 'service': _get(raw, 'service.name') or '—',
        'ip': _get(raw, 'source.ip'), 'country': _get(raw, 'source.geo.country_iso_code'),
        'user': _get(raw, 'user.name'), 'action': _get(raw, 'event.action'), 'outcome': _get(raw, 'event.outcome'),
        'message': str(raw.get('message') or '')[:600],
        'latency_ms': round(now_ms - emitted) if emitted is not None else None,
        'ingest_ms': _get(raw, 'event.ingest_lag_ms'),
        'transport': _get(raw, 'labels.transport'),
    }


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return round(ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo))


class StreamStats:
    """Débit et erreurs sur fenêtres glissantes, latences des 500 derniers événements."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.events = deque()            # (t, est_erreur)
        self.latencies = deque(maxlen=500)
        self.total = 0

    def add(self, item):
        self.events.append((self.clock(), item['level'] in ERROR_LEVELS))
        self.total += 1
        if item.get('latency_ms') is not None and 0 <= item['latency_ms'] < 600_000:
            self.latencies.append(item['latency_ms'])

    def snapshot(self):
        now = self.clock()
        while self.events and self.events[0][0] < now - 60:
            self.events.popleft()
        last10 = sum(1 for t, _ in self.events if t >= now - 10)
        lat = list(self.latencies)
        return {'logs_per_s': round(last10 / 10, 1), 'errors_per_min': sum(1 for _, e in self.events if e),
                'events_last_min': len(self.events), 'received': self.total,
                'latency_p50_ms': percentile(lat, .5), 'latency_p95_ms': percentile(lat, .95)}


# ---------------------------------------------------------------- compteurs globaux (Redis)
def request_started(redis, username=None):
    token = uuid.uuid4().hex
    now = time.time()
    try:
        pipe = redis.pipeline()
        pipe.zadd(INFLIGHT_KEY, {token: now})
        if username:
            pipe.zadd(USERS_KEY, {username: now})
        pipe.execute()
    except Exception:  # noqa: BLE001 - une métrique ne doit jamais faire échouer une requête
        return None
    return token


def request_finished(redis, token):
    if token:
        try:
            redis.zrem(INFLIGHT_KEY, token)
        except Exception:  # noqa: BLE001
            pass


def platform_metrics(redis, now=None):
    now = now or time.time()
    try:
        pipe = redis.pipeline()
        pipe.zremrangebyscore(INFLIGHT_KEY, 0, now - 60)       # requête interrompue sans « finished »
        pipe.zcard(INFLIGHT_KEY)
        pipe.zcount(USERS_KEY, now - USER_WINDOW_S, '+inf')
        pipe.zremrangebyscore(CLIENTS_KEY, 0, now - 15)
        pipe.zcard(CLIENTS_KEY)
        _, inflight, users, _, clients = pipe.execute()
    except Exception:  # noqa: BLE001
        return {'active_requests': None, 'connected_users': None, 'live_viewers': None}
    return {'active_requests': int(inflight), 'connected_users': int(users), 'live_viewers': int(clients)}


def same_origin(origin, host):
    """Protection contre le détournement de WebSocket entre sites : l'Origin doit être l'hôte de l'application."""
    if not origin:
        return False
    return urlparse(origin).netloc == host


def publish_alert(redis, alert):
    """Appelé par le worker : l'alerte apparaît immédiatement sur les écrans ouverts."""
    keep = ('id', 'rule_id', 'rule_name', 'severity', 'severity_label', 'group', 'group_field', 'count',
            'message', 'triggered_at', 'status', 'escalation_level')
    try:
        redis.publish(ALERTS_CHANNEL, json.dumps({k: alert.get(k) for k in keep}, default=str, ensure_ascii=False))
    except Exception as exc:  # noqa: BLE001
        log.warning('alert not published live: %s', exc)


# ---------------------------------------------------------------- boucle d'une connexion
class Closed(Exception):
    pass


def serve(ws, redis, username, clock=time.time, max_seconds=None, receive=None):
    """Relaie Redis Pub/Sub vers une WebSocket. ``ws`` expose ``send(str)`` et ``receive(timeout)``.

    Les lignes sont regroupées par paquets de 250 ms (une rafale de 1 000 lignes ne fait pas 1 000 envois) ;
    un message de métriques part chaque seconde, ce qui sert aussi de battement de cœur à l'indicateur de connexion.
    """
    conn_id = uuid.uuid4().hex
    stats = StreamStats(clock)
    pubsub = redis.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(LOGS_CHANNEL, ALERTS_CHANNEL)
    batch, started = [], clock()
    last_flush = last_metrics = 0.0
    receive = receive or (lambda: ws.receive(timeout=0))
    ws.send(json.dumps({'type': 'hello', 'user': username, 'channels': [LOGS_CHANNEL, ALERTS_CHANNEL]}))
    try:
        while max_seconds is None or clock() - started < max_seconds:
            msg = pubsub.get_message(timeout=0.1)
            if msg and msg.get('type') == 'message':
                channel = msg['channel'].decode() if isinstance(msg['channel'], bytes) else msg['channel']
                try:
                    data = json.loads(msg['data'])
                except (TypeError, ValueError):
                    data = None
                if isinstance(data, dict) and channel == LOGS_CHANNEL:
                    item = shape_log(data, clock() * 1000)
                    stats.add(item)
                    batch.append(item)
                    if item['latency_ms'] is not None:
                        redis.lpush(LATENCY_KEY, item['latency_ms'])
                        redis.ltrim(LATENCY_KEY, 0, 999)
                elif isinstance(data, dict) and channel == ALERTS_CHANNEL:
                    ws.send(json.dumps({'type': 'alert', 'alert': data}, ensure_ascii=False))
            now = clock()
            if batch and (now - last_flush >= BATCH_S or len(batch) >= 200):
                ws.send(json.dumps({'type': 'logs', 'items': batch}, ensure_ascii=False, default=str))
                batch, last_flush = [], now
            if now - last_metrics >= METRICS_EVERY_S:
                redis.zadd(CLIENTS_KEY, {conn_id: now})
                redis.zadd(USERS_KEY, {username: now})
                ws.send(json.dumps({'type': 'metrics', 'at': now, **stats.snapshot(), **platform_metrics(redis, now)}))
                last_metrics = now
            if receive() is Closed:
                break
    finally:
        try:
            pubsub.close()
            redis.zrem(CLIENTS_KEY, conn_id)
        except Exception:  # noqa: BLE001
            pass
    return stats.total


def register(app):
    """Route ``/ws/live`` (flask-sock). Absente si la bibliothèque n'est pas installée : la page l'indique."""
    try:
        from flask_sock import Sock
        from simple_websocket import ConnectionClosed
    except ImportError:  # pragma: no cover - dépendance déclarée dans requirements.txt
        app.extensions['sentinel_live'] = False
        log.warning('flask-sock absent : la page Temps réel ne recevra rien')
        return
    from flask import request
    from flask_login import current_user

    sock = Sock(app)
    app.extensions['sentinel_live'] = True

    @sock.route('/ws/live')
    def live_socket(ws):
        if not current_user.is_authenticated or not same_origin(request.headers.get('Origin'), request.host):
            ws.close(reason=1008, message='Session requise')
            return

        def receive():
            try:
                ws.receive(timeout=0)
            except ConnectionClosed:
                return Closed
            return None

        try:
            serve(ws, app.extensions['sentinel_stores'].redis, current_user.username, receive=receive)
        except ConnectionClosed:
            pass
