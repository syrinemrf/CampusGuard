"""Validation and ECS normalisation of uploaded CSV / JSON / TXT log files.

Pure functions (no I/O to Mongo/ES): everything here is unit-tested.  The
normalised records are written as NDJSON for Logstash, which performs the final
validation, GeoIP enrichment, deduplication fingerprint and the Elasticsearch
indexing.

Honesty notes
-------------
* A naive timestamp (no zone) is *assumed* to be UTC and reported as a warning.
* TXT lines without a recognisable timestamp get the reception time and are
  labelled ``labels.time_mode = "ingest"`` so they are never mistaken for source
  times.
* The sshd patterns are simple heuristics; they have not been validated on the
  complete Loghub OpenSSH corpus.
"""
import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

ALLOWED_EXTENSIONS = {
    'csv': 'csv', 'json': 'json', 'jsonl': 'json', 'ndjson': 'json', 'txt': 'txt', 'log': 'txt',
}
ALLOWED_MIMETYPES = {
    '', 'text/csv', 'application/csv', 'application/vnd.ms-excel', 'text/plain',
    'application/json', 'text/json', 'application/x-ndjson', 'application/jsonl',
    'application/octet-stream',
}
PREVIEW_LINES = 10
PREVIEW_CHARS = 300
MAX_LINE_CHARS = 8192
MAX_MESSAGE_CHARS = 4096
MAX_ERRORS_KEPT = 50
LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
LEVEL_ALIASES = {'WARN': 'WARNING', 'FATAL': 'CRITICAL', 'ERR': 'ERROR', 'NOTICE': 'INFO', 'TRACE': 'DEBUG'}
OUTCOME_ALIASES = {
    'success': 'success', 'succeeded': 'success', 'ok': 'success', 'accepted': 'success', 'allow': 'success',
    'allowed': 'success', 'failure': 'failure', 'fail': 'failure', 'failed': 'failure', 'denied': 'failure',
    'deny': 'failure', 'rejected': 'failure', 'unknown': 'unknown',
}

ALIASES = {
    'timestamp': ('timestamp', '@timestamp', 'time', 'datetime', 'date', 'ts'),
    'ip': ('source_ip', 'source.ip', 'src_ip', 'srcip', 'ip', 'client_ip', 'remote_ip'),
    'user': ('username', 'user', 'user.name', 'user_name', 'account'),
    'level': ('level', 'log.level', 'severity', 'loglevel'),
    'action': ('action', 'event.action', 'event_action'),
    'outcome': ('outcome', 'event.outcome', 'result', 'status'),
    'service': ('service', 'service.name', 'app', 'program'),
    'port': ('port', 'destination.port', 'dst_port', 'dest_port'),
    'message': ('message', 'msg', 'text'),
    'category': ('category', 'event.category'),
}
# Containers that are legitimate nested ECS-like objects in JSON input.
KNOWN_ROOTS = {'source', 'user', 'event', 'log', 'service', 'destination', 'labels'}

_TS_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?\s*(Z|[+-]\d{2}:?\d{2})?$', re.I)
_SYSLOG_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$')
_ISO_PREFIX_RE = re.compile(
    r'^\[?(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?\s?(?:Z|[+-]\d{2}:?\d{2})?)\]?[\s,;|-]+(.*)$', re.I)
_IPV4_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
_SSH_FAIL = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+', re.I)
_SSH_OK = re.compile(r'Accepted (?:password|publickey|keyboard-interactive\S*) for (\S+) from (\S+) port \d+', re.I)
_SSH_INVALID = re.compile(r'Invalid user (\S*) from (\S+)', re.I)
_SSH_AUTHFAIL = re.compile(r'authentication failure.*?rhost=(\S+)(?:.*?user=(\S+))?', re.I)
_SERVICE_RE = re.compile(r'^[\w.\- ]{1,64}$')
_ACTION_RE = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
_MONTHS = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}


class FileRejected(Exception):
    """The whole file cannot be processed (structure, encoding, content)."""


class RowError(ValueError):
    """One row is invalid; the message is shown to the user."""

    def __init__(self, reason, field_name=None):
        super().__init__(reason)
        self.reason = reason
        self.field = field_name


def format_for_filename(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    return ALLOWED_EXTENSIONS.get(ext)


# ---------------------------------------------------------------- field parsers

def parse_timestamp(value, now, *, naive_counter=None):
    """Return an aware UTC datetime or raise RowError."""
    if isinstance(value, bool) or value is None:
        raise RowError('horodatage absent', 'timestamp')
    numeric = isinstance(value, (int, float)) or (
        isinstance(value, str) and re.fullmatch(r'\d{9,13}(\.\d+)?', value.strip()))
    if numeric:
        number = float(value)
        if number > 1e11:  # milliseconds
            number /= 1000.0
        try:
            dt = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise RowError('horodatage numérique hors limites', 'timestamp')
    elif isinstance(value, str):
        m = _TS_RE.match(value.strip())
        if not m:
            raise RowError(f'horodatage illisible : « {value.strip()[:40]} »', 'timestamp')
        y, mo, d, h, mi, s, frac, tz = m.groups()
        try:
            micro = int((frac or '0')[:6].ljust(6, '0'))
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s or 0), micro)
        except ValueError:
            raise RowError(f'horodatage invalide : « {value.strip()[:40]} »', 'timestamp')
        if tz and tz.upper() != 'Z':
            sign = 1 if tz[0] == '+' else -1
            digits = tz[1:].replace(':', '')
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            dt = (dt - sign * offset).replace(tzinfo=timezone.utc)
        else:
            dt = dt.replace(tzinfo=timezone.utc)
            if not tz and naive_counter is not None:
                naive_counter['naive_timestamps'] = naive_counter.get('naive_timestamps', 0) + 1
    else:
        raise RowError('type d’horodatage non supporté', 'timestamp')
    if dt.year < 1970:
        raise RowError('horodatage antérieur à 1970', 'timestamp')
    if dt > now + timedelta(days=1):
        raise RowError('horodatage dans le futur', 'timestamp')
    return dt


def iso_utc(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'


def parse_ip(value):
    if not isinstance(value, str):
        raise RowError('adresse IP de type invalide', 'ip')
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise RowError(f'adresse IP invalide : « {value.strip()[:45]} »', 'ip')


def parse_port(value):
    if isinstance(value, bool):
        raise RowError('port invalide', 'port')
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str):
        value = value.strip()
        if not re.fullmatch(r'\d{1,5}', value):
            raise RowError(f'port invalide : « {value[:10]} »', 'port')
        value = int(value)
    if not isinstance(value, int) or not 1 <= value <= 65535:
        raise RowError('port hors de la plage 1–65535', 'port')
    return value


def parse_level(value):
    if not isinstance(value, str):
        raise RowError('niveau de type invalide', 'level')
    level = value.strip().upper()
    level = LEVEL_ALIASES.get(level, level)
    if level not in LEVELS:
        raise RowError(f'niveau inconnu : « {value.strip()[:20]} » (attendu : {", ".join(sorted(LEVELS))})', 'level')
    return level


def parse_outcome(value):
    if not isinstance(value, str):
        raise RowError('résultat de type invalide', 'outcome')
    outcome = OUTCOME_ALIASES.get(value.strip().lower())
    if outcome is None:
        raise RowError(f'résultat inconnu : « {value.strip()[:20]} » (attendu : success, failure, unknown)', 'outcome')
    return outcome


def parse_action(value):
    if not isinstance(value, str) or not _ACTION_RE.match(value.strip()):
        raise RowError('action invalide (lettres, chiffres, . _ - uniquement, 64 max)', 'action')
    return value.strip().lower()


def parse_text(value, field_name, limit):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise RowError(f'{field_name} de type invalide', field_name)
    text = str(value).strip()
    if len(text) > limit:
        raise RowError(f'{field_name} trop long (> {limit})', field_name)
    return text


def clip_message(text, counters):
    if len(text) > MAX_MESSAGE_CHARS:
        counters['truncated_messages'] = counters.get('truncated_messages', 0) + 1
        return text[:MAX_MESSAGE_CHARS - 1] + '…'
    return text


# ---------------------------------------------------------------- normalisation

def _get(raw, names):
    """First present value among alias names, supporting flat keys and nested paths."""
    for name in names:
        value = raw.get(name)
        # A dict under a flat alias (e.g. ECS ``user: {name: ..}``) is a container, not a value:
        # fall through to the dotted alias (``user.name``).
        if value not in (None, '') and not isinstance(value, dict):
            return value
        if '.' in name:
            cur = raw
            for part in name.split('.'):
                cur = cur.get(part) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if cur not in (None, ''):
                return cur
    return None


def build_event(raw, *, fmt, line, now, counters, message_fallback):
    """Turn a raw mapping into the canonical record consumed by Logstash.

    The canonical record carries a top-level ``timestamp`` (ISO 8601 UTC) that the
    Logstash ``date`` filter converts to ``@timestamp``.
    """
    ts = parse_timestamp(_get(raw, ALIASES['timestamp']), now, naive_counter=counters)
    event = {'timestamp': iso_utc(ts)}

    ip_value = _get(raw, ALIASES['ip'])
    if ip_value is None:
        raise RowError('adresse IP source absente', 'ip')
    event['source'] = {'ip': parse_ip(ip_value)}

    user = _get(raw, ALIASES['user'])
    if user is not None:
        event['user'] = {'name': parse_text(user, 'user', 128)}

    level = _get(raw, ALIASES['level'])
    outcome = _get(raw, ALIASES['outcome'])
    action = _get(raw, ALIASES['action'])
    service = _get(raw, ALIASES['service'])
    category = _get(raw, ALIASES['category'])
    port = _get(raw, ALIASES['port'])

    event['log'] = {'level': parse_level(level) if level is not None else 'INFO',
                    'origin': {'file': {'line': line}}}
    event['event'] = {
        'category': parse_text(category, 'category', 64).lower() if category is not None else 'uncategorized',
        'action': parse_action(action) if action is not None else 'event',
        'outcome': parse_outcome(outcome) if outcome is not None else 'unknown',
    }
    svc = parse_text(service, 'service', 64) if service is not None else f'upload-{fmt}'
    if not _SERVICE_RE.match(svc):
        raise RowError('nom de service invalide', 'service')
    event['service'] = {'name': svc}
    if port is not None:
        event['destination'] = {'port': parse_port(port)}

    message = _get(raw, ALIASES['message'])
    message = parse_text(message, 'message', 10 ** 6) if message is not None else message_fallback()
    event['message'] = clip_message(message, counters)
    event['labels'] = {'provenance': 'upload', 'time_mode': 'source'}
    return event


# ---------------------------------------------------------------- analysis

@dataclass
class Analysis:
    fmt: str
    total_rows: int = 0
    valid_rows: int = 0
    invalid_rows: int = 0
    blank_lines: int = 0
    columns: list = field(default_factory=list)
    ignored_columns: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    raw_preview: list = field(default_factory=list)
    event_preview: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)

    def add_error(self, line, exc):
        self.invalid_rows += 1
        if len(self.errors) < MAX_ERRORS_KEPT:
            entry = {'line': line, 'reason': exc.reason}
            if exc.field:
                entry['field'] = exc.field
            self.errors.append(entry)

    @property
    def invalid_ratio(self):
        return self.invalid_rows / self.total_rows if self.total_rows else 0.0


def check_binary_and_decode(path):
    """Reject binary / non UTF-8 content before parsing."""
    with open(path, 'rb') as fh:
        head = fh.read(8192)
        if b'\x00' in head:
            raise FileRejected('Fichier binaire détecté (octets NUL) : seuls les fichiers texte sont acceptés.')
        fh.seek(0)
        decoder = io.TextIOWrapper(fh, encoding='utf-8-sig', errors='strict')
        try:
            while decoder.read(1 << 20):
                pass
        except UnicodeDecodeError as exc:
            raise FileRejected(f'Encodage non UTF-8 (octet invalide à la position {exc.start}).')
        finally:
            decoder.detach()


def _text_lines(path):
    with open(path, 'r', encoding='utf-8-sig', newline='') as fh:
        for raw in fh:
            yield raw.rstrip('\r\n')


def _push_preview(analysis, event):
    if len(analysis.event_preview) < PREVIEW_LINES:
        analysis.event_preview.append({
            'line': event['log']['origin']['file']['line'],
            'timestamp': event['timestamp'],
            'ip': event.get('source', {}).get('ip'),
            'user': event.get('user', {}).get('name'),
            'level': event['log']['level'],
            'outcome': event['event']['outcome'],
            'service': event['service']['name'],
            'message': event['message'][:160],
        })


def _collect_raw_preview(analysis, path):
    for i, line in enumerate(_text_lines(path)):
        if i >= PREVIEW_LINES:
            break
        analysis.raw_preview.append(line[:PREVIEW_CHARS] + ('…' if len(line) > PREVIEW_CHARS else ''))


def analyze(path, fmt, *, now, sink=None):
    """Single-pass validation. ``sink(event)`` receives each valid canonical record."""
    check_binary_and_decode(path)
    a = Analysis(fmt=fmt)
    _collect_raw_preview(a, path)
    if fmt == 'csv':
        _analyze_csv(path, a, now, sink)
    elif fmt == 'json':
        _analyze_json(path, a, now, sink)
    elif fmt == 'txt':
        _analyze_txt(path, a, now, sink)
    else:
        raise FileRejected(f'Format non pris en charge : {fmt}')
    a.total_rows = a.valid_rows + a.invalid_rows
    if a.total_rows == 0:
        raise FileRejected('Le fichier ne contient aucune ligne de données.')
    c = a.counters
    if c.get('naive_timestamps'):
        a.warnings.append(f"{c['naive_timestamps']} horodatage(s) sans fuseau : interprétés comme UTC.")
    if c.get('truncated_messages'):
        a.warnings.append(f"{c['truncated_messages']} message(s) tronqué(s) à {MAX_MESSAGE_CHARS} caractères.")
    if c.get('ingest_time_lines'):
        a.warnings.append(
            f"{c['ingest_time_lines']} ligne(s) sans horodatage source : heure de réception utilisée "
            "(labels.time_mode = ingest).")
    if c.get('syslog_year_assumed'):
        a.warnings.append(
            f"{c['syslog_year_assumed']} horodatage(s) syslog sans année : année déduite de la date de réception.")
    if a.ignored_columns:
        a.warnings.append(
            'Champs non reconnus (conservés uniquement dans le message) : ' + ', '.join(a.ignored_columns[:10]))
    return a


def _unrecognised(names):
    known = {n for group in ALIASES.values() for n in group} | KNOWN_ROOTS
    return [n for n in names if n not in known]


def _analyze_csv(path, a, now, sink):
    with open(path, 'r', encoding='utf-8-sig', newline='') as fh:
        sample = fh.read(8192)
        fh.seek(0)
        if not sample.strip():
            raise FileRejected('CSV vide : en-tête manquant.')
        header_line = sample.splitlines()[0]
        delimiter = max(',;\t|', key=header_line.count)
        if header_line.count(delimiter) == 0:
            raise FileRejected('CSV sans séparateur : en-tête avec au moins deux colonnes attendu (, ; tab |).')
        reader = csv.reader(fh, delimiter=delimiter)
        header = next(reader)
        names = [h.strip().lower() for h in header]
        a.columns = names
        if len(set(names)) != len(names):
            raise FileRejected('En-tête CSV avec des colonnes en double.')
        if not any(n in names for n in ALIASES['timestamp']):
            raise FileRejected('Colonne d’horodatage absente (attendu : timestamp, @timestamp, time, date…).')
        if not any(n in names for n in ALIASES['ip']):
            raise FileRejected('Colonne d’adresse IP absente (attendu : ip, source_ip, src_ip, client_ip…).')
        a.ignored_columns = _unrecognised(names)
        try:
            for row in reader:
                line = reader.line_num
                if not row or all(not c.strip() for c in row):
                    a.blank_lines += 1
                    continue
                if len(row) != len(names):
                    a.add_error(line, RowError(f'{len(row)} colonne(s) au lieu de {len(names)}'))
                    continue
                raw = {n: v.strip() for n, v in zip(names, row) if v.strip() != ''}
                try:
                    event = build_event(raw, fmt='csv', line=line, now=now, counters=a.counters,
                                        message_fallback=lambda r=raw: ' '.join(f'{k}={v}' for k, v in r.items()))
                except RowError as exc:
                    a.add_error(line, exc)
                    continue
                a.valid_rows += 1
                _push_preview(a, event)
                if sink:
                    sink(event)
        except csv.Error as exc:
            raise FileRejected(f'CSV mal formé : {exc}')


def _json_items(path):
    """Yield (line, obj | RowError | None)."""
    with open(path, 'r', encoding='utf-8-sig') as fh:
        first = ''
        while True:
            ch = fh.read(1)
            if not ch or not ch.isspace():
                first = ch
                break
        fh.seek(0)
        if first == '[':
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise FileRejected(f'JSON invalide (ligne {exc.lineno}, colonne {exc.colno}) : {exc.msg}.')
            for i, item in enumerate(data, 1):
                yield i, item
        else:
            for i, line in enumerate(fh, 1):
                if not line.strip():
                    yield i, None
                    continue
                try:
                    yield i, json.loads(line)
                except json.JSONDecodeError as exc:
                    yield i, RowError(f'JSON invalide : {exc.msg} (colonne {exc.colno})')


def _analyze_json(path, a, now, sink):
    seen_keys = set()
    for line, item in _json_items(path):
        if item is None:
            a.blank_lines += 1
            continue
        if isinstance(item, RowError):
            a.add_error(line, item)
            continue
        if not isinstance(item, dict):
            a.add_error(line, RowError('l’élément JSON doit être un objet'))
            continue
        seen_keys.update(item.keys())
        try:
            event = build_event(item, fmt='json', line=line, now=now, counters=a.counters,
                                message_fallback=lambda o=item: json.dumps(
                                    o, ensure_ascii=False, separators=(',', ':')))
        except RowError as exc:
            a.add_error(line, exc)
            continue
        a.valid_rows += 1
        _push_preview(a, event)
        if sink:
            sink(event)
    a.columns = sorted(seen_keys)[:40]
    a.ignored_columns = _unrecognised(sorted(seen_keys))[:20]


def _txt_timestamp(text, now, counters):
    """Return (datetime | None, remainder)."""
    m = _ISO_PREFIX_RE.match(text)
    if m:
        try:
            return parse_timestamp(m.group(1).replace(',', '.'), now, naive_counter=counters), m.group(2)
        except RowError:
            return None, text
    m = _SYSLOG_RE.match(text)
    if m and m.group(1) in _MONTHS:
        mon, day, hh, mm, ss, _host, rest = m.groups()
        try:
            dt = datetime(now.year, _MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=now.year - 1)
        except ValueError:
            return None, text
        counters['syslog_year_assumed'] = counters.get('syslog_year_assumed', 0) + 1
        return dt, rest
    return None, text


def _txt_event(text, line, now, counters):
    if len(text) > MAX_LINE_CHARS:
        raise RowError(f'ligne trop longue (> {MAX_LINE_CHARS} caractères)')
    ts, rest = _txt_timestamp(text, now, counters)
    time_mode = 'source'
    if ts is None:
        ts, time_mode = now, 'ingest'
        counters['ingest_time_lines'] = counters.get('ingest_time_lines', 0) + 1
    service = 'upload-txt'
    proc = re.match(r'^([A-Za-z][\w.-]*)(?:\[\d+\])?:\s', rest)
    if proc:
        service = proc.group(1)[:64]
    user = ip = None
    outcome, action, category, level = 'unknown', 'event', 'uncategorized', 'INFO'
    m = _SSH_FAIL.search(rest)
    if m:
        user, ip, outcome, action, category, level = m.group(1), m.group(2), 'failure', 'ssh-login', 'authentication', 'WARNING'
    else:
        m = _SSH_OK.search(rest)
        if m:
            user, ip, outcome, action, category = m.group(1), m.group(2), 'success', 'ssh-login', 'authentication'
        else:
            m = _SSH_INVALID.search(rest)
            if m:
                user, ip, outcome, action, category, level = (
                    m.group(1) or None, m.group(2), 'failure', 'ssh-login', 'authentication', 'WARNING')
            else:
                m = _SSH_AUTHFAIL.search(rest)
                if m:
                    ip, user, outcome, action, category, level = (
                        m.group(1), m.group(2), 'failure', 'ssh-login', 'authentication', 'WARNING')
                else:
                    word = re.search(r'\b(CRITICAL|FATAL|ERROR|WARN(?:ING)?|DEBUG)\b', rest)
                    if word:
                        level = parse_level(word.group(1))
    if ip is not None:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            ip = None
    if ip is None:
        for cand in _IPV4_RE.findall(rest):
            try:
                ip = str(ipaddress.ip_address(cand))
                break
            except ValueError:
                continue
    event = {'timestamp': iso_utc(ts)}
    if ip:
        event['source'] = {'ip': ip}
    if user:
        event['user'] = {'name': user[:128]}
    event['log'] = {'level': level, 'origin': {'file': {'line': line}}}
    event['event'] = {'category': category, 'action': action, 'outcome': outcome}
    event['service'] = {'name': service if _SERVICE_RE.match(service) else 'upload-txt'}
    event['message'] = clip_message(text, counters)
    event['labels'] = {'provenance': 'upload', 'time_mode': time_mode}
    return event


def _analyze_txt(path, a, now, sink):
    a.columns = ['message']
    for line_no, text in enumerate(_text_lines(path), 1):
        if not text.strip():
            a.blank_lines += 1
            continue
        try:
            event = _txt_event(text.strip(), line_no, now, a.counters)
        except RowError as exc:
            a.add_error(line_no, exc)
            continue
        a.valid_rows += 1
        _push_preview(a, event)
        if sink:
            sink(event)
