"""Upload workflow: reçu → validé → (confirmation) → ingestion Logstash → indexé / partiel / échec.

Files never leave the upload volume: the web app validates, normalises and writes one NDJSON file per
upload; the Logstash ``upload-security`` pipeline watches ``ready/`` and indexes it.  The final status
is *measured* (Elasticsearch ``_count`` on ``labels.upload_id`` + Logstash dead-letter file), never
assumed from the HTTP 200 of the upload.
"""
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone

from pymongo import ReturnDocument

from app.services import parsing
from app.stores import ElasticError

STATE_LABELS = {
    'received': 'Reçu', 'validated': 'Validé', 'rejected': 'Rejeté', 'ingesting': 'Ingestion en cours',
    'indexed': 'Indexé', 'partial': 'Partiellement indexé', 'failed': 'Échec', 'cancelled': 'Annulé',
}
BLOCKING_DUPLICATE_STATES = ['validated', 'ingesting', 'indexed', 'partial']
_ID_RE = re.compile(r'^[0-9a-f]{32}$')
CHUNK = 1 << 16


class UploadError(Exception):
    def __init__(self, code, message, status=400, **extra):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


def utcnow():
    return datetime.now(timezone.utc)


def clean_display_name(name):
    base = (name or '').replace('\\', '/').split('/')[-1]
    base = re.sub(r'[\x00-\x1f\x7f]', '', base).strip()
    return base[:200] or 'fichier'


def count_lines(path):
    if not os.path.isfile(path):
        return 0
    n = 0
    with open(path, 'rb') as fh:
        for _ in fh:
            n += 1
    return n


class UploadService:
    def __init__(self, db, es, config, now=utcnow):
        self.col = db.uploaded_files
        self.es = es
        self.cfg = config
        self.now = now
        self.staging = os.path.join(config.upload_dir, 'staging')
        self.ready = os.path.join(config.upload_dir, 'ready')

    # ------------------------------------------------------------ helpers
    def _ensure_dirs(self):
        for path in (self.staging, self.ready):
            os.makedirs(path, exist_ok=True)

    def _transition(self, upload_id, state, extra=None, expected=None):
        flt = {'_id': upload_id}
        if expected:
            flt['state'] = {'$in': expected} if isinstance(expected, list) else expected
        update = {'$set': {'state': state, 'updated_at': self.now(), **(extra or {})},
                  '$push': {'state_history': {'state': state, 'at': self.now()}}}
        return self.col.find_one_and_update(flt, update, return_document=ReturnDocument.AFTER)

    def _cleanup(self, upload_id):
        for suffix in ('.upload', '.ndjson.part', '.ndjson'):
            try:
                os.remove(os.path.join(self.staging, upload_id + suffix))
            except FileNotFoundError:
                pass

    @staticmethod
    def _can_see(doc, user):
        return user.role in ('admin', 'auditor') or doc['uploaded_by'] == user.username

    @staticmethod
    def _can_modify(doc, user):
        return user.role == 'admin' or (user.role == 'analyst' and doc['uploaded_by'] == user.username)

    # ------------------------------------------------------------ receive + validate
    def receive(self, storage, user, declared_type=None):
        """Store, validate and normalise an uploaded file. Returns (public document, rejected flag)."""
        self._ensure_dirs()
        name = clean_display_name(storage.filename)
        fmt = parsing.format_for_filename(name)
        if fmt is None:
            raise UploadError('unsupported_format',
                              'Extension non prise en charge. Formats acceptés : .csv, .json, .jsonl, .ndjson, .txt, .log.', 415)
        if declared_type and declared_type != 'auto' and declared_type != fmt:
            raise UploadError('type_mismatch', f'Type choisi « {declared_type.upper()} » incompatible avec l’extension du fichier ({fmt.upper()}).', 422)
        mimetype = (storage.mimetype or '').lower()
        if mimetype not in parsing.ALLOWED_MIMETYPES:
            raise UploadError('unsupported_mimetype', f'Type MIME refusé : {mimetype}.', 415)

        upload_id = uuid.uuid4().hex
        raw_path = os.path.join(self.staging, upload_id + '.upload')
        limit = self.cfg.max_upload_mb * 1024 * 1024
        digest, size = hashlib.sha256(), 0
        try:
            with open(raw_path, 'wb') as out:
                while True:
                    chunk = storage.stream.read(CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise UploadError('too_large', f'Fichier trop volumineux (maximum {self.cfg.max_upload_mb} Mo).', 413)
                    digest.update(chunk)
                    out.write(chunk)
        except UploadError:
            self._cleanup(upload_id)
            raise
        sha256 = digest.hexdigest()

        if size == 0:
            self._cleanup(upload_id)
            raise UploadError('empty_file', 'Le fichier est vide.', 422)
        existing = self.col.find_one({'sha256': sha256, 'state': {'$in': BLOCKING_DUPLICATE_STATES}})
        if existing:
            self._cleanup(upload_id)
            raise UploadError('duplicate', 'Ce fichier (même empreinte SHA-256) a déjà été importé.', 409,
                              existing_id=existing['_id'], existing_state=existing['state'])

        now = self.now()
        self.col.insert_one({
            '_id': upload_id, 'original_name': name, 'source_type': fmt, 'sha256': sha256, 'size_bytes': size,
            'uploaded_by': user.username, 'state': 'received', 'created_at': now, 'updated_at': now,
            'state_history': [{'state': 'received', 'at': now}], 'indexed_count': 0, 'rejected_count': 0,
        })

        ndjson_part = os.path.join(self.staging, upload_id + '.ndjson.part')
        analysis = None
        try:
            with open(ndjson_part, 'w', encoding='utf-8', newline='\n') as out:
                def sink(event):
                    event['labels']['upload_id'] = upload_id
                    event['log']['origin']['file']['name'] = name
                    out.write(json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n')
                analysis = parsing.analyze(raw_path, fmt, now=now, sink=sink)
            if analysis.valid_rows == 0:
                raise parsing.FileRejected('Aucune ligne valide : ' + (analysis.errors[0]['reason'] if analysis.errors else 'fichier vide') + '.')
            if analysis.invalid_ratio > self.cfg.max_invalid_ratio:
                raise parsing.FileRejected(
                    f'Trop de lignes invalides : {analysis.invalid_rows} sur {analysis.total_rows} '
                    f'(seuil {int(self.cfg.max_invalid_ratio * 100)} %).')
        except parsing.FileRejected as exc:
            partial = analysis
            self._cleanup(upload_id)
            doc = self._transition(upload_id, 'rejected', {
                'failure_reason': str(exc),
                'errors': partial.errors if partial else [], 'warnings': []})
            return self.public(doc), True
        os.replace(ndjson_part, os.path.join(self.staging, upload_id + '.ndjson'))
        os.chmod(os.path.join(self.staging, upload_id + '.ndjson'), 0o644)
        os.remove(raw_path)

        doc = self._transition(upload_id, 'validated', {
            'validated_at': self.now(),
            'stats': {'total_rows': analysis.total_rows, 'valid_rows': analysis.valid_rows,
                      'invalid_rows': analysis.invalid_rows, 'blank_lines': analysis.blank_lines},
            'columns': analysis.columns, 'errors': analysis.errors, 'warnings': analysis.warnings,
            'preview': {'raw_lines': analysis.raw_preview, 'events': analysis.event_preview},
        })
        return self.public(doc), False

    # ------------------------------------------------------------ confirm / cancel
    def _load(self, upload_id, user, modify=False):
        if not _ID_RE.match(upload_id or ''):
            raise UploadError('not_found', 'Import introuvable.', 404)
        doc = self.col.find_one({'_id': upload_id})
        if not doc or not self._can_see(doc, user):
            raise UploadError('not_found', 'Import introuvable.', 404)
        if modify and not self._can_modify(doc, user):
            raise UploadError('forbidden', 'Vous ne pouvez pas modifier cet import.', 403)
        return doc

    def confirm(self, upload_id, user):
        self._load(upload_id, user, modify=True)
        doc = self._transition(upload_id, 'ingesting', {'confirmed_at': self.now(), 'confirmed_by': user.username},
                               expected='validated')
        if doc is None:
            current = self.col.find_one({'_id': upload_id})
            raise UploadError('invalid_state', f"Import à l'état « {STATE_LABELS.get(current['state'], current['state'])} » : "
                                               'seul un import validé peut être lancé.', 409)
        self._ensure_dirs()
        try:
            os.replace(os.path.join(self.staging, upload_id + '.ndjson'), os.path.join(self.ready, upload_id + '.ndjson'))
        except OSError as exc:
            doc = self._transition(upload_id, 'failed', {'failure_reason': f'Dépôt dans le répertoire surveillé impossible : {exc.__class__.__name__}'})
            raise UploadError('handoff_failed', doc['failure_reason'], 500)
        return self.public(doc)

    def cancel(self, upload_id, user):
        self._load(upload_id, user, modify=True)
        doc = self._transition(upload_id, 'cancelled', expected='validated')
        if doc is None:
            raise UploadError('invalid_state', 'Seul un import validé (non lancé) peut être annulé.', 409)
        self._cleanup(upload_id)
        return self.public(doc)

    # ------------------------------------------------------------ status
    def get(self, upload_id, user, refresh=True):
        doc = self._load(upload_id, user)
        warning = None
        if refresh and doc['state'] == 'ingesting':
            doc, warning = self.refresh_status(doc)
        out = self.public(doc)
        if warning:
            out['status_warning'] = warning
        return out

    def refresh_status(self, doc):
        """Measure the real outcome of an ingesting upload. Returns (doc, warning | None)."""
        upload_id = doc['_id']
        valid = doc['stats']['valid_rows']
        try:
            indexed = self.es.count(self.cfg.logs_index, {'term': {'labels.upload_id': upload_id}})
        except ElasticError:
            return doc, 'Elasticsearch indisponible : état non actualisé.'
        rejected = count_lines(os.path.join(self.cfg.rejected_dir, f'upload-{upload_id}.ndjson'))
        extra = {'indexed_count': indexed, 'rejected_count': rejected, 'last_status_check': self.now()}
        if indexed + rejected >= valid:
            if rejected == 0:
                state, extra['failure_reason'] = 'indexed', None
            elif indexed == 0:
                state = 'failed'
                extra['failure_reason'] = 'Tous les événements ont été rejetés par Logstash (voir le fichier de rejets).'
            else:
                state = 'partial'
                extra['failure_reason'] = f'{rejected} événement(s) rejeté(s) par Logstash.'
            new = self._transition(upload_id, state, extra, expected='ingesting')
            return (new or self.col.find_one({'_id': upload_id})), None
        self.col.update_one({'_id': upload_id}, {'$set': extra})
        return self.col.find_one({'_id': upload_id}), None

    def count_imported(self):
        """Files that went past validation (validated, ingesting, indexed, partial, failed)."""
        return self.col.count_documents({'state': {'$in': ['validated', 'ingesting', 'indexed', 'partial', 'failed']}})

    def list(self, user, limit=50, refresh=True):
        """Newest first. Uploads still ingesting are re-measured (at most 10 per call)."""
        flt = {} if user.role in ('admin', 'auditor') else {'uploaded_by': user.username}
        docs = list(self.col.find(flt, {'preview': 0}).sort('created_at', -1).limit(limit))
        refreshed = 0
        for i, doc in enumerate(docs):
            if refresh and doc['state'] == 'ingesting' and refreshed < 10:
                docs[i], _warning = self.refresh_status(doc)
                refreshed += 1
        return [self.public(d, light=True) for d in docs]

    # ------------------------------------------------------------ serialisation
    def public(self, doc, light=False):
        def iso(value):
            return value.astimezone(timezone.utc).isoformat() if isinstance(value, datetime) and value.tzinfo \
                else (value.replace(tzinfo=timezone.utc).isoformat() if isinstance(value, datetime) else value)
        stalled = False
        if doc['state'] == 'ingesting' and doc.get('confirmed_at'):
            confirmed = doc['confirmed_at']
            if confirmed.tzinfo is None:
                confirmed = confirmed.replace(tzinfo=timezone.utc)
            stalled = (self.now() - confirmed).total_seconds() > self.cfg.ingest_stall_seconds
        out = {
            'id': doc['_id'], 'original_name': doc['original_name'], 'source_type': doc['source_type'],
            'sha256': doc['sha256'], 'size_bytes': doc['size_bytes'], 'uploaded_by': doc['uploaded_by'],
            'state': doc['state'], 'state_label': STATE_LABELS.get(doc['state'], doc['state']),
            'created_at': iso(doc['created_at']), 'stats': doc.get('stats'),
            'indexed_count': doc.get('indexed_count', 0), 'rejected_count': doc.get('rejected_count', 0),
            'failure_reason': doc.get('failure_reason'), 'stalled': stalled,
            'warnings': doc.get('warnings', []), 'errors': doc.get('errors', []),
        }
        if stalled:
            out['stalled_hint'] = ("Aucune indexation constatée depuis plus de "
                                   f"{self.cfg.ingest_stall_seconds // 60} min : vérifiez `docker compose logs logstash`.")
        if not light:
            out['preview'] = doc.get('preview')
            out['columns'] = doc.get('columns', [])
            out['history'] = [{'state': h['state'], 'at': iso(h['at'])} for h in doc.get('state_history', [])]
        return out
