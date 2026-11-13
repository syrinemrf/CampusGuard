"""Upload workflow: validate → preview → confirm → measured ingestion status."""
import io
import json
import os
from datetime import datetime, timedelta, timezone

from app.services.uploads import UploadService

GOOD_CSV = ('timestamp,ip,action,port,level\n'
            '2026-10-30T13:00:00+00:00,203.0.113.50,deny,22,WARNING\n'
            '2026-10-30T13:00:30+00:00,192.0.2.82,allow,443,INFO\n')


def send(session, name, content, mimetype='text/csv'):
    data = content if isinstance(content, bytes) else content.encode()
    return session.post('/api/uploads', data={'file': (io.BytesIO(data), name, mimetype)},
                        content_type='multipart/form-data')


def test_valid_csv_is_validated_with_preview_and_ndjson_staged(analyst, config, stores):
    res = send(analyst, 'fw.csv', GOOD_CSV)
    body = res.get_json()
    assert res.status_code == 201 and body['state'] == 'validated' and body['state_label'] == 'Validé'
    assert body['stats'] == {'total_rows': 2, 'valid_rows': 2, 'invalid_rows': 0, 'blank_lines': 0}
    assert len(body['preview']['raw_lines']) == 3 and len(body['preview']['events']) == 2
    staged = os.path.join(config.upload_dir, 'staging', body['id'] + '.ndjson')
    lines = [json.loads(l) for l in open(staged, encoding='utf-8')]
    assert len(lines) == 2
    assert lines[0]['labels']['upload_id'] == body['id'] and lines[0]['log']['origin']['file']['name'] == 'fw.csv'
    assert lines[0]['timestamp'] == '2026-10-30T13:00:00.000Z'
    assert not os.path.exists(os.path.join(config.upload_dir, 'staging', body['id'] + '.upload'))   # raw copy removed
    assert not os.path.exists(os.path.join(config.upload_dir, 'ready', body['id'] + '.ndjson'))      # not handed to Logstash yet
    doc = stores.db.uploaded_files.find_one({'_id': body['id']})
    assert [h['state'] for h in doc['state_history']] == ['received', 'validated']
    assert doc['sha256'] == body['sha256'] and doc['uploaded_by'] == 'analyste'


def test_confirm_moves_file_to_watched_directory_atomically(analyst, config):
    uid = send(analyst, 'fw.csv', GOOD_CSV).get_json()['id']
    res = analyst.post(f'/api/uploads/{uid}/confirm')
    assert res.status_code == 202 and res.get_json()['state'] == 'ingesting'
    assert os.path.exists(os.path.join(config.upload_dir, 'ready', uid + '.ndjson'))
    assert not os.path.exists(os.path.join(config.upload_dir, 'staging', uid + '.ndjson'))
    assert analyst.post(f'/api/uploads/{uid}/confirm').status_code == 409          # cannot confirm twice


def test_cancel_removes_staged_file_and_blocks_confirm(analyst, config):
    uid = send(analyst, 'fw.csv', GOOD_CSV).get_json()['id']
    assert analyst.delete(f'/api/uploads/{uid}').get_json()['state'] == 'cancelled'
    assert not os.path.exists(os.path.join(config.upload_dir, 'staging', uid + '.ndjson'))
    assert analyst.post(f'/api/uploads/{uid}/confirm').status_code == 409


def test_rejected_file_reports_reason_and_leaves_no_files(analyst, config, stores):
    res = send(analyst, 'bad.csv', 'timestamp,ip\nnot-a-date,999.0.0.1\nalso-bad,abc\n')
    body = res.get_json()
    assert res.status_code == 422 and body['state'] == 'rejected'
    assert 'Aucune ligne valide' in body['failure_reason'] and body['errors'][0]['line'] == 2
    leftovers = os.listdir(os.path.join(config.upload_dir, 'staging'))
    assert leftovers == []
    assert stores.db.audit_actions.find_one({'action': 'upload_rejected'})['target'] == body['id']


def test_too_many_invalid_rows_rejects_whole_file(analyst):
    rows = ''.join(f'2026-10-30T13:00:0{i}Z,{"bad" if i < 6 else "192.0.2.1"}\n' for i in range(9))
    body = send(analyst, 'mix.csv', 'timestamp,ip\n' + rows).get_json()
    assert body['state'] == 'rejected' and 'Trop de lignes invalides' in body['failure_reason']


def test_some_invalid_rows_below_threshold_are_accepted_with_report(analyst):
    rows = ''.join(f'2026-10-30T13:00:0{i}Z,192.0.2.{i + 1}\n' for i in range(8)) + '2026-10-30T13:00:09Z,bad\n'
    body = send(analyst, 'ok.csv', 'timestamp,ip\n' + rows).get_json()
    assert body['state'] == 'validated' and body['stats']['valid_rows'] == 8 and body['stats']['invalid_rows'] == 1
    assert body['errors'][0]['line'] == 10


def test_unsupported_extension_and_mimetype_refused(analyst):
    assert send(analyst, 'evil.exe', 'MZ').status_code == 415
    assert send(analyst, 'a.csv', GOOD_CSV, mimetype='image/png').status_code == 415


def test_empty_file_refused(analyst):
    res = send(analyst, 'e.csv', b'')
    assert res.status_code == 422 and res.get_json()['error'] == 'empty_file'


def test_oversize_file_refused_with_413(analyst, config):
    big = 'timestamp,ip\n' + '2026-10-30T13:00:00Z,192.0.2.1\n' * 40000      # > 1 MB limit of the test config
    res = send(analyst, 'big.csv', big)
    assert res.status_code == 413 and 'volumineux' in res.get_json()['message']
    assert os.listdir(os.path.join(config.upload_dir, 'staging')) == []


def test_duplicate_content_is_refused_with_reference_to_first_import(analyst):
    first = send(analyst, 'fw.csv', GOOD_CSV).get_json()
    res = send(analyst, 'copy.csv', GOOD_CSV)
    assert res.status_code == 409 and res.get_json()['existing_id'] == first['id']


def test_path_traversal_in_filename_is_neutralised(analyst, config):
    body = send(analyst, '../../etc/passwd.csv', GOOD_CSV).get_json()
    assert body['original_name'] == 'passwd.csv'
    assert os.path.exists(os.path.join(config.upload_dir, 'staging', body['id'] + '.ndjson'))


def test_missing_file_field(analyst):
    assert analyst.post('/api/uploads', data={}, content_type='multipart/form-data').status_code == 400


def test_txt_and_json_uploads(analyst):
    txt = send(analyst, 'ssh.log', '2026-10-30T13:00:00Z sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2\n', 'text/plain')
    assert txt.status_code == 201 and txt.get_json()['preview']['events'][0]['outcome'] == 'failure'
    js = send(analyst, 'a.jsonl', json.dumps({'timestamp': '2026-10-30T13:00:00Z', 'ip': '192.0.2.4'}) + '\n', 'application/x-ndjson')
    assert js.status_code == 201


# ------------------------------------------------------------ ingestion status (measured, never assumed)
def start_ingestion(analyst):
    uid = send(analyst, 'fw.csv', GOOD_CSV).get_json()['id']
    analyst.post(f'/api/uploads/{uid}/confirm')
    return uid


def test_status_stays_ingesting_until_elasticsearch_confirms(analyst, stores):
    uid = start_ingestion(analyst)
    stores.es.count_value = 1                                   # only 1 of 2 events indexed so far
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'ingesting' and body['indexed_count'] == 1
    assert stores.es.counts[-1][1] == {'term': {'labels.upload_id': uid}}


def test_status_becomes_indexed_when_all_events_are_counted(analyst, stores):
    uid = start_ingestion(analyst)
    stores.es.count_value = 2
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'indexed' and body['indexed_count'] == 2 and body['rejected_count'] == 0
    assert [h['state'] for h in body['history']] == ['received', 'validated', 'ingesting', 'indexed']


def test_status_partial_when_logstash_dead_letter_has_rejections(analyst, stores, config):
    uid = start_ingestion(analyst)
    os.makedirs(config.rejected_dir, exist_ok=True)
    with open(os.path.join(config.rejected_dir, f'upload-{uid}.ndjson'), 'w') as fh:
        fh.write('{"tags":["_bad_timestamp"]}\n')
    stores.es.count_value = 1
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'partial' and body['rejected_count'] == 1 and '1 événement' in body['failure_reason']


def test_status_failed_when_everything_was_rejected(analyst, stores, config):
    uid = start_ingestion(analyst)
    os.makedirs(config.rejected_dir, exist_ok=True)
    with open(os.path.join(config.rejected_dir, f'upload-{uid}.ndjson'), 'w') as fh:
        fh.write('{}\n{}\n')
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'failed' and 'rejetés par Logstash' in body['failure_reason']


def test_status_keeps_last_known_state_when_elasticsearch_is_down(analyst, stores):
    uid = start_ingestion(analyst)
    stores.es.down = True
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'ingesting' and 'indisponible' in body['status_warning']


def test_stalled_hint_after_timeout_without_pretending_failure(analyst, stores, config):
    uid = start_ingestion(analyst)
    old = datetime.now(timezone.utc) - timedelta(seconds=config.ingest_stall_seconds + 60)
    stores.db.uploaded_files.update_one({'_id': uid}, {'$set': {'confirmed_at': old}})
    body = analyst.get(f'/api/uploads/{uid}').get_json()
    assert body['state'] == 'ingesting' and body['stalled'] is True and 'docker compose logs logstash' in body['stalled_hint']


# ------------------------------------------------------------ visibility / RBAC
def test_analyst_sees_only_own_uploads_admin_and_auditor_see_all(make_session):
    a, b = make_session('analyste'), make_session('admin')
    uid = send(a, 'fw.csv', GOOD_CSV).get_json()['id']
    other = send(b, 'other.csv', GOOD_CSV.replace('203.0.113.50', '203.0.113.51')).get_json()['id']
    assert [u['id'] for u in a.get('/api/uploads').get_json()['uploads']] == [uid]
    assert {u['id'] for u in b.get('/api/uploads').get_json()['uploads']} == {uid, other}
    assert {u['id'] for u in make_session('auditeur').get('/api/uploads').get_json()['uploads']} == {uid, other}
    assert a.get(f'/api/uploads/{other}').status_code == 404                  # not leaked
    assert make_session('auditeur').post(f'/api/uploads/{uid}/confirm').status_code == 403


def test_invalid_upload_id_is_404(analyst):
    assert analyst.get('/api/uploads/../../etc').status_code == 404
    assert analyst.get('/api/uploads/not-a-valid-id').status_code == 404


def test_audit_trail_for_upload_lifecycle(analyst, stores):
    uid = start_ingestion(analyst)
    actions = [a['action'] for a in stores.db.audit_actions.find({'target': uid})]
    assert actions == ['upload_validated', 'upload_confirmed']


def test_listing_refreshes_uploads_that_are_still_ingesting(analyst, stores):
    uid = start_ingestion(analyst)
    stores.es.count_value = 2
    listed = analyst.get('/api/uploads').get_json()['uploads']
    assert listed[0]['id'] == uid and listed[0]['state'] == 'indexed' and listed[0]['indexed_count'] == 2


def test_declared_type_must_match_extension(analyst):
    ok = analyst.post('/api/uploads', data={'file': (io.BytesIO(GOOD_CSV.encode()), 'fw.csv', 'text/csv'), 'source_type': 'csv'},
                      content_type='multipart/form-data')
    assert ok.status_code == 201
    other = GOOD_CSV.replace('203.0.113.50', '203.0.113.99')
    bad = analyst.post('/api/uploads', data={'file': (io.BytesIO(other.encode()), 'fw2.csv', 'text/csv'), 'source_type': 'json'},
                       content_type='multipart/form-data')
    assert bad.status_code == 422 and bad.get_json()['error'] == 'type_mismatch'
    auto = analyst.post('/api/uploads', data={'file': (io.BytesIO(other.encode()), 'fw2.csv', 'text/csv'), 'source_type': 'auto'},
                        content_type='multipart/form-data')
    assert auto.status_code == 201
