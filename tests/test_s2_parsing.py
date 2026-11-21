"""Unit tests for file validation and ECS normalisation (no I/O to external services)."""
import json
from datetime import datetime, timezone

import pytest

from app.services import parsing
from app.services.parsing import FileRejected, RowError

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def run(tmp_path, name, content, fmt, mode='w'):
    path = tmp_path / name
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding='utf-8')
    events = []
    analysis = parsing.analyze(str(path), fmt, now=NOW, sink=events.append)
    return analysis, events


# ------------------------------------------------------------ timestamps
@pytest.mark.parametrize('value,expected', [
    ('2026-10-30T13:00:00+00:00', '2026-10-30T13:00:00.000Z'),
    ('2026-10-30T13:00:00Z', '2026-10-30T13:00:00.000Z'),
    ('2026-10-30 13:00:00', '2026-10-30T13:00:00.000Z'),
    ('2026-10-30T15:00:00+02:00', '2026-10-30T13:00:00.000Z'),
    ('2026-10-30T08:00:00-0500', '2026-10-30T13:00:00.000Z'),
    ('2026-10-30T13:00:00.123456Z', '2026-10-30T13:00:00.123Z'),
    ('1793365200', '2026-10-30T13:00:00.000Z'),
    ('1793365200000', '2026-10-30T13:00:00.000Z'),
])
def test_parse_timestamp_normalises_to_utc(value, expected):
    assert parsing.iso_utc(parsing.parse_timestamp(value, NOW)) == expected


@pytest.mark.parametrize('value', ['', None, 'hier', '2026-13-45T00:00:00Z', '30/10/2026', '2999-01-01T00:00:00Z', '1960-01-01T00:00:00Z', True])
def test_parse_timestamp_rejects_invalid(value):
    with pytest.raises(RowError):
        parsing.parse_timestamp(value, NOW)


def test_naive_timestamp_counted_as_assumption():
    counters = {}
    parsing.parse_timestamp('2026-10-30 13:00:00', NOW, naive_counter=counters)
    parsing.parse_timestamp('2026-10-30T13:00:00Z', NOW, naive_counter=counters)
    assert counters == {'naive_timestamps': 1}


# ------------------------------------------------------------ field parsers
def test_ip_validation():
    assert parsing.parse_ip(' 192.0.2.1 ') == '192.0.2.1'
    assert parsing.parse_ip('2001:db8::1') == '2001:db8::1'
    for bad in ('999.1.1.1', 'abc', '', 12):
        with pytest.raises(RowError):
            parsing.parse_ip(bad)


def test_port_validation():
    assert parsing.parse_port('22') == 22 and parsing.parse_port(443) == 443
    for bad in (0, 70000, '-1', 'http', True, 1.5):
        with pytest.raises(RowError):
            parsing.parse_port(bad)


def test_level_and_outcome_aliases():
    assert parsing.parse_level('warn') == 'WARNING' and parsing.parse_level('fatal') == 'CRITICAL'
    assert parsing.parse_outcome('Denied') == 'failure' and parsing.parse_outcome('OK') == 'success'
    with pytest.raises(RowError):
        parsing.parse_level('loud')
    with pytest.raises(RowError):
        parsing.parse_outcome('maybe')


# ------------------------------------------------------------ CSV
def test_csv_firewall_sample_is_valid(tmp_path):
    csv_text = 'timestamp,ip,action,port,level\n2026-10-30T13:00:00+00:00,203.0.113.50,deny,22,WARNING\n2026-10-30T13:00:30+00:00,192.0.2.82,allow,443,INFO\n'
    analysis, events = run(tmp_path, 'fw.csv', csv_text, 'csv')
    assert (analysis.valid_rows, analysis.invalid_rows) == (2, 0)
    first = events[0]
    assert first['timestamp'] == '2026-10-30T13:00:00.000Z'
    assert first['source'] == {'ip': '203.0.113.50'}
    assert first['destination'] == {'port': 22}
    assert first['log']['level'] == 'WARNING' and first['log']['origin']['file']['line'] == 2
    assert first['event']['action'] == 'deny' and first['event']['outcome'] == 'unknown'
    assert first['service']['name'] == 'upload-csv'
    assert 'ip=203.0.113.50' in first['message']          # raw row kept searchable
    assert first['labels'] == {'provenance': 'upload', 'time_mode': 'source'}


def test_csv_reports_each_invalid_row_with_line_and_reason(tmp_path):
    text = ('timestamp,ip,level\n2026-10-30T13:00:00Z,203.0.113.1,INFO\n'
            'not-a-date,203.0.113.2,INFO\n2026-10-30T13:00:00Z,999.9.9.9,INFO\n'
            '2026-10-30T13:00:00Z,203.0.113.4,LOUD\n2026-10-30T13:00:00Z,203.0.113.5\n')
    analysis, events = run(tmp_path, 'bad.csv', text, 'csv')
    assert analysis.valid_rows == 1 and analysis.invalid_rows == 4
    lines = {e['line']: e for e in analysis.errors}
    assert set(lines) == {3, 4, 5, 6}
    assert lines[3]['field'] == 'timestamp' and lines[4]['field'] == 'ip' and lines[5]['field'] == 'level'
    assert 'colonne' in lines[6]['reason']


def test_csv_semicolon_and_aliases(tmp_path):
    text = 'time;src_ip;user;result;msg\n2026-10-30 13:00:00;192.0.2.7;alice;failed;mauvais mot de passe\n'
    analysis, events = run(tmp_path, 'fr.csv', text, 'csv')
    assert analysis.valid_rows == 1
    e = events[0]
    assert e['user'] == {'name': 'alice'} and e['event']['outcome'] == 'failure' and e['message'] == 'mauvais mot de passe'
    assert any('sans fuseau' in w for w in analysis.warnings)


@pytest.mark.parametrize('content,reason', [
    ('', 'vide'),
    ('timestamp,level\n2026-10-30T13:00:00Z,INFO\n', 'IP absente'),
    ('ip,level\n192.0.2.1,INFO\n', 'horodatage absente'),
    ('timestamp,ip,ip\n2026-10-30T13:00:00Z,192.0.2.1,192.0.2.2\n', 'double'),
    ('timestamp,ip\n', 'aucune ligne'),
    ('justone\nx\n', 'séparateur'),
])
def test_csv_structural_rejections(tmp_path, content, reason):
    with pytest.raises(FileRejected) as exc:
        run(tmp_path, 'x.csv', content, 'csv')
    assert reason in str(exc.value)


def test_csv_unknown_columns_are_warned_not_dropped_silently(tmp_path):
    text = 'timestamp,ip,secret_field\n2026-10-30T13:00:00Z,192.0.2.1,abc\n'
    analysis, events = run(tmp_path, 'x.csv', text, 'csv')
    assert 'secret_field' in analysis.ignored_columns
    assert any('secret_field' in w for w in analysis.warnings)
    assert 'secret_field=abc' in events[0]['message']


# ------------------------------------------------------------ JSON
def test_jsonl_sample_format(tmp_path):
    line = {'timestamp': '2026-10-30T13:00:00+00:00', 'source_ip': '203.0.113.50', 'username': 'user_4',
            'outcome': 'failure', 'level': 'WARNING', 'message': 'Simulated failed login'}
    analysis, events = run(tmp_path, 'a.jsonl', json.dumps(line) + '\n\n' + json.dumps(line) + '\n', 'json')
    assert analysis.valid_rows == 2 and analysis.blank_lines == 1
    assert events[0]['event']['outcome'] == 'failure' and events[0]['user']['name'] == 'user_4'


def test_json_array_with_nested_ecs_fields(tmp_path):
    doc = [{'@timestamp': '2026-10-30T13:00:00Z', 'source': {'ip': '192.0.2.9'}, 'user': {'name': 'bob'},
            'event': {'action': 'ssh-login', 'outcome': 'success'}, 'log': {'level': 'info'},
            'service': {'name': 'sshd'}}]
    analysis, events = run(tmp_path, 'e.json', json.dumps(doc), 'json')
    e = events[0]
    assert (e['source']['ip'], e['user']['name'], e['event']['action'], e['service']['name']) == ('192.0.2.9', 'bob', 'ssh-login', 'sshd')
    assert e['message'].startswith('{')   # no message field → compact original JSON kept


def test_json_invalid_lines_and_non_objects(tmp_path):
    text = '{"timestamp":"2026-10-30T13:00:00Z","ip":"192.0.2.1"}\n{broken\n[1,2]\n"str"\n'
    analysis, events = run(tmp_path, 'm.jsonl', text, 'json')
    assert analysis.valid_rows == 1 and analysis.invalid_rows == 3
    assert analysis.errors[0]['line'] == 2 and 'JSON invalide' in analysis.errors[0]['reason']


def test_json_array_syntax_error_rejects_file(tmp_path):
    with pytest.raises(FileRejected) as exc:
        run(tmp_path, 'bad.json', '[{"a": 1,]', 'json')
    assert 'JSON invalide' in str(exc.value)


def test_json_wrong_types_rejected_per_row(tmp_path):
    rows = [{'timestamp': '2026-10-30T13:00:00Z', 'ip': 12345}, {'timestamp': '2026-10-30T13:00:00Z', 'ip': '192.0.2.1', 'port': 'x'},
            {'timestamp': {'a': 1}, 'ip': '192.0.2.1'}]
    analysis, _ = run(tmp_path, 'w.json', json.dumps(rows), 'json')
    assert analysis.valid_rows == 0 and analysis.invalid_rows == 3


# ------------------------------------------------------------ TXT
def test_txt_sshd_failed_password(tmp_path):
    line = '2026-10-30T13:00:00Z sshd[1234]: Failed password for invalid user admin from 203.0.113.50 port 51234 ssh2'
    analysis, events = run(tmp_path, 'a.txt', line + '\n', 'txt')
    e = events[0]
    assert e['event'] == {'category': 'authentication', 'action': 'ssh-login', 'outcome': 'failure'}
    assert e['user']['name'] == 'admin' and e['source']['ip'] == '203.0.113.50' and e['log']['level'] == 'WARNING'
    assert e['service']['name'] == 'sshd' and e['labels']['time_mode'] == 'source'
    assert 'destination' not in e                      # the sshd port is a *source* port, not destination.port


def test_txt_syslog_without_year_is_flagged(tmp_path):
    line = 'Oct 30 13:00:00 host sshd[99]: Accepted password for alice from 192.0.2.5 port 2200 ssh2'
    analysis, events = run(tmp_path, 's.log', line + '\n', 'txt')
    assert events[0]['timestamp'] == '2026-10-30T13:00:00.000Z'
    assert events[0]['event']['outcome'] == 'success'
    assert any('année déduite' in w for w in analysis.warnings)


def test_txt_syslog_future_date_uses_previous_year(tmp_path):
    analysis, events = run(tmp_path, 's.log', 'Dec 31 23:59:00 host cron[1]: job done\n', 'txt')
    assert events[0]['timestamp'].startswith('2025-12-31')


def test_txt_without_timestamp_uses_ingest_time_and_says_so(tmp_path):
    analysis, events = run(tmp_path, 'n.txt', 'ERROR disk full on 10.0.0.5\n', 'txt')
    e = events[0]
    assert e['labels']['time_mode'] == 'ingest' and e['timestamp'] == '2026-11-06T12:00:00.000Z'
    assert e['log']['level'] == 'ERROR' and e['source']['ip'] == '10.0.0.5'
    assert any('heure de réception' in w for w in analysis.warnings)


def test_txt_line_without_ip_is_still_valid(tmp_path):
    analysis, events = run(tmp_path, 'n.txt', '2026-10-30T13:00:00Z service started\n', 'txt')
    assert 'source' not in events[0] and analysis.valid_rows == 1


def test_txt_too_long_line_is_invalid(tmp_path):
    analysis, events = run(tmp_path, 'l.txt', 'ok line\n' + 'x' * 9000 + '\n', 'txt')
    assert analysis.valid_rows == 1 and analysis.invalid_rows == 1 and 'trop longue' in analysis.errors[0]['reason']


# ------------------------------------------------------------ generic guards
def test_binary_and_non_utf8_rejected(tmp_path):
    with pytest.raises(FileRejected) as exc:
        run(tmp_path, 'b.csv', b'timestamp,ip\n\x00\x01\x02', 'csv')
    assert 'binaire' in str(exc.value)
    with pytest.raises(FileRejected) as exc:
        run(tmp_path, 'l.txt', 'caf\xe9'.encode('latin-1') + b'\n', 'txt')
    assert 'UTF-8' in str(exc.value)


def test_utf8_bom_is_accepted(tmp_path):
    analysis, events = run(tmp_path, 'bom.csv', '﻿timestamp,ip\n2026-10-30T13:00:00Z,192.0.2.1\n', 'csv')
    assert analysis.valid_rows == 1


def test_preview_is_limited_to_ten_lines(tmp_path):
    rows = ''.join(f'2026-10-30T13:00:{i % 60:02d}Z,192.0.2.{i % 250 + 1}\n' for i in range(40))
    analysis, _ = run(tmp_path, 'p.csv', 'timestamp,ip\n' + rows, 'csv')
    assert len(analysis.raw_preview) == 10 and len(analysis.event_preview) == 10
    assert analysis.valid_rows == 40


def test_long_message_is_truncated_and_counted(tmp_path):
    msg = 'x' * 6000
    analysis, events = run(tmp_path, 't.txt', f'2026-10-30T13:00:00Z {msg}\n', 'txt')
    assert len(events[0]['message']) == parsing.MAX_MESSAGE_CHARS
    assert any('tronqué' in w for w in analysis.warnings)


def test_format_detection_from_filename():
    assert parsing.format_for_filename('a.CSV') == 'csv'
    assert parsing.format_for_filename('a.ndjson') == 'json'
    assert parsing.format_for_filename('a.log') == 'txt'
    assert parsing.format_for_filename('a.exe') is None and parsing.format_for_filename('noext') is None
