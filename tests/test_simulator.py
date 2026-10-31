import csv
import json
from datetime import datetime, timedelta

import pytest

from simulator.generate import generate


def test_generator_writes_both_sources_to_requested_directory(tmp_path):
    assert generate(40, output_dir=tmp_path) == 40

    auth_events = [
        json.loads(line)
        for line in (tmp_path / 'auth.jsonl').read_text(encoding='utf-8').splitlines()
    ]
    with (tmp_path / 'firewall.csv').open(encoding='utf-8', newline='') as source:
        firewall_events = list(csv.DictReader(source))

    assert len(auth_events) == 40
    assert len(firewall_events) == 40
    assert {'attack', 'normal'} == {
        event['labels']['ground_truth'] for event in auth_events
    }
    assert sum(event['labels']['ground_truth'] == 'attack' for event in auth_events) == 3
    assert sum(event['action'] == 'deny' for event in firewall_events) == 3
    assert all(
        datetime.fromisoformat(event['timestamp']).utcoffset() == timedelta(0)
        for event in auth_events
    )


def test_generator_is_deterministic_for_same_seed(tmp_path):
    first = tmp_path / 'first'
    second = tmp_path / 'second'

    generate(20, seed=99, output_dir=first)
    generate(20, seed=99, output_dir=second)

    assert (first / 'auth.jsonl').read_bytes() == (second / 'auth.jsonl').read_bytes()
    assert (first / 'firewall.csv').read_bytes() == (second / 'firewall.csv').read_bytes()


def test_generator_accepts_zero_events(tmp_path):
    assert generate(0, output_dir=tmp_path) == 0
    assert (tmp_path / 'auth.jsonl').read_text(encoding='utf-8') == ''

    with (tmp_path / 'firewall.csv').open(encoding='utf-8', newline='') as source:
        assert list(csv.reader(source)) == [['timestamp', 'ip', 'action', 'port', 'level']]


def test_generator_rejects_negative_count_before_creating_output(tmp_path):
    output_dir = tmp_path / 'not-created'

    with pytest.raises(ValueError, match='greater than or equal to zero'):
        generate(-1, output_dir=output_dir)

    assert not output_dir.exists()


@pytest.mark.parametrize('invalid_count', [1.5, '10', True])
def test_generator_rejects_non_integer_count(tmp_path, invalid_count):
    with pytest.raises(TypeError, match='must be an integer'):
        generate(invalid_count, output_dir=tmp_path)
