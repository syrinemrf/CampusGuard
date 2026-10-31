import json
from pathlib import Path
from app.main import app
from bus.event_bus import EventBus, RedisBus, KafkaBus

ROOT = Path(__file__).resolve().parents[1]

def test_health():
    with app.test_client() as c:
        res = c.get('/health')
        assert res.status_code == 200
        assert res.get_json()['status'] == 'ok'

def test_mapping():
    data = json.loads((ROOT / 'ingestion/elasticsearch/logs-template.json').read_text())
    assert data['template']['mappings']['dynamic'] is False
    assert data['template']['mappings']['properties']['source']['properties']['ip']['type'] == 'ip'
    setup_script = (ROOT / 'scripts/setup-index.sh').read_text()
    assert 'logs-*/_mapping' in setup_script
    assert "'{\"dynamic\":false}'" in setup_script


def test_logstash_read_inputs_preserve_source_files():
    for pipeline in ('csv.conf', 'json.conf'):
        config = (ROOT / 'ingestion/logstash/pipeline' / pipeline).read_text()
        assert 'mode => "read"' in config
        assert 'file_completed_action => "log"' in config


def test_json_pipeline_rejects_invalid_field_types_and_fingerprints_user():
    config = (ROOT / 'ingestion/logstash/pipeline/json.conf').read_text()
    assert "event.tag('_invalid_field_type')" in config
    assert 'tag_on_exception => "_invalid_field_type"' in config
    assert '"_rubyexception" in [tags]' in config
    assert (
        'source => ["[@timestamp]", "[source][ip]", "[user][name]", '
        '"[service][name]"'
    ) in config


def test_reject_invalid_topic():
    try:
        EventBus.validate('bogus', {})
    except ValueError:
        return
    assert False

class FakeRedis:
    def __init__(self): self.calls = []
    def xadd(self, *a, **kw): self.calls.append(('xadd', a))
    def publish(self, *a): self.calls.append(('publish', a))

def test_redis_bus():
    redis = FakeRedis()
    RedisBus(redis).publish('logs.auth', {'action': 'login'}, '192.0.2.1')
    assert [c[0] for c in redis.calls] == ['xadd', 'publish']

class FakeKafka:
    def __init__(self): self.calls = []
    def produce(self, *a, **kw): self.calls.append((a, kw))
    def poll(self, t): pass
    def flush(self, t): return 0

def test_kafka_bus():
    producer = FakeKafka()
    bus = KafkaBus(producer)
    bus.publish('alerts', {'severity': 'high'}, '203.0.113.8')
    assert producer.calls[0][1]['key'] == b'203.0.113.8'
    assert bus.flush() == 0
