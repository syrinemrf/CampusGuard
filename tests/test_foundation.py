import json
from pathlib import Path
from app.main import app
from bus.event_bus import EventBus, RedisBus, KafkaBus
from simulator.generate import generate

ROOT = Path(__file__).resolve().parents[1]

def test_health():
    with app.test_client() as c:
        res = c.get('/health')
        assert res.status_code == 200
        assert res.get_json()['status'] == 'ok'

def test_mapping():
    data = json.loads((ROOT / 'ingestion/elasticsearch/logs-template.json').read_text())
    assert data['template']['mappings']['properties']['source']['properties']['ip']['type'] == 'ip'

def test_generator():
    assert generate(40) == 40
    lines = (ROOT / 'datasets/samples/auth.jsonl').read_text().splitlines()
    assert len(lines) == 40
    assert {'attack', 'normal'} == {json.loads(row)['labels']['ground_truth'] for row in lines}

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
