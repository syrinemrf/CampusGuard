"""Experimental logical event bus adapter for S3; not a durable production queue."""
from abc import ABC, abstractmethod
import json

TOPICS = frozenset({'logs.honeypot', 'logs.auth', 'logs.sim', 'logs.firewall', 'alerts'})

class EventBus(ABC):
    @abstractmethod
    def publish(self, topic: str, event: dict, key: str | None = None) -> None: ...

    @staticmethod
    def validate(topic, event):
        if topic not in TOPICS or not isinstance(event, dict):
            raise ValueError('Unknown topic or invalid event')

class RedisBus(EventBus):
    """S1 proof of concept: Redis Stream for persisted events and Pub/Sub for live UI."""
    def __init__(self, client): self.client = client
    def publish(self, topic, event, key=None):
        self.validate(topic, event)
        payload = json.dumps({'key': key, 'event': event}, ensure_ascii=False)
        self.client.xadd(f'sentinel:{topic}', {'payload': payload}, maxlen=10000, approximate=True)
        self.client.publish(f'sentinel:live:{topic}', payload)

class KafkaBus(EventBus):
    def __init__(self, producer): self.producer = producer
    def publish(self, topic, event, key=None):
        self.validate(topic, event)
        self.producer.produce(topic, key=key.encode() if key else None,
                              value=json.dumps(event).encode())
        self.producer.poll(0)
    def flush(self, timeout=10):
        return self.producer.flush(timeout)
