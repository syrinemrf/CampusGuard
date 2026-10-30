"""Deterministic, non-sensitive synthetic authentication + firewall samples."""
import csv
import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / 'datasets' / 'samples'

def generate(n=100, seed=2026):
    rng = random.Random(seed)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    base = datetime(2026, 10, 30, 13, 0, tzinfo=timezone.utc)
    with (OUTPUT / 'auth.jsonl').open('w', encoding='utf8') as auth, \
            (OUTPUT / 'firewall.csv').open('w', newline='', encoding='utf8') as firewall:
        writer = csv.writer(firewall)
        writer.writerow(['timestamp', 'ip', 'action', 'port', 'level'])
        for i in range(n):
            attack = i % 17 == 0
            ip = '203.0.113.50' if attack else f'192.0.2.{rng.randint(1,220)}'
            stamp = (base + timedelta(seconds=i*30)).isoformat()
            event = {'timestamp': stamp, 'source_ip': ip, 'username': f'user_{rng.randint(1,20)}',
                     'outcome': 'failure' if attack else 'success', 'level': 'WARNING' if attack else 'INFO',
                     'message': 'Simulated failed login' if attack else 'Simulated successful login',
                     'labels': {'ground_truth': 'attack' if attack else 'normal'}}
            auth.write(json.dumps(event) + '\n')
            writer.writerow([stamp, ip, 'deny' if attack else 'allow', 22 if attack else 443,
                             'WARNING' if attack else 'INFO'])
    return n

if __name__ == '__main__':
    print(f'Generated {generate()} synthetic records per source in {OUTPUT}')
