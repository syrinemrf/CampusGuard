"""Separate alerting worker process (container ``alert-worker``): evaluates the rules every ALERT_INTERVAL_SECONDS.

    python -m app.alerting.worker               # run forever
    python -m app.alerting.worker --once        # one cycle (demo, tests, cron)
    python -m app.alerting.worker --healthcheck # exit 0 if a cycle ran recently (Docker healthcheck)

Why a plain loop and not Celery? One periodic job does not need a broker, a beat scheduler and a pool of
workers; on a 16 GB laptop already running ELK the saving (~150 MB) matters. The properties that Celery would
give are implemented explicitly and tested:
- **single runner**: a Redis lock (SET NX EX) — two workers never evaluate the same cycle twice;
- **idempotence**: alert fingerprints + silencing + cooldown (engine.py) — re-running a cycle creates nothing new;
- **recovery after an error**: an exception in a cycle is logged, the loop sleeps and tries again; a failing rule
  is recorded on the rule (last_status = error) and does not block the others;
- **observability**: a heartbeat in Redis (shown on the home page and the alerts page).
"""
import argparse
import json
import logging
import signal
import socket
import sys
import time

from app.alerting.engine import HEARTBEAT_KEY, LOCK_KEY, AlertEngine
from app.alerting.rules import RuleStore
from app.config import Config
from app.stores import build_stores, ensure_indexes

log = logging.getLogger('sentinel.alerting.worker')


class Worker:
    def __init__(self, stores, config, engine=None, sleep=time.sleep):
        self.stores, self.cfg = stores, config
        self.engine = engine or AlertEngine(stores, config)
        self.sleep = sleep
        self.running = True
        self.owner = f'{socket.gethostname()}:{id(self)}'

    def cycle(self):
        """Run one cycle if this process gets the lock. Returns the summary, or None if another worker holds it."""
        redis, interval = self.stores.redis, max(5, self.cfg.alert_interval_seconds)
        if not redis.set(LOCK_KEY, self.owner, nx=True, ex=interval * 2):
            return None
        try:
            summary = self.engine.run_once()
            summary['worker'] = self.owner
            redis.setex(HEARTBEAT_KEY, interval * 4, json.dumps(summary))
            log.info('cycle: %s', summary)
            return summary
        finally:
            if redis.get(LOCK_KEY) == self.owner:
                redis.delete(LOCK_KEY)

    def run(self):
        ensure_indexes(self.stores.db)
        created = RuleStore(self.stores.db).seed_defaults()
        if created:
            log.info('default rules created: %s', ', '.join(created))
        interval = max(5, self.cfg.alert_interval_seconds)
        while self.running:
            try:
                self.cycle()
            except Exception:  # noqa: BLE001 - recovery: log, wait, retry on the next cycle
                log.exception('alerting cycle failed; retrying in %s s', interval)
            self.sleep(interval)

    def stop(self, *_):
        self.running = False


def healthcheck(stores, config):
    raw = stores.redis.get(HEARTBEAT_KEY)
    return bool(raw)


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--healthcheck', action='store_true')
    args = ap.parse_args(argv)
    config = Config()
    stores = build_stores(config)
    if args.healthcheck:
        return 0 if healthcheck(stores, config) else 1
    worker = Worker(stores, config)
    if args.once:
        ensure_indexes(stores.db)
        RuleStore(stores.db).seed_defaults()
        print(json.dumps(worker.cycle() or {'skipped': 'another worker holds the lock'}, ensure_ascii=False))
        return 0
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    worker.run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
