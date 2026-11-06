"""Application configuration, read from environment variables (never from git)."""
import os
from dataclasses import dataclass, field


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return int(default)


def _float(name, default):
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return float(default)


def _bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {'1', 'true', 'yes', 'on'}


def _env(name, default):
    return field(default_factory=lambda: os.getenv(name, default))


@dataclass
class Config:
    secret_key: str = _env('FLASK_SECRET_KEY', 'local-only-secret')
    elasticsearch_url: str = field(default_factory=lambda: os.getenv('ELASTICSEARCH_URL', 'http://elasticsearch:9200').rstrip('/'))
    mongo_uri: str = _env('MONGO_URI', 'mongodb://mongodb:27017/')
    mongo_db: str = _env('MONGO_DB', 'sentinel')
    redis_url: str = _env('REDIS_URL', 'redis://redis:6379/0')
    logs_index: str = _env('ES_LOGS_INDEX', 'logs-*')
    upload_dir: str = _env('UPLOAD_DIR', '/data/uploads')
    rejected_dir: str = _env('REJECTED_DIR', '/data/rejected')
    max_upload_mb: int = field(default_factory=lambda: _int('MAX_UPLOAD_MB', 10))
    max_invalid_ratio: float = field(default_factory=lambda: _float('MAX_INVALID_RATIO', 0.5))
    session_ttl: int = field(default_factory=lambda: _int('SESSION_TTL_SECONDS', 7200))
    session_cookie_secure: bool = field(default_factory=lambda: _bool('SESSION_COOKIE_SECURE', False))
    login_max_failures: int = field(default_factory=lambda: _int('LOGIN_MAX_FAILURES', 5))
    login_window_seconds: int = field(default_factory=lambda: _int('LOGIN_WINDOW_SECONDS', 300))
    search_cache_ttl: int = field(default_factory=lambda: _int('SEARCH_CACHE_TTL', 30))
    export_max_rows: int = field(default_factory=lambda: _int('EXPORT_MAX_ROWS', 5000))
    kibana_public_url: str = _env('KIBANA_PUBLIC_URL', 'http://localhost:5601')
    api_rate_limit: int = field(default_factory=lambda: _int('API_RATE_LIMIT_PER_MIN', 300))
    ingest_stall_seconds: int = field(default_factory=lambda: _int('INGEST_STALL_SECONDS', 300))
    testing: bool = False
