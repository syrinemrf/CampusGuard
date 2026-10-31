#!/usr/bin/env python3
"""Wait for and verify the locally exposed CampusGuard CORE stack.

This script intentionally uses only the Python standard library so it can run
from the host before the application dependencies have been installed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable


DEFAULT_FLASK_URL = os.getenv("CAMPUSGUARD_FLASK_URL", "http://127.0.0.1:8000")
DEFAULT_ELASTICSEARCH_URL = os.getenv(
    "CAMPUSGUARD_ELASTICSEARCH_URL", "http://127.0.0.1:9200"
)
DEFAULT_KIBANA_URL = os.getenv("CAMPUSGUARD_KIBANA_URL", "http://127.0.0.1:5601")


@dataclass(frozen=True)
class CheckResult:
    passed: bool
    detail: str


class JsonClient:
    """Small JSON HTTP client that turns transport errors into check details."""

    def __init__(self, base_url: str, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self, path: str, *, method: str = "GET", body: dict[str, Any] | None = None
    ) -> tuple[int | None, Any | None, str]:
        encoded_body = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "campusguard-core-verifier/1.0",
        }
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=encoded_body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
                return response.status, _decode_json(raw), raw
        except urllib.error.HTTPError as error:
            raw = error.read().decode("utf-8", errors="replace")
            return error.code, _decode_json(raw), raw
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return None, None, _short_error(error)


def _decode_json(raw: str) -> Any | None:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None


def _short_error(error: BaseException) -> str:
    detail = getattr(error, "reason", error)
    return str(detail).replace("\r", " ").replace("\n", " ")[:240]


def _http_failure(status: int | None, raw: str) -> str:
    if status is None:
        return f"connexion impossible: {raw}"
    excerpt = raw.replace("\r", " ").replace("\n", " ").strip()[:180]
    return f"HTTP {status}" + (f": {excerpt}" if excerpt else "")


def _nested_value(document: dict[str, Any], dotted_path: str) -> Any | None:
    value: Any = document
    for part in dotted_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def check_flask_ready(client: JsonClient) -> CheckResult:
    status, payload, raw = client.request("/ready")
    if status != 200:
        return CheckResult(False, _http_failure(status, raw))
    if not isinstance(payload, dict):
        return CheckResult(False, "réponse /ready non JSON")

    services = payload.get("services")
    required = ("elasticsearch", "mongodb", "redis")
    if not isinstance(services, dict):
        return CheckResult(False, "champ services absent de /ready")
    failing = [name for name in required if services.get(name) != "ok"]
    if failing:
        states = ", ".join(f"{name}={services.get(name)!r}" for name in failing)
        return CheckResult(False, f"services non prêts: {states}")
    if payload.get("status") != "ready":
        return CheckResult(False, f"status={payload.get('status')!r}, attendu 'ready'")
    return CheckResult(True, "HTTP 200; Elasticsearch, MongoDB et Redis = ok")


def check_index_template(client: JsonClient, template_name: str) -> CheckResult:
    quoted_name = urllib.parse.quote(template_name, safe="-_.")
    status, payload, raw = client.request(f"/_index_template/{quoted_name}")
    if status != 200:
        return CheckResult(False, _http_failure(status, raw))
    templates = payload.get("index_templates") if isinstance(payload, dict) else None
    names = {
        item.get("name")
        for item in templates or []
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if template_name not in names:
        return CheckResult(False, f"template {template_name!r} absent de la réponse")
    return CheckResult(True, f"template {template_name!r} présent")


def check_index_count(client: JsonClient, pattern: str, minimum: int) -> CheckResult:
    quoted_pattern = urllib.parse.quote(pattern, safe="*-_.")
    path = f"/{quoted_pattern}/_count?allow_no_indices=false&ignore_unavailable=false"
    status, payload, raw = client.request(path)
    if status != 200:
        return CheckResult(False, _http_failure(status, raw))
    count = payload.get("count") if isinstance(payload, dict) else None
    if not isinstance(count, int):
        return CheckResult(False, "compteur Elasticsearch absent ou invalide")
    if count < minimum:
        return CheckResult(False, f"{count} document(s), minimum attendu: {minimum}")
    return CheckResult(True, f"{count} document(s) (minimum {minimum})")


def check_ecs_sample(
    client: JsonClient, pattern: str, required_fields: tuple[str, ...]
) -> CheckResult:
    quoted_pattern = urllib.parse.quote(pattern, safe="*-_.")
    filters = [{"exists": {"field": field}} for field in required_fields]
    body = {
        "size": 1,
        "track_total_hits": False,
        "_source": list(required_fields),
        "query": {"bool": {"filter": filters}},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }
    status, payload, raw = client.request(
        f"/{quoted_pattern}/_search?allow_no_indices=false&ignore_unavailable=false",
        method="POST",
        body=body,
    )
    if status != 200:
        return CheckResult(False, _http_failure(status, raw))
    try:
        hits = payload["hits"]["hits"]
        source = hits[0]["_source"]
    except (KeyError, IndexError, TypeError):
        return CheckResult(False, "aucun document ne contient tous les champs attendus")

    missing = [field for field in required_fields if _nested_value(source, field) is None]
    if missing:
        return CheckResult(False, "champs absents de l'échantillon: " + ", ".join(missing))
    return CheckResult(True, "champs présents: " + ", ".join(required_fields))


def check_kibana_status(client: JsonClient) -> CheckResult:
    status, payload, raw = client.request("/api/status")
    if status != 200:
        return CheckResult(False, _http_failure(status, raw))
    try:
        level = payload["status"]["overall"]["level"]
    except (KeyError, TypeError):
        return CheckResult(False, "niveau global absent de /api/status")
    if level != "available":
        return CheckResult(False, f"niveau global Kibana: {level!r}")
    return CheckResult(True, "HTTP 200; niveau global = available")


def _data_view_titles(payload: Any) -> set[str]:
    if not isinstance(payload, dict):
        return set()
    views = payload.get("data_view") or payload.get("data_views") or []
    if isinstance(views, dict):
        views = [views]
    return {
        item.get("title")
        for item in views
        if isinstance(item, dict) and isinstance(item.get("title"), str)
    }


def _saved_object_titles(payload: Any) -> set[str]:
    if not isinstance(payload, dict):
        return set()
    titles: set[str] = set()
    for item in payload.get("saved_objects", []):
        attributes = item.get("attributes") if isinstance(item, dict) else None
        if isinstance(attributes, dict) and isinstance(attributes.get("title"), str):
            titles.add(attributes["title"])
    return titles


def check_kibana_data_view(client: JsonClient, expected_title: str) -> CheckResult:
    status, payload, raw = client.request("/api/data_views")
    titles = _data_view_titles(payload) if status == 200 else set()
    if expected_title in titles:
        return CheckResult(True, f"data view {expected_title!r} présente")

    # The saved-objects endpoint keeps this check compatible with Kibana builds
    # that do not expose the collection form of /api/data_views.
    query = urllib.parse.urlencode({"type": "index-pattern", "per_page": 1000})
    fallback_status, fallback_payload, fallback_raw = client.request(
        f"/api/saved_objects/_find?{query}"
    )
    titles.update(_saved_object_titles(fallback_payload) if fallback_status == 200 else set())
    if expected_title in titles:
        return CheckResult(True, f"data view {expected_title!r} présente")

    if status != 200 and fallback_status != 200:
        return CheckResult(
            False,
            "API data views indisponible: "
            + _http_failure(status, raw)
            + "; fallback: "
            + _http_failure(fallback_status, fallback_raw),
        )
    observed = ", ".join(sorted(titles)[:8]) or "aucune"
    return CheckResult(False, f"data view {expected_title!r} absente (observées: {observed})")


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("la valeur doit être strictement positive")
    return parsed


def non_negative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("la valeur doit être positive ou nulle")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("la valeur doit être strictement positive")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Attend puis vérifie la stack CORE CampusGuard exposée en local."
    )
    parser.add_argument("--flask-url", default=DEFAULT_FLASK_URL)
    parser.add_argument("--elasticsearch-url", default=DEFAULT_ELASTICSEARCH_URL)
    parser.add_argument("--kibana-url", default=DEFAULT_KIBANA_URL)
    parser.add_argument(
        "--wait-timeout",
        type=non_negative_float,
        default=300.0,
        help="délai total d'attente en secondes (défaut: 300)",
    )
    parser.add_argument(
        "--request-timeout",
        type=positive_float,
        default=5.0,
        help="délai de chaque requête HTTP en secondes (défaut: 5)",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=5.0,
        help="intervalle entre deux passes en secondes (défaut: 5)",
    )
    parser.add_argument(
        "--min-docs",
        type=positive_int,
        default=100,
        help="minimum requis pour chaque famille d'indices (défaut: 100)",
    )
    parser.add_argument("--template", default="campusguard-logs")
    parser.add_argument("--data-view", default="logs-*")
    return parser.parse_args(argv)


def build_checks(args: argparse.Namespace) -> list[tuple[str, Callable[[], CheckResult]]]:
    flask = JsonClient(args.flask_url, args.request_timeout)
    elasticsearch = JsonClient(args.elasticsearch_url, args.request_timeout)
    kibana = JsonClient(args.kibana_url, args.request_timeout)
    auth_fields = (
        "@timestamp",
        "log.level",
        "service.name",
        "source.ip",
        "event.outcome",
    )
    firewall_fields = (
        "@timestamp",
        "log.level",
        "service.name",
        "source.ip",
        "event.action",
        "destination.port",
    )
    return [
        ("Flask /ready", lambda: check_flask_ready(flask)),
        (
            "Template Elasticsearch",
            lambda: check_index_template(elasticsearch, args.template),
        ),
        (
            "Documents authentification",
            lambda: check_index_count(elasticsearch, "logs-auth-*", args.min_docs),
        ),
        (
            "Documents pare-feu",
            lambda: check_index_count(elasticsearch, "logs-firewall-*", args.min_docs),
        ),
        (
            "Échantillon ECS authentification",
            lambda: check_ecs_sample(elasticsearch, "logs-auth-*", auth_fields),
        ),
        (
            "Échantillon ECS pare-feu",
            lambda: check_ecs_sample(elasticsearch, "logs-firewall-*", firewall_fields),
        ),
        ("Kibana /api/status", lambda: check_kibana_status(kibana)),
        (
            "Data view Kibana",
            lambda: check_kibana_data_view(kibana, args.data_view),
        ),
    ]


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    checks = build_checks(args)
    started = time.monotonic()
    deadline = started + args.wait_timeout
    attempt = 0
    results: list[tuple[str, CheckResult]] = []

    print(
        "Vérification CORE CampusGuard "
        f"(attente max. {args.wait_timeout:g}s, intervalle {args.interval:g}s)"
    )
    while True:
        attempt += 1
        results = []
        for name, check in checks:
            try:
                result = check()
            except Exception as error:  # Keep one unexpected check failure readable.
                result = CheckResult(False, f"erreur inattendue: {_short_error(error)}")
            results.append((name, result))

        failures = [name for name, result in results if not result.passed]
        if not failures:
            break
        now = time.monotonic()
        if now >= deadline:
            break
        remaining = max(0.0, deadline - now)
        print(
            f"[WAIT] passe {attempt}: {len(failures)} contrôle(s) en attente; "
            f"reste {remaining:.0f}s"
        )
        time.sleep(min(args.interval, remaining))

    elapsed = time.monotonic() - started
    print()
    for name, result in results:
        marker = "PASS" if result.passed else "FAIL"
        print(f"[{marker}] {name}: {result.detail}")
    passed = sum(result.passed for _, result in results)
    print(f"\nRésultat: {passed}/{len(results)} contrôles PASS en {elapsed:.1f}s")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        print("\nVérification interrompue.", file=sys.stderr)
        sys.exit(130)
