#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def function_body(source: str, start: str, end: str) -> str:
    start_index = source.find(start)
    require(start_index >= 0, f"router marker is missing: {start}")
    end_index = source.find(end, start_index + len(start))
    require(end_index >= 0, f"router marker is missing: {end}")
    return source[start_index:end_index]


def implemented_routes(source: str) -> dict[str, tuple[str, ...]]:
    read_router = function_body(
        source,
        "Response route(MHD_Connection* connection, const std::string_view url)",
        "Response health() const",
    )
    mutation_router = function_body(
        source,
        "Response route_mutation(MHD_Connection* connection, const std::string_view url,",
        "Response route(MHD_Connection* connection, const std::string_view url)",
    )

    read_paths = set(re.findall(r'\*relative\s*==\s*"([^"]+)"', read_router))
    read_paths.update(re.findall(r'url\s*==\s*"([^"]+)"', read_router))
    mutation_paths = set(re.findall(r'\*relative\s*(?:==|!=)\s*"([^"]+)"', mutation_router))
    mutation_paths.update(re.findall(r'url\s*==\s*"([^"]+)"', mutation_router))
    mutation_paths.discard("/healthz")

    routes = {path: ("GET", "HEAD") for path in read_paths}
    for path in mutation_paths:
        require(path not in routes, f"route method extraction is ambiguous for {path}")
        routes[path] = ("POST",)
    return routes


def main() -> None:
    require(len(sys.argv) == 3, "expected API manifest and router source paths")
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    source = Path(sys.argv[2]).read_text(encoding="utf-8")

    require(manifest.get("schema_version") == 1, "unsupported API surface schema")
    require(manifest.get("api_version") == "v1", "unexpected API version")
    endpoints = manifest.get("endpoints")
    require(isinstance(endpoints, list), "endpoints must be an array")

    allowed_authentication = {"public", "management", "gateway"}
    allowed_media_types = {"application/json", "text/event-stream"}
    documented: dict[str, tuple[str, ...]] = {}
    for endpoint in endpoints:
        require(isinstance(endpoint, dict), "every endpoint must be an object")
        require(set(endpoint) == {
            "path", "methods", "authentication", "csrf", "feature", "response_media_type",
        }, f"endpoint fields drifted for {endpoint.get('path')}")
        path = endpoint["path"]
        require(isinstance(path, str) and path.startswith("/"), "endpoint path is invalid")
        require(path == "/healthz" or path.startswith("/api/v1/"),
                f"endpoint escapes the versioned API: {path}")
        require(path not in documented, f"duplicate endpoint: {path}")
        methods = endpoint["methods"]
        require(methods in (["GET", "HEAD"], ["POST"]), f"unsupported methods for {path}")
        require(endpoint["authentication"] in allowed_authentication,
                f"invalid authentication boundary for {path}")
        require(isinstance(endpoint["csrf"], bool), f"invalid CSRF marker for {path}")
        require(endpoint["csrf"] == (methods == ["POST"]),
                f"mutation CSRF policy drifted for {path}")
        if methods == ["POST"]:
            require(endpoint["authentication"] == "gateway",
                    f"mutation authentication weakened for {path}")
        require(endpoint["feature"] is None or
                re.fullmatch(r"[a-z][a-z0-9_]{0,63}", endpoint["feature"]),
                f"invalid feature name for {path}")
        require(endpoint["response_media_type"] in allowed_media_types,
                f"invalid media type for {path}")
        if endpoint["response_media_type"] == "text/event-stream":
            require(path == "/api/v1/events", "unexpected event stream endpoint")
        documented[path] = tuple(methods)

    require(documented == implemented_routes(source),
            "API surface manifest and C++ router have different paths or methods")

    public_paths = {
        path for path, endpoint in ((item["path"], item) for item in endpoints)
        if endpoint["authentication"] == "public"
    }
    require(public_paths == {"/healthz", "/api/v1/capabilities", "/api/v1/auth/session"},
            "public endpoint boundary drifted")
    gateway_paths = {
        item["path"] for item in endpoints if item["authentication"] == "gateway"
    }
    require(gateway_paths == {
        "/api/v1/config/snapshot",
        "/api/v1/config/draft",
        "/api/v1/config/draft/preflight",
        "/api/v1/config/draft/changes",
        "/api/v1/config/draft/validate",
        "/api/v1/config/draft/commit",
        "/api/v1/config/draft/clear",
    }, "trusted-gateway endpoint boundary drifted")
    require(all(item["authentication"] == "management" for item in endpoints
                if item["path"] not in public_paths | gateway_paths),
            "monitoring endpoint boundary drifted")

    features = {item["path"]: item["feature"] for item in endpoints}
    require(features == {
        "/healthz": None,
        "/api/v1/capabilities": None,
        "/api/v1/auth/session": None,
        "/api/v1/status": None,
        "/api/v1/metrics/summary": "metrics",
        "/api/v1/tls/cache/summary": "tls_monitoring",
        "/api/v1/network/neighbors/summary": "neighbor_monitoring",
        "/api/v1/sessions/activity": "session_activity",
        "/api/v1/events/recent": "events",
        "/api/v1/events": "events",
        "/api/v1/alerts": "alerts",
        "/api/v1/audit/recent": "audit",
        "/api/v1/config/snapshot": "config_read",
        "/api/v1/config/draft": "drafts",
        "/api/v1/config/draft/preflight": "draft_preflight",
        "/api/v1/config/draft/changes": "drafts",
        "/api/v1/config/draft/validate": "draft_preflight",
        "/api/v1/config/draft/commit": "config_write",
        "/api/v1/config/draft/clear": "drafts",
    }, "endpoint capability mapping drifted")


if __name__ == "__main__":
    main()
