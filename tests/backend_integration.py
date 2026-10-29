#!/usr/bin/env python3

import http.client
import http.server
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(port: int, path: str, method: str = "GET", headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    body = response.read()
    headers = dict(response.getheaders())
    connection.close()
    return response.status, headers, body


def assert_error_response(result, expected_status: int, expected_code: str) -> str:
    status, headers, body = result
    assert status == expected_status
    request_id = headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]+-[1-9][0-9]*", request_id)
    document = json.loads(body)
    assert document["error"]["code"] == expected_code
    assert document["error"]["request_id"] == request_id
    assert isinstance(document["error"]["message"], str)
    assert document["error"]["message"]
    assert document["error"]["retryable"] is False
    assert document["error"]["fields"] == []
    assert document["error"]["details"] == {}
    return request_id


class FakeSmithproxy(http.server.BaseHTTPRequestHandler):
    api_key = None
    response_status = 200
    config_revision = "sha256:" + "c" * 64
    revision_requests = 0
    transaction_capabilities = {
        "success": {
            "transaction_version": 1,
            "operation_version": 1,
            "stable_entity_ids": True,
            "operations": ["set", "create", "delete", "move"],
            "maximum_operations": 4096,
            "maximum_request_bytes": 1048576,
            "collections": [{
                "id": "policy", "ordered": True, "nested": False,
                "schema_revision": "sha256:" + "a" * 64,
            }],
        },
    }
    config_sections = {
        "policy": [{
            "name": "office policy", "disabled": "0",
            "proto": "tcp", "src": ["office"], "sport": ["any"],
            "dst": ["internet"], "dport": ["https"], "action": "accept",
            "nat": "masquerade", "routing": "main", "tls_profile": "inspect",
            "features": ["sinkhole"], "ssh_profile": "", "detection_profile": "default-detection",
            "content_profile": "safe-content", "auth_profile": "", "alg_dns_profile": "",
            "script_profile": "audit-script",
        }],
        "address_objects": {
            "office": {"type": "cidr", "value": "10.0.0.0/24"},
            "internet": {"type": "fqdn", "value": "example.test"},
        },
        "port_objects": {"https": {"start": "443", "end": "443"}},
        "proto_objects": {"tcp": {"id": "6"}},
        "detection_profiles": {"default-detection": {"mode": "1"}},
        "content_profiles": {"safe-content": {
            "write_payload": "false",
            "content_rules": [{
                "match": "private-content-match", "replace": "private-content-replacement",
                "fill_length": "true", "replace_each_nth": "3",
            }],
        }},
        "tls_profiles": {"inspect": {}},
        "ssh_profiles": {"default-ssh": {"host_key": "/redacted/test-key"}},
        "alg_dns_profiles": {},
        "script_profiles": {"audit-script": {}},
        "auth_profiles": {},
        "routing": {"main": {}},
        "settings": {
            "accept_tproxy": "true", "accept_redirect": "true",
            "accept_socks": "false", "accept_http_connect": "true", "accept_api": "true",
            "extended_local_destination_protection": "true",
            "policy_fail_open": "false", "policy_access_request_fail_open": "false",
            "plaintext_workers": "2", "ssl_workers": "4", "udp_workers": "1",
            "dtls_workers": "1", "quic_workers": "-1", "socks_workers": "-1",
            "http_connect_workers": "1", "ssl_autodetect": "true",
            "plaintext_port": "50080", "ssl_port": "50443", "udp_port": "50080",
            "dtls_port": "50443", "quic_port": "443", "socks_port": "1080",
            "http_connect_port": "3128", "tpool_log": "false",
            "ssl_ocsp_status_ttl": "1800", "ssl_crl_status_ttl": "86400",
            "default_write_payload": "false", "write_payload_dir": "/private/payloads",
            "write_pcap_single_quota": "100", "log_level": "6",
            "log_file": "/private/log/messages.log", "log_console": "true",
            "sslkeylog_file": "/private/log/tls.keys", "syslog_server": "192.0.2.60",
            "syslog_port": "514", "syslog_facility": "23", "syslog_level": "6",
            "syslog_family": "4",
            "udp_quick_ports": ["0"], "certs_path": "/private/certs",
            "certs_ca_key_password": "private-ca-password",
            "certs_ctlog": "/private/ct-log-list.cnf",
            "ca_bundle_path": "/private/ca-bundle", "ca_bundle_file": "/private/ca-bundle.pem",
            "messages_dir": "/private/messages", "admin": {"group": "private-admins"},
            "write_payload_file_prefix": "private-prefix",
            "write_payload_file_suffix": "private-suffix",
            "cli": {"port": "50000", "enable_password": "private-cli-password"},
            "tuning": {
                "host_bufsz_min": "2048", "host_bufsz_max_multiplier": "1024",
                "host_write_full": "200000", "host_io_batch": "262144",
                "tls_write_chunk": "20480", "host_open_timeout": "7",
                "host_idle_timeout": "3600", "nbr_cache_size": "8000",
            },
            "web_rating": {"wot_key": "private-rating-key"},
            "socks": {"async_dns": "true", "ipver_mixing": "true", "prefer_ipv6": "false"},
            "ssl_autodetect_harder": "false", "ssl_use_ktls": "false",
            "nameservers": ["192.0.2.53"],
            "http_api": {
                "keys": ["backend-secret-value"], "allowed_ips": ["127.0.0.1"],
                "key_timeout": "3600", "port": "55555", "key_extend_on_access": "true",
                "loopback_only": "true", "pam_login": "false", "allow_api_header": "false",
                "bind_address": "192.0.2.77", "bind_interface": "private-api0",
            },
            "webhook": {
                "enabled": "true", "tls_verify": "true",
                "url": "https://private-webhook.example/", "sift": "true",
                "sift_url": "http://private-sift.example/webhook",
                "sift_tenant_id": "private-tenant", "sift_instance_id": "private-instance",
                "sift_payload_limit_per_direction": "524288", "hostid": "private-host-id",
                "sift_lored_mode": "optional", "sift_lored_include_url": "true",
                "bind_interface": "private-webhook0", "api_override": "false",
                "ping_interval": "60", "nbr_update_interval": "600",
                "nbr_tag_refresh_age": "240", "task_debug": "true",
                "task_debug_dump": "false",
            },
        },
        "debug": {
            "log_data_crc": "false", "log_sockets": "true",
            "log_online_cx_name": "false", "log_srclines": "true",
            "log_srclines_always": "false", "log": {"proxy": "7"},
        },
        "captures": {
            "local": {
                "enabled": "true", "dir": "/private/captures", "format": "pcap_single",
                "pcap_quota": "512", "file_prefix": "secret-prefix", "file_suffix": ".pcap",
            },
            "remote": {
                "enabled": "false", "tun_type": "gre", "gre_format": "traffic",
                "tun_dst": "192.0.2.10", "tun_ttl": "1", "bind_interface": "private0",
            },
            "options": {"calculate_checksums": "true"},
        },
        "tls_ca": {
            "default": {"path": "/private/ca/default"},
        },
        "starttls_signatures": [
            {"name": "smtp/starttls", "severity": "2", "flow": [{"signature": "secret-starttls-regex"}]},
        ],
        "detection_signatures": [
            {"name": "http/request", "severity": "4", "flow": [
                {"signature": "secret-detection-regex"},
                {"signature": "another-secret-regex"},
            ]},
        ],
    }

    def do_GET(self):
        if self.path == "/api/status/ping":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(FakeSmithproxy.response_status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        if self.path == "/api/config/v2/capabilities":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(FakeSmithproxy.transaction_capabilities).encode())
            return
        if self.path == "/api/config/v2/revision":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            FakeSmithproxy.revision_requests += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": {"revision": FakeSmithproxy.config_revision},
            }).encode())
            return
        if self.path == "/api/diag/proxy/listener/stats":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"listeners": [
                {"name": "tcp", "workers": 2, "sessions_total": 12,
                 "sessions_active": 3, "bytes_up": 1024, "bytes_down": 2048},
                {"name": "tls", "workers": 1, "sessions_total": 7,
                 "sessions_active": 1, "bytes_up": 512, "bytes_down": 256},
            ]}).encode())
            return
        if self.path == "/api/diag/ssl/cache/stats":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"cache_size":42,"max_size":1000}')
            return
        if self.path == "/api/diag/proxy/neighbor/list?max_days=30":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {"hostname": "private-neighbor.example", "tags": "office", "last_seen": 1,
                 "stats": [{"relative_days": 0, "counter": 3, "bytes_up": 100, "bytes_down": 200}]},
                {"hostname": "another-private.example", "tags": "", "last_seen": 1,
                 "stats": [{"relative_days": 3, "counter": 4, "bytes_up": 10, "bytes_down": 20}]},
            ]).encode())
            return
        if self.path == "/api/v1/network/interfaces/summary":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "schema_version": 1,
                "state": "ready",
                "generation": 42,
                "sampled_at_unix_ms": int(time.time() * 1000),
                "synchronization": {
                    "running": True, "attempts": 3, "successes": 3, "errors": 0,
                    "event_datagrams": 15, "changed_event_datagrams": 4,
                },
                "totals": {
                    "interfaces": 3, "addresses": 5,
                    "ipv4_addresses": 3, "ipv6_addresses": 2,
                },
                "last_error": None,
            }).encode())
            return
        if self.path == "/api/diag/proxy/session/list":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {
                    "oid": "secret-session-id",
                    "origin": "tls acceptor",
                    "policy": "confidential-policy",
                    "left": [{"host": "10.20.30.40", "port": "43100", "com": "tls"}],
                    "right": [{"host": "private.example", "port": "443", "com": "tls"}],
                    "stats": {
                        "speed": {"up": 100, "down": 200},
                        "counters": {"bytes_up": 1000, "bytes_down": 2000},
                    },
                },
                {
                    "oid": "another-secret-session-id",
                    "origin": "plain acceptor",
                    "policy": "another-confidential-policy",
                    "left": [{"host": "10.20.30.41", "port": "43101", "com": "tcp"}],
                    "right": [{"host": "other.private", "port": "80", "com": "tcp"}],
                    "stats": {
                        "speed": {"up": 25, "down": 50},
                        "counters": {"bytes_up": 250, "bytes_down": 500},
                    },
                },
            ]).encode())
            return
        self.send_error(404)

    def do_POST(self):
        if self.path != "/api/config/uni/get":
            self.send_error(404)
            return
        FakeSmithproxy.api_key = self.headers.get("X-API-Key")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            document = json.loads(self.rfile.read(length))
            section = document["params"]["section"]
            value = FakeSmithproxy.config_sections[section]
        except (KeyError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"success": {section: value}}).encode())

    def log_message(self, *_args):
        return


def wait_for_state(port: int, expected: str):
    for _ in range(60):
        try:
            status, _, body = request(port, "/healthz")
            if status == 200 and json.loads(body)["smithproxy"]["state"] == expected:
                return body
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"server did not reach Smithproxy state {expected}")


def wait_for_snapshot_state(port: int, expected: str, headers=None):
    for _ in range(140):
        try:
            status, _, body = request(port, "/api/v1/status", headers=headers)
            snapshot = json.loads(body)
            if status == 200 and snapshot["smithproxy"]["state"] == expected:
                return snapshot
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"status endpoint did not reach Smithproxy state {expected}")


def wait_for_config(port: int, gateway_secret: str):
    headers = {"X-Smithproxy-GUI-Gateway": gateway_secret}
    last_snapshot = None
    for _ in range(140):
        try:
            status, _, body = request(port, "/api/v1/config/snapshot", headers=headers)
            snapshot = json.loads(body)
            last_snapshot = snapshot
            if status == 200 and snapshot["state"] == "ready":
                return snapshot, body
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError(f"configuration endpoint did not become ready: {last_snapshot}")


def main() -> int:
    binary, assets = sys.argv[1:]
    port = free_port()
    environment = os.environ.copy()
    for key in ("SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT",
                "SMITHPROXY_GUI_GATEWAY_SECRET"):
        environment.pop(key, None)
    process = subprocess.Popen(
        [binary, "--port", str(port), "--bind", "127.0.0.1", "--base-path",
         "/ws001/smithproxy-gui/", "--assets", assets],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(50):
            try:
                if request(port, "/healthz")[0] == 200:
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("server did not become ready")

        status, headers, body = request(port, "/healthz")
        assert status == 200
        health = json.loads(body)
        assert health["smithproxy"]["state"] == "unconfigured"
        assert health["smithproxy"]["checked_at_unix_ms"] is None
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "frame-ancestors 'self'" in headers["Content-Security-Policy"]
        assert "form-action 'self'" in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "SAMEORIGIN"
        assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert headers["Origin-Agent-Cluster"] == "?1"
        assert headers["X-Permitted-Cross-Domain-Policies"] == "none"
        assert "camera=()" in headers["Permissions-Policy"]
        assert headers["Cache-Control"] == "no-store"
        health_request_id = headers["X-Request-ID"]
        assert re.fullmatch(r"[0-9a-f]+-[1-9][0-9]*", health_request_id)
        assert request(port, "/healthz", headers={"Host": "rebind.attacker.invalid"})[0] == 200

        for host in (f"localhost:{port}", f"LOCALHOST.:{port}", f"127.0.0.2:{port}", f"[::1]:{port}"):
            assert request(
                port, "/ws001/smithproxy-gui/api/v1/status", headers={"Host": host})[0] == 200
        for host in (
            "rebind.attacker.invalid", "localhost.attacker.invalid", "127.0.0.1.attacker.invalid",
            "localhost:0", "localhost:65536", "[::1]suffix",
        ):
            assert_error_response(request(
                port, "/ws001/smithproxy-gui/api/v1/status", headers={"Host": host}),
                421, "request.invalid_host")
        status, headers, body = request(port, "/ws001/smithproxy-gui/api/v1/capabilities")
        capabilities = json.loads(body)
        assert status == 200
        assert headers["X-Request-ID"] != health_request_id
        assert capabilities["base_path"] == "/ws001/smithproxy-gui"
        assert capabilities["config_transaction_state"] == "unavailable"
        assert capabilities["features"]["config_read"] is False
        assert capabilities["features"]["config_write"] is False
        assert capabilities["features"]["drafts"] is False
        assert capabilities["features"]["draft_preflight"] is False
        assert capabilities["features"]["jobs"] is True
        assert capabilities["features"]["events"] is True
        assert capabilities["features"]["alerts"] is True
        assert capabilities["features"]["audit"] is True
        assert capabilities["features"]["smithproxy_events"] is False
        assert capabilities["features"]["metrics"] is True
        assert capabilities["features"]["session_activity"] is True
        assert capabilities["features"]["tls_monitoring"] is True
        assert capabilities["features"]["neighbor_monitoring"] is True
        assert capabilities["features"]["interface_monitoring"] is True

        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/status")
        snapshot = json.loads(body)
        assert status == 200
        assert snapshot["smithproxy"]["configured"] is False
        assert snapshot["smithproxy"]["total_probes"] == 0
        assert snapshot["smithproxy"]["history"] == []
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/metrics/summary")
        metrics = json.loads(body)
        assert status == 200
        assert metrics["state"] == "unconfigured"
        assert metrics["listeners"] == []
        assert metrics["history"] == []
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/sessions/activity")
        activity = json.loads(body)
        assert status == 200
        assert activity["state"] == "unconfigured"
        assert activity["protocols"] == []
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/tls/cache/summary")
        tls_cache = json.loads(body)
        assert status == 200
        assert tls_cache["state"] == "unconfigured"
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/network/neighbors/summary")
        neighbors = json.loads(body)
        assert status == 200
        assert neighbors["state"] == "unconfigured"
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/network/interfaces/summary")
        interfaces = json.loads(body)
        assert status == 200
        assert interfaces["state"] == "unconfigured"
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/events/recent")
        assert status == 200
        assert json.loads(body) == {
            "source": "gui-core", "smithproxy_events_available": False, "events": []}
        status, headers, body = request(port, "/ws001/smithproxy-gui/api/v1/events")
        assert status == 200
        assert headers["Content-Type"] == "text/event-stream; charset=utf-8"
        assert headers["Cache-Control"] == "no-store"
        assert headers["X-Accel-Buffering"] == "no"
        assert b"retry: 2500\n" in body
        assert b"event: snapshot\n" in body
        assert b'"events":[]' in body
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/alerts")
        assert status == 200
        alerts = json.loads(body)
        assert alerts["source"] == "gui-core"
        assert alerts["alerts"][0]["id"] == "control-plane-unconfigured"
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/audit/recent")
        assert status == 200
        assert json.loads(body) == {
            "source": "gui-core", "actor_available": False, "entries": []}
        assert_error_response(request(
            port, "/ws001/smithproxy-gui/api/v1/config/draft/clear", "POST",
            headers={"Host": "rebind.attacker.invalid", "Content-Type": "application/json"},
            body=json.dumps({"expected_version": 0})), 421, "request.invalid_host")
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/jobs")
        assert status == 200
        jobs = json.loads(body)
        assert jobs["source"] == "gui-core"
        assert jobs["owner_available"] is False
        assert jobs["jobs"] == []
        assert isinstance(jobs["generated_at_unix_ms"], int)
        assert request(port, "/ws001/smithproxy-gui/api/v1/jobs/not-a-job")[0] == 404

        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/auth/session")
        assert status == 200
        assert json.loads(body) == {"mode": "disabled", "authenticated": False}
        assert request(port, "/ws001/smithproxy-gui/api/v1/config/snapshot")[0] == 401

        status, headers, body = request(port, "/ws001/smithproxy-gui/")
        assert status == 200
        assert b"smithproxy-gui" in body
        assert headers["Cache-Control"] == "no-store"
        asset_match = re.search(rb'(?:src|href)="\./(assets/[^"]+)"', body)
        assert asset_match is not None
        asset_path = "/ws001/smithproxy-gui/" + asset_match.group(1).decode("ascii")
        status, headers, _ = request(port, asset_path)
        assert status == 200
        assert headers["Cache-Control"] == "public, max-age=31536000, immutable"
        assert request(port, "/ws001/smithproxy-gui/assets/%2e%2e/secret")[0] == 400
        assert request(port, "/outside")[0] == 404
        assert request(port, "/healthz", "POST")[0] == 405
    finally:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    assert process.returncode == 0, process.stderr.read()

    fake_port = free_port()
    fake = http.server.ThreadingHTTPServer(("127.0.0.1", fake_port), FakeSmithproxy)
    fake_thread = threading.Thread(target=fake.serve_forever, daemon=True)
    fake_thread.start()
    secret = "integration-secret-that-must-not-leak"
    gateway_secret = "gateway-secret-used-only-by-integration-tests"
    previous_gateway_secret = "previous-gateway-secret-used-by-tests"
    with tempfile.NamedTemporaryFile() as certificate:
        configured_port = free_port()
        configured_environment = environment.copy()
        configured_environment.update({
            "SMITHPROXY_API_URL": f"http://127.0.0.1:{fake_port}/",
            "SMITHPROXY_API_KEY": secret,
            "SMITHPROXY_CA_CERT": certificate.name,
            "SMITHPROXY_GUI_GATEWAY_SECRET": gateway_secret,
            "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS": previous_gateway_secret,
            "HTTP_PROXY": "http://127.0.0.1:1",
        })
        configured = subprocess.Popen(
            [binary, "--port", str(configured_port), "--assets", assets],
            env=configured_environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            gateway_headers = {"X-Smithproxy-GUI-Gateway": gateway_secret}
            health_body = wait_for_state(configured_port, "ready")
            assert FakeSmithproxy.api_key == secret
            assert secret.encode() not in health_body
            assert isinstance(json.loads(health_body)["smithproxy"]["checked_at_unix_ms"], int)
            protected_paths = (
                "/api/v1/status", "/api/v1/events/recent", "/api/v1/events", "/api/v1/alerts",
                "/api/v1/audit/recent",
                "/api/v1/metrics/summary", "/api/v1/tls/cache/summary",
                "/api/v1/network/neighbors/summary", "/api/v1/network/interfaces/summary",
                "/api/v1/sessions/activity",
            )
            for path in protected_paths:
                assert request(configured_port, path)[0] == 401
                assert request(configured_port, path, headers={
                    "X-Smithproxy-GUI-Gateway": "incorrect-gateway-secret-value-000",
                })[0] == 401
            assert_error_response(
                request(configured_port, "/api/v1/status"), 401, "auth.required")
            assert request(configured_port, "/api/v1/future-management-endpoint")[0] == 401
            assert request(
                configured_port, "/api/v1/future-management-endpoint",
                headers=gateway_headers)[0] == 404
            assert request(
                configured_port, "/api/v1/future-mutation", "POST")[0] == 401
            assert request(
                configured_port, "/api/v1/future-mutation", "POST",
                headers=gateway_headers)[0] == 404
            status, _, body = request(
                configured_port, "/api/v1/status", headers=gateway_headers)
            snapshot = json.loads(body)
            assert status == 200
            assert snapshot["smithproxy"]["configured"] is True
            assert snapshot["smithproxy"]["state"] == "ready"
            assert snapshot["smithproxy"]["total_probes"] >= 1
            assert isinstance(snapshot["smithproxy"]["latency_ms"], int)
            assert len(snapshot["smithproxy"]["history"]) >= 1
            assert snapshot["smithproxy"]["availability_window"]["successful"] >= 1
            assert request(configured_port, "/api/v1/status", headers={
                **gateway_headers, "Host": "saslik.example.test",
            })[0] == 200
            status, _, body = request(configured_port, "/api/v1/status", headers={
                "X-Smithproxy-GUI-Gateway": previous_gateway_secret,
            })
            assert status == 200
            assert json.loads(body)["smithproxy"]["state"] == "ready"
            status, _, body = request(
                configured_port, "/api/v1/events/recent", headers=gateway_headers)
            events = json.loads(body)
            assert status == 200
            assert events["smithproxy_events_available"] is False
            assert events["events"][-1]["message"] == "Smithproxy control plane is reachable"
            assert events["events"][-1]["category"] == "control-plane"
            assert events["events"][-1]["code"] == "control-plane.ready"
            assert len(events["events"]) <= 60
            latest_event_id = events["events"][-1]["id"]
            status, headers, body = request(
                configured_port, "/api/v1/events", headers=gateway_headers)
            assert status == 200
            assert headers["Content-Type"] == "text/event-stream; charset=utf-8"
            assert f"id: {latest_event_id}\n".encode() in body
            assert b"event: snapshot\n" in body
            status, _, replay = request(configured_port, "/api/v1/events", headers={
                **gateway_headers, "Last-Event-ID": latest_event_id,
            })
            assert status == 200
            assert b": keepalive\n\n" in replay
            assert b"event: operational\n" not in replay
            status, _, reset = request(configured_port, "/api/v1/events", headers={
                **gateway_headers, "Last-Event-ID": "expired-event-id",
            })
            assert status == 200
            assert b"event: reset\n" in reset
            assert request(configured_port, "/api/v1/events", headers={
                **gateway_headers, "Last-Event-ID": "x" * 97,
            })[0] == 400
            status, _, body = request(
                configured_port, "/api/v1/alerts", headers=gateway_headers)
            alerts = json.loads(body)
            assert status == 200
            assert isinstance(alerts["generated_at_unix_ms"], int)
            assert alerts["alerts"] == []
            last_success = snapshot["smithproxy"]["last_success_at_unix_ms"]
            status, _, body = request(
                configured_port, "/api/v1/metrics/summary", headers=gateway_headers)
            metrics = json.loads(body)
            assert status == 200
            assert metrics["state"] == "ready"
            assert metrics["totals"] == {
                "workers": 3, "sessions_total": 19, "sessions_active": 4,
                "bytes_up": 1536, "bytes_down": 2304,
            }
            assert [item["name"] for item in metrics["listeners"]] == ["tcp", "tls"]
            assert metrics["history"][-1]["state"] == "ready"
            assert metrics["history"][-1]["sessions_active"] == 4
            metrics_last_success = metrics["last_success_at_unix_ms"]
            status, _, body = request(
                configured_port, "/api/v1/tls/cache/summary", headers=gateway_headers)
            tls_cache = json.loads(body)
            assert status == 200
            assert tls_cache["state"] == "ready"
            assert tls_cache["size"] == 42
            assert tls_cache["capacity"] == 1000
            tls_cache_last_success = tls_cache["last_success_at_unix_ms"]
            status, _, body = request(
                configured_port, "/api/v1/network/neighbors/summary", headers=gateway_headers)
            neighbors = json.loads(body)
            assert status == 200
            assert neighbors["state"] == "ready"
            assert neighbors["hosts_total"] == 2
            assert neighbors["active_today"] == 1
            assert neighbors["active_week"] == 2
            assert neighbors["observations"] == 7
            assert neighbors["bytes_up"] == 110
            assert neighbors["bytes_down"] == 220
            assert b"private-neighbor.example" not in body
            neighbor_last_success = neighbors["last_success_at_unix_ms"]
            status, _, body = request(
                configured_port, "/api/v1/network/interfaces/summary", headers=gateway_headers)
            interfaces = json.loads(body)
            assert status == 200
            assert interfaces["state"] == "ready"
            assert interfaces["generation"] == 42
            assert interfaces["interfaces"] == 3
            assert interfaces["addresses"] == 5
            assert interfaces["ipv4_addresses"] == 3
            assert interfaces["ipv6_addresses"] == 2
            assert interfaces["last_error_code"] is None
            assert b"private" not in body
            interface_last_success = interfaces["last_success_at_unix_ms"]
            status, _, body = request(
                configured_port, "/api/v1/sessions/activity", headers=gateway_headers)
            activity = json.loads(body)
            assert status == 200
            assert activity["state"] == "ready"
            assert activity["total"] == 2
            assert activity["speed_up"] == 125
            assert activity["speed_down"] == 250
            assert [item["protocol"] for item in activity["protocols"]] == ["tcp", "tls"]
            assert b"10.20.30.40" not in body
            assert b"private.example" not in body
            assert b"secret-session-id" not in body
            assert b"confidential-policy" not in body
            activity_last_success = activity["last_success_at_unix_ms"]

            assert request(configured_port, "/api/v1/config/snapshot")[0] == 401
            assert request(
                configured_port, "/api/v1/config/snapshot",
                headers={"X-Smithproxy-GUI-Gateway": "incorrect-gateway-secret-value-000"},
            )[0] == 401
            config_snapshot, config_body = wait_for_config(configured_port, gateway_secret)
            assert config_snapshot["view"] == "runtime"
            assert config_snapshot["revision"] == FakeSmithproxy.config_revision
            assert FakeSmithproxy.revision_requests >= 2
            assert len(config_snapshot["policies"]) == 1
            assert config_snapshot["policies"][0]["name"] == "office policy"
            assert config_snapshot["policies"][0]["enabled"] is True
            assert config_snapshot["policies"][0]["sources"] == ["office"]
            assert config_snapshot["policies"][0]["features"] == ["sinkhole"]
            assert config_snapshot["policies"][0]["detection_profile"] == "default-detection"
            assert config_snapshot["policies"][0]["script_profile"] == "audit-script"
            assert len(config_snapshot["addresses"]) == 2
            assert config_snapshot["ports"][0]["start"] == 443
            assert config_snapshot["protocols"][0]["number"] == 6
            assert config_snapshot["settings"]["ports"] == {
                "plaintext": 50080,
                "tls": 50443,
                "udp": 50080,
                "dtls": 50443,
                "quic": 443,
                "socks": 1080,
                "http_connect": 3128,
            }
            assert config_snapshot["settings"]["ocsp_status_ttl"] == 1800
            assert config_snapshot["settings"]["crl_status_ttl"] == 86400
            assert config_snapshot["settings"]["logging"] == {
                "default_write_payload": False,
                "payload_directory_configured": True,
                "pcap_single_quota": 100,
                "level": 6,
                "file_configured": True,
                "console": True,
                "ssl_key_file_configured": True,
                "syslog_server_configured": True,
                "syslog_port": 514,
                "syslog_facility": 23,
                "syslog_level": 6,
                "syslog_family": 4,
            }
            assert config_snapshot["settings"]["auxiliary"] == {
                "udp_quick_port_count": 1,
                "udp_quick_ports": ["0"],
                "certificates_path_configured": True,
                "certificate_password_configured": True,
                "certificate_transparency_log_configured": True,
                "ca_bundle_path_configured": True,
                "ca_bundle_file_configured": True,
                "messages_directory_configured": True,
                "payload_file_prefix_configured": True,
                "payload_file_suffix_configured": True,
                "cli_port": 50000,
                "cli_password_configured": True,
                "web_rating_key_configured": True,
                "admin_group_configured": True,
                "tuning": {
                    "host_buffer_min": 2048, "host_buffer_max_multiplier": 1024,
                    "host_write_full": 200000, "host_io_batch": 262144,
                    "tls_write_chunk": 20480, "host_open_timeout": 7,
                    "host_idle_timeout": 3600, "neighbor_cache_size": 8000,
                },
                "thread_pool_logging": False,
                "socks_async_dns": True,
                "socks_ip_version_mixing": True,
                "socks_prefer_ipv6": False,
            }
            assert config_snapshot["settings"]["extended_local_destination_protection"] is True
            assert config_snapshot["settings"]["nameservers"] == ["192.0.2.53"]
            assert config_snapshot["settings"]["http_api"] == {
                "key_count": 1,
                "allowed_ip_count": 1,
                "allowed_ips": ["127.0.0.1"],
                "key_timeout": 3600,
                "port": 55555,
                "key_extend_on_access": True,
                "loopback_only": True,
                "pam_login": False,
                "allow_api_header": False,
                "bind_address_configured": True,
                "bind_interface_configured": True,
            }
            assert config_snapshot["settings"]["webhook"] == {
                "enabled": True, "tls_verify": True, "url_configured": True,
                "sift_enabled": True, "sift_url_configured": True,
                "sift_tenant_configured": True, "sift_instance_configured": True,
                "sift_payload_limit_per_direction": 524288,
                "sift_lored_mode": "optional", "sift_lored_include_url": True,
                "hostid_configured": True, "bind_interface_configured": True,
                "api_override": False, "ping_interval": 60,
                "nbr_update_interval": 600, "nbr_tag_refresh_age": 240,
                "task_debug": True, "task_debug_dump": False,
            }
            assert config_snapshot["captures"]["local"]["file_prefix_configured"] is True
            assert config_snapshot["captures"]["local"]["file_suffix_configured"] is True
            assert config_snapshot["debug"] == {
                "log_data_crc": False,
                "log_sockets": True,
                "log_online_cx_name": False,
                "log_srclines": True,
                "log_srclines_always": False,
                "module_override_count": 1,
                "module_overrides": [{"name": "proxy", "kind": "integer", "value": 7}],
            }
            assert {item["type"] for item in config_snapshot["profiles"]} == {
                "detection", "content", "tls", "ssh", "script", "routing",
            }
            content_profile = next(
                item for item in config_snapshot["profiles"] if item["type"] == "content")
            assert content_profile["content"]["rules"] == [{
                "id": "content-rule-0-0",
                "match_configured": True,
                "replacement_configured": True,
                "replacement_has_value": True,
                "fill_length": True,
                "replace_each_nth": 3,
            }]
            assert secret.encode() not in config_body
            assert gateway_secret.encode() not in config_body
            assert b"backend-secret-value" not in config_body
            assert b"192.0.2.77" not in config_body
            assert b"private-api0" not in config_body
            assert b"private-webhook.example" not in config_body
            assert b"private-sift.example" not in config_body
            assert b"private-tenant" not in config_body
            assert b"private-instance" not in config_body
            assert b"private-host-id" not in config_body
            assert b"private-webhook0" not in config_body
            assert b"ct-log-list" not in config_body
            assert b"ca-bundle.pem" not in config_body
            assert b"private-admins" not in config_body
            assert b"/private/captures" not in config_body
            assert b"192.0.2.10" not in config_body
            assert b"private0" not in config_body
            assert b"/private/payloads" not in config_body
            assert b"/private/log" not in config_body
            assert b"192.0.2.60" not in config_body
            for private_value in (
                b"/private/certs", b"private-ca-password", b"/private/ca-bundle",
                b"/private/messages", b"private-prefix", b"private-suffix",
                b"private-cli-password", b"private-rating-key",
            ):
                assert private_value not in config_body
            assert config_snapshot["security_assets"] == {
                "certificate_authorities": [
                    {"id": "certificate-authority-0", "name": "default", "path_configured": True},
                ],
                "certificate_authority_count": 1,
                "certificate_authority_path_count": 1,
                "starttls_signature_count": 1,
                "starttls_flow_step_count": 1,
                "detection_signature_count": 1,
                "detection_flow_step_count": 2,
                "signatures": [
                    {
                        "id": "starttls-signature-0", "kind": "starttls", "category": "",
                        "name": "smtp/starttls", "side": "client", "severity": 2, "group": "",
                        "enables": "", "engine": "", "flow": [{
                            "id": "starttls-signature-0-flow-0", "side": "r", "type": "regex",
                            "expression_configured": True, "bytes_start": 0, "bytes_max": 0,
                        }],
                    },
                    {
                        "id": "detection-signature-0", "kind": "detection", "category": "",
                        "name": "http/request", "side": "client", "severity": 4, "group": "",
                        "enables": "", "engine": "", "flow": [
                            {
                                "id": "detection-signature-0-flow-0", "side": "r", "type": "regex",
                                "expression_configured": True, "bytes_start": 0, "bytes_max": 0,
                            },
                            {
                                "id": "detection-signature-0-flow-1", "side": "r", "type": "regex",
                                "expression_configured": True, "bytes_start": 0, "bytes_max": 0,
                            },
                        ],
                    },
                ],
            }
            assert config_snapshot["augment_support"] is False
            assert config_snapshot["value_origins"] == []
            assert b"/private/ca/default" not in config_body
            assert b"secret-starttls-regex" not in config_body
            assert b"secret-detection-regex" not in config_body
            assert b"private-content-match" not in config_body
            assert b"private-content-replacement" not in config_body

            status, _, body = request(configured_port, "/api/v1/auth/session")
            assert status == 200
            assert json.loads(body) == {"mode": "gateway", "authenticated": False}
            status, _, body = request(
                configured_port, "/api/v1/auth/session", headers=gateway_headers)
            assert status == 200
            assert json.loads(body) == {"mode": "gateway", "authenticated": True}
            assert json.loads(request(configured_port, "/api/v1/capabilities")[2])[
                "features"]["config_read"] is False
            assert json.loads(request(configured_port, "/api/v1/capabilities")[2])[
                "features"]["metrics"] is False
            unauthenticated_features = json.loads(request(
                configured_port, "/api/v1/capabilities")[2])["features"]
            for feature in ("jobs", "events", "alerts", "metrics", "session_activity",
                            "tls_monitoring", "neighbor_monitoring", "interface_monitoring"):
                assert unauthenticated_features[feature] is False
            assert json.loads(request(configured_port, "/api/v1/capabilities")[2])[
                "config_transaction_state"] == "unavailable"
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "config_transaction_state"] == "review-required"
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["config_read"] is True
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["drafts"] is True
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["draft_preflight"] is True
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["metrics"] is True
            authenticated_features = json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])["features"]
            for feature in ("jobs", "events", "alerts", "metrics", "session_activity",
                            "tls_monitoring", "neighbor_monitoring", "interface_monitoring"):
                assert authenticated_features[feature] is True

            assert request(configured_port, "/api/v1/jobs")[0] == 401
            status, _, body = request(
                configured_port, "/api/v1/jobs", headers=gateway_headers)
            assert status == 200
            assert json.loads(body)["jobs"] == []

            assert request(configured_port, "/api/v1/config/draft")[0] == 401
            status, _, body = request(
                configured_port, "/api/v1/config/draft", headers=gateway_headers)
            assert status == 200
            assert json.loads(body) == {
                "id": "workspace-draft", "base_revision": FakeSmithproxy.config_revision,
                "version": 1, "changes": []}
            assert request(configured_port, "/api/v1/config/draft/preflight")[0] == 401
            status, _, body = request(
                configured_port, "/api/v1/config/draft/preflight", headers=gateway_headers)
            assert status == 200
            empty_preflight = json.loads(body)
            assert empty_preflight["source"] == "gui-core"
            assert empty_preflight["draft_version"] == 1
            assert empty_preflight["change_count"] == 0
            assert empty_preflight["sensitive_change_count"] == 0
            assert empty_preflight["schema_validation"] == "valid"
            assert empty_preflight["upstream_validation"] == "unavailable"
            assert empty_preflight["validation_available"] is False
            assert empty_preflight["commit_available"] is False
            assert empty_preflight["sections"] == []
            assert [item["code"] for item in empty_preflight["blockers"]] == [
                "draft.empty", "upstream.schema_review_required"]
            draft_change = json.dumps({
                "expected_version": 1, "path": "policy.[0].action", "value": "accept"})
            csrf_failure = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers={**gateway_headers, "Content-Type": "application/json"}, body=draft_change)
            assert_error_response(csrf_failure, 403, "auth.csrf_failed")
            mutation_headers = {
                **gateway_headers,
                "Host": f"127.0.0.1:{configured_port}",
                "Origin": f"http://127.0.0.1:{configured_port}",
                "Sec-Fetch-Site": "same-origin",
                "X-Smithproxy-GUI-CSRF": "1",
                "Content-Type": "application/json",
            }
            assert request(
                configured_port, "/api/v1/config/draft/validate", "POST",
                body=json.dumps({"expected_version": 1}))[0] == 401
            assert request(
                configured_port, "/api/v1/config/draft/commit", "POST",
                body=json.dumps({"expected_version": 1}))[0] == 401
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/validate", "POST",
                headers={**mutation_headers, "Origin": "https://attacker.invalid"},
                body=json.dumps({"expected_version": 1}),
            ), 403, "auth.csrf_failed")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/commit", "POST",
                headers={**mutation_headers, "Origin": "https://attacker.invalid"},
                body=json.dumps({"expected_version": 1}),
            ), 403, "auth.csrf_failed")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/validate", "POST",
                headers=mutation_headers, body=json.dumps({"expected_version": 1}),
            ), 422, "config.validation_rejected")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers={key: value for key, value in mutation_headers.items() if key != "Origin"},
                body=draft_change,
            ), 403, "auth.csrf_failed")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers={**mutation_headers, "Sec-Fetch-Site": "cross-site"},
                body=draft_change,
            ), 403, "auth.csrf_failed")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers={**mutation_headers, "Content-Type": "text/plain"},
                body=draft_change,
            ), 403, "auth.csrf_failed")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body="{",
            ), 400, "draft.invalid_request")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body="x" * (64 * 1024 + 1),
            ), 413, "request.body_too_large")
            unchanged_after_rejections = json.loads(request(
                configured_port, "/api/v1/config/draft", headers=gateway_headers)[2])
            assert unchanged_after_rejections["version"] == 1
            assert unchanged_after_rejections["changes"] == []
            status, _, body = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=draft_change)
            assert status == 200
            assert json.loads(body)["changes"] == [
                {"path": "policy.[0].action", "value": "accept"}]
            assert json.loads(body)["version"] == 2
            conflict = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=draft_change)
            conflict_request_id = assert_error_response(
                conflict, 409, "draft.version_conflict")
            status, _, audit_body = request(
                configured_port, "/api/v1/audit/recent", headers=gateway_headers)
            assert status == 200
            audit = json.loads(audit_body)
            assert audit["actor_available"] is False
            assert audit["entries"][-1] == {
                "id": audit["entries"][-1]["id"],
                "occurred_at_unix_ms": audit["entries"][-1]["occurred_at_unix_ms"],
                "request_id": conflict_request_id,
                "operation": "config.draft.upsert",
                "outcome": "conflict",
                "authentication": "gateway",
                "actor": None,
                "target_count": 1,
                "targets": ["policy.[0].action"],
                "targets_truncated": False,
            }
            assert b'"accept"' not in audit_body
            cross_origin_headers = {**mutation_headers, "Origin": "https://attacker.invalid"}
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=cross_origin_headers,
                body=json.dumps({"expected_version": 2, "path": "settings.enabled", "value": True}),
            )[0] == 403
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({"expected_version": 2, "path": "../unsafe", "value": True}),
            )[0] == 400
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({"expected_version": 2, "path": "settings.enabled", "value": True}),
            ), 400, "draft.change_rejected")
            assert_error_response(request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({
                    "expected_version": 2,
                    "changes": [
                        {"path": "policy.[0].name", "value": "must-not-apply"},
                        {"path": "settings.http_api.port", "value": 22},
                    ],
                }),
            ), 400, "draft.change_rejected")
            status, _, body = request(
                configured_port, "/api/v1/config/draft", headers=gateway_headers)
            assert status == 200
            rejected_snapshot = json.loads(body)
            assert rejected_snapshot["version"] == 2
            assert all(change["path"] != "policy.[0].name" for change in rejected_snapshot["changes"])
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({
                    "expected_version": 2,
                    "path": "tls_profiles.[0].redirect_warning_ports",
                    "value": [443, "8443"],
                }),
            )[0] == 400
            batch_change = json.dumps({
                "expected_version": 2,
                "changes": [
                    {"path": "policy.[0].name", "value": "Office outbound"},
                    {"path": "policy.[0].disabled", "value": True},
                    {"path": "policy.[0].dst", "value": ["internet", "backup"]},
                    {"path": "settings.certs_ca_key_password", "value": "new-private-password"},
                    {"path": "settings.http_api.keys", "value": ["new-api-key", "overlap-api-key"]},
                    {"path": "settings.http_api.key_timeout", "value": 900},
                    {"path": "settings.http_api.port", "value": 55580},
                    {"path": "settings.http_api.key_extend_on_access", "value": False},
                    {"path": "settings.http_api.bind_address", "value": "192.0.2.88"},
                    {"path": "settings.http_api.bind_interface", "value": "private-api1"},
                    {"path": "settings.webhook.sift_url", "value": "http://new-private-sift/webhook"},
                    {"path": "settings.webhook.sift_tenant_id", "value": "new-private-tenant"},
                    {"path": "settings.webhook.sift_instance_id", "value": "new-private-instance"},
                    {"path": "settings.webhook.hostid", "value": "new-private-host"},
                    {"path": "settings.webhook.bind_interface", "value": "private-webhook1"},
                    {"path": "settings.certs_ctlog", "value": "/new/private/ct-log.cnf"},
                    {"path": "settings.ca_bundle_file", "value": "/new/private/ca-bundle.pem"},
                    {"path": "settings.admin.group", "value": "new-private-admins"},
                    {"path": "captures.local.dir", "value": "/new/private/captures"},
                    {"path": "captures.remote.tun_dst", "value": ""},
                    {"path": "ssh_profiles.[0].host_key", "value": "/new/private/ssh-key"},
                    {"path": "script_profiles.[0].script-file", "value": "/new/private/audit.py"},
                    {"path": "tls_profiles.[0].sni_filter_bypass", "value": ["private.example"]},
                    {"path": "tls_profiles.[0].redirect_warning_ports", "value": [443, 44443]},
                    {"path": "content_profiles.[0].rules_session_filter", "value": "secret session expression"},
                    {"path": "content_profiles.[0].content_rules.[0].match", "value": "secret content match"},
                    {"path": "content_profiles.[0].content_rules.[0].replace", "value": "secret content replacement"},
                    {"path": "tls_ca.[0].path", "value": "/new/private/ca/default"},
                    {"path": "detection_signatures.[0].flow.[0].signature", "value": "secret replacement regex"},
                ],
            })
            status, _, body = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=batch_change)
            assert status == 200
            batch_snapshot = json.loads(body)
            assert batch_snapshot["version"] == 3
            changes_by_path = {item["path"]: item["value"] for item in batch_snapshot["changes"]}
            assert changes_by_path["policy.[0].dst"] == ["internet", "backup"]
            assert changes_by_path["tls_profiles.[0].redirect_warning_ports"] == [443, 44443]
            assert changes_by_path["settings.http_api.key_timeout"] == 900
            assert changes_by_path["settings.http_api.port"] == 55580
            assert changes_by_path["settings.http_api.key_extend_on_access"] is False
            status, _, preflight_body = request(
                configured_port, "/api/v1/config/draft/preflight", headers=gateway_headers)
            assert status == 200
            preflight = json.loads(preflight_body)
            assert preflight["draft_version"] == 3
            assert preflight["change_count"] == len(batch_snapshot["changes"])
            assert sum(section["change_count"] for section in preflight["sections"]) == preflight["change_count"]
            assert preflight["sensitive_change_count"] > 0
            assert {section["name"] for section in preflight["sections"]} >= {
                "policy", "settings", "captures", "tls_profiles", "content_profiles"}
            assert [item["code"] for item in preflight["blockers"]] == [
                "upstream.schema_review_required"]
            assert b"new-private-password" not in preflight_body
            assert b"secret content replacement" not in preflight_body
            status, _, audit_body = request(
                configured_port, "/api/v1/audit/recent", headers=gateway_headers)
            assert status == 200
            latest_audit = json.loads(audit_body)["entries"][-1]
            assert latest_audit["outcome"] == "succeeded"
            assert latest_audit["target_count"] == len(json.loads(batch_change)["changes"])
            assert b"new-private-password" not in audit_body
            assert b"secret content replacement" not in audit_body
            validation_result = request(
                configured_port, "/api/v1/config/draft/validate", "POST",
                headers=mutation_headers, body=json.dumps({"expected_version": 3}))
            assert_error_response(validation_result, 503, "config.validation_unavailable")
            status, _, validation_audit_body = request(
                configured_port, "/api/v1/audit/recent", headers=gateway_headers)
            assert status == 200
            validation_audit = json.loads(validation_audit_body)["entries"][-1]
            assert validation_audit["operation"] == "config.draft.validate"
            assert validation_audit["outcome"] == "rejected"
            assert validation_audit["target_count"] == 0
            assert b"new-private-password" not in validation_audit_body
            assert b"secret content replacement" not in validation_audit_body
            commit_result = request(
                configured_port, "/api/v1/config/draft/commit", "POST",
                headers=mutation_headers, body=json.dumps({"expected_version": 3}))
            assert_error_response(commit_result, 503, "config.commit_unavailable")
            status, _, commit_audit_body = request(
                configured_port, "/api/v1/audit/recent", headers=gateway_headers)
            assert status == 200
            commit_audit = json.loads(commit_audit_body)["entries"][-1]
            assert commit_audit["operation"] == "config.draft.commit"
            assert commit_audit["outcome"] == "rejected"
            assert commit_audit["target_count"] == 0
            assert b"new-private-password" not in commit_audit_body
            assert b"secret content replacement" not in commit_audit_body
            expected_redactions = {
                "settings.certs_ca_key_password": "[redacted:replace]",
                "settings.http_api.keys": "[redacted:replace:2]",
                "settings.http_api.bind_address": "[redacted:replace]",
                "settings.http_api.bind_interface": "[redacted:replace]",
                "settings.webhook.sift_url": "[redacted:replace]",
                "settings.webhook.sift_tenant_id": "[redacted:replace]",
                "settings.webhook.sift_instance_id": "[redacted:replace]",
                "settings.webhook.hostid": "[redacted:replace]",
                "settings.webhook.bind_interface": "[redacted:replace]",
                "settings.certs_ctlog": "[redacted:replace]",
                "settings.ca_bundle_file": "[redacted:replace]",
                "settings.admin.group": "[redacted:replace]",
                "captures.local.dir": "[redacted:replace]",
                "captures.remote.tun_dst": "[redacted:clear]",
                "ssh_profiles.[0].host_key": "[redacted:replace]",
                "script_profiles.[0].script-file": "[redacted:replace]",
                "tls_profiles.[0].sni_filter_bypass": "[redacted:replace:1]",
                "content_profiles.[0].rules_session_filter": "[redacted:replace]",
                "tls_ca.[0].path": "[redacted:replace]",
                "content_profiles.[0].content_rules.[0].match": "[redacted:replace]",
                "content_profiles.[0].content_rules.[0].replace": "[redacted:replace]",
                "detection_signatures.[0].flow.[0].signature": "[redacted:replace]",
            }
            for sensitive_path, expected_redaction in expected_redactions.items():
                assert changes_by_path[sensitive_path] == expected_redaction
            assert b"new-private-password" not in body
            assert b"new-api-key" not in body
            assert b"overlap-api-key" not in body
            assert b"192.0.2.88" not in body
            assert b"private-api1" not in body
            assert b"new-private-sift" not in body
            assert b"new-private-tenant" not in body
            assert b"new-private-instance" not in body
            assert b"new-private-host" not in body
            assert b"private-webhook1" not in body
            assert b"ct-log.cnf" not in body
            assert b"ca-bundle.pem" not in body
            assert b"new-private-admins" not in body
            assert b"/new/private/captures" not in body
            assert b"/new/private/ssh-key" not in body
            assert b"/new/private/audit.py" not in body
            assert b"private.example" not in body
            assert b"secret session expression" not in body
            assert b"secret content match" not in body
            assert b"secret content replacement" not in body
            assert b"/new/private/ca/default" not in body
            assert b"secret replacement regex" not in body
            clear_change = json.dumps({"expected_version": 3})
            assert request(
                configured_port, "/api/v1/config/draft/clear", "POST",
                headers={**mutation_headers, "Origin": "https://attacker.invalid"},
                body=clear_change,
            )[0] == 403
            status, _, body = request(
                configured_port, "/api/v1/config/draft/clear", "POST",
                headers=mutation_headers, body=clear_change)
            assert status == 200
            cleared_snapshot = json.loads(body)
            assert cleared_snapshot["version"] == 4
            assert cleared_snapshot["changes"] == []
            assert request(
                configured_port, "/api/v1/config/draft/clear", "POST",
                headers=mutation_headers, body=clear_change,
            )[0] == 409

            FakeSmithproxy.response_status = 503
            snapshot = wait_for_snapshot_state(configured_port, "error", gateway_headers)
            assert snapshot["smithproxy"]["consecutive_failures"] == 1
            assert snapshot["smithproxy"]["last_success_at_unix_ms"] == last_success
            assert snapshot["smithproxy"]["history"][-1]["state"] == "error"
            status, _, body = request(
                configured_port, "/api/v1/events/recent", headers=gateway_headers)
            events = json.loads(body)["events"]
            assert events[-1]["severity"] == "error"
            assert events[-1]["category"] == "control-plane"
            assert events[-1]["code"] == "control-plane.error"
            assert events[-1]["message"] == "Smithproxy control plane changed to error"
            assert snapshot["smithproxy"]["availability_window"]["samples"] >= 2
            status, _, body = request(
                configured_port, "/api/v1/metrics/summary", headers=gateway_headers)
            stale_metrics = json.loads(body)
            assert status == 200
            assert stale_metrics["state"] == "unavailable"
            assert stale_metrics["last_success_at_unix_ms"] == metrics_last_success
            assert stale_metrics["totals"]["sessions_active"] == 4
            assert stale_metrics["history"][-1]["state"] == "unavailable"
            assert len(stale_metrics["history"]) <= 60
            status, _, body = request(
                configured_port, "/api/v1/tls/cache/summary", headers=gateway_headers)
            stale_tls_cache = json.loads(body)
            assert status == 200
            assert stale_tls_cache["state"] == "unavailable"
            assert stale_tls_cache["last_success_at_unix_ms"] == tls_cache_last_success
            assert stale_tls_cache["size"] == 42
            status, _, body = request(
                configured_port, "/api/v1/network/neighbors/summary", headers=gateway_headers)
            stale_neighbors = json.loads(body)
            assert status == 200
            assert stale_neighbors["state"] == "unavailable"
            assert stale_neighbors["last_success_at_unix_ms"] == neighbor_last_success
            assert stale_neighbors["hosts_total"] == 2
            status, _, body = request(
                configured_port, "/api/v1/network/interfaces/summary", headers=gateway_headers)
            stale_interfaces = json.loads(body)
            assert status == 200
            assert stale_interfaces["state"] == "unavailable"
            assert stale_interfaces["last_success_at_unix_ms"] == interface_last_success
            assert stale_interfaces["interfaces"] == 3
            status, _, body = request(
                configured_port, "/api/v1/sessions/activity", headers=gateway_headers)
            stale_activity = json.loads(body)
            assert status == 200
            assert stale_activity["state"] == "unavailable"
            assert stale_activity["last_success_at_unix_ms"] == activity_last_success
            assert stale_activity["total"] == 2
        finally:
            FakeSmithproxy.response_status = 200
            configured.send_signal(signal.SIGTERM)
            configured.wait(timeout=4)
        output = configured.stdout.read() + configured.stderr.read()
        assert configured.returncode == 0
        assert secret not in output
        assert gateway_secret not in output
        assert previous_gateway_secret not in output
    fake.shutdown()
    fake.server_close()
    fake_thread.join(timeout=2)

    invalid_environment = environment.copy()
    invalid_environment["SMITHPROXY_API_KEY"] = secret
    invalid = subprocess.run(
        [binary, "--assets", assets], env=invalid_environment,
        capture_output=True, text=True, timeout=3,
    )
    assert invalid.returncode == 2
    assert secret not in invalid.stdout + invalid.stderr
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
