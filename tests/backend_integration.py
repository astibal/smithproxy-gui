#!/usr/bin/env python3

import http.client
import http.server
import json
import os
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


class FakeSmithproxy(http.server.BaseHTTPRequestHandler):
    api_key = None
    response_status = 200
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
        "content_profiles": {"safe-content": {"write_payload": "false"}},
        "tls_profiles": {"inspect": {}},
        "ssh_profiles": {"default-ssh": {"host_key": "/redacted/test-key"}},
        "alg_dns_profiles": {},
        "script_profiles": {"audit-script": {}},
        "auth_profiles": {},
        "routing": {"main": {}},
        "settings": {
            "accept_tproxy": "true", "accept_redirect": "true",
            "accept_socks": "false", "accept_http_connect": "true", "accept_api": "true",
            "policy_fail_open": "false", "policy_access_request_fail_open": "false",
            "plaintext_workers": "2", "ssl_workers": "4", "udp_workers": "1",
            "dtls_workers": "1", "quic_workers": "0", "socks_workers": "0",
            "http_connect_workers": "1", "ssl_autodetect": "true",
            "ssl_autodetect_harder": "false", "ssl_use_ktls": "false",
            "nameservers": ["192.0.2.53"],
            "http_api": {
                "keys": ["backend-secret-value"], "allowed_ips": ["127.0.0.1"],
                "loopback_only": "true", "pam_login": "false", "allow_api_header": "false",
            },
            "webhook": {
                "enabled": "true", "tls_verify": "true",
                "url": "https://private-webhook.example/", "sift": "false", "api_override": "false",
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
            {"name": "smtp/starttls", "flow": [{"signature": "secret-starttls-regex"}]},
        ],
        "detection_signatures": [
            {"name": "http/request", "flow": [
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


def wait_for_snapshot_state(port: int, expected: str):
    for _ in range(140):
        try:
            status, _, body = request(port, "/api/v1/status")
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
        assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
        assert headers["X-Permitted-Cross-Domain-Policies"] == "none"
        assert "camera=()" in headers["Permissions-Policy"]
        assert headers["Cache-Control"] == "no-store"

        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/capabilities")
        capabilities = json.loads(body)
        assert status == 200
        assert capabilities["base_path"] == "/ws001/smithproxy-gui"
        assert capabilities["features"]["config_read"] is False
        assert capabilities["features"]["config_write"] is False
        assert capabilities["features"]["drafts"] is False
        assert capabilities["features"]["events"] is True
        assert capabilities["features"]["smithproxy_events"] is False
        assert capabilities["features"]["metrics"] is True
        assert capabilities["features"]["session_activity"] is True
        assert capabilities["features"]["tls_monitoring"] is True
        assert capabilities["features"]["neighbor_monitoring"] is True

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
        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/events/recent")
        assert status == 200
        assert json.loads(body) == {
            "source": "gui-core", "smithproxy_events_available": False, "events": []}

        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/auth/session")
        assert status == 200
        assert json.loads(body) == {"mode": "disabled", "authenticated": False}
        assert request(port, "/ws001/smithproxy-gui/api/v1/config/snapshot")[0] == 401

        status, _, body = request(port, "/ws001/smithproxy-gui/")
        assert status == 200
        assert b"smithproxy-gui" in body
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
    with tempfile.NamedTemporaryFile() as certificate:
        configured_port = free_port()
        configured_environment = environment.copy()
        configured_environment.update({
            "SMITHPROXY_API_URL": f"http://127.0.0.1:{fake_port}/",
            "SMITHPROXY_API_KEY": secret,
            "SMITHPROXY_CA_CERT": certificate.name,
            "SMITHPROXY_GUI_GATEWAY_SECRET": gateway_secret,
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
            health_body = wait_for_state(configured_port, "ready")
            assert FakeSmithproxy.api_key == secret
            assert secret.encode() not in health_body
            assert isinstance(json.loads(health_body)["smithproxy"]["checked_at_unix_ms"], int)
            status, _, body = request(configured_port, "/api/v1/status")
            snapshot = json.loads(body)
            assert status == 200
            assert snapshot["smithproxy"]["configured"] is True
            assert snapshot["smithproxy"]["state"] == "ready"
            assert snapshot["smithproxy"]["total_probes"] >= 1
            assert isinstance(snapshot["smithproxy"]["latency_ms"], int)
            assert len(snapshot["smithproxy"]["history"]) >= 1
            assert snapshot["smithproxy"]["availability_window"]["successful"] >= 1
            status, _, body = request(configured_port, "/api/v1/events/recent")
            events = json.loads(body)
            assert status == 200
            assert events["smithproxy_events_available"] is False
            assert events["events"][-1]["message"] == "Smithproxy control plane is reachable"
            assert len(events["events"]) <= 60
            last_success = snapshot["smithproxy"]["last_success_at_unix_ms"]
            status, _, body = request(configured_port, "/api/v1/metrics/summary")
            metrics = json.loads(body)
            assert status == 200
            assert metrics["state"] == "ready"
            assert metrics["totals"] == {
                "workers": 3, "sessions_total": 19, "sessions_active": 4,
                "bytes_up": 1536, "bytes_down": 2304,
            }
            assert [item["name"] for item in metrics["listeners"]] == ["tcp", "tls"]
            metrics_last_success = metrics["last_success_at_unix_ms"]
            status, _, body = request(configured_port, "/api/v1/tls/cache/summary")
            tls_cache = json.loads(body)
            assert status == 200
            assert tls_cache["state"] == "ready"
            assert tls_cache["size"] == 42
            assert tls_cache["capacity"] == 1000
            tls_cache_last_success = tls_cache["last_success_at_unix_ms"]
            status, _, body = request(configured_port, "/api/v1/network/neighbors/summary")
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
            status, _, body = request(configured_port, "/api/v1/sessions/activity")
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
            assert config_snapshot["revision"] is None
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
            assert config_snapshot["debug"] == {
                "log_data_crc": False,
                "log_sockets": True,
                "log_online_cx_name": False,
                "log_srclines": True,
                "log_srclines_always": False,
                "module_override_count": 1,
            }
            assert {item["type"] for item in config_snapshot["profiles"]} == {
                "detection", "content", "tls", "ssh", "script", "routing",
            }
            assert secret.encode() not in config_body
            assert gateway_secret.encode() not in config_body
            assert b"backend-secret-value" not in config_body
            assert b"private-webhook.example" not in config_body
            assert b"/private/captures" not in config_body
            assert b"192.0.2.10" not in config_body
            assert b"private0" not in config_body
            assert config_snapshot["security_assets"] == {
                "certificate_authority_count": 1,
                "certificate_authority_path_count": 1,
                "starttls_signature_count": 1,
                "starttls_flow_step_count": 1,
                "detection_signature_count": 1,
                "detection_flow_step_count": 2,
            }
            assert config_snapshot["augment_support"] is False
            assert config_snapshot["value_origins"] == []
            assert b"/private/ca/default" not in config_body
            assert b"secret-starttls-regex" not in config_body
            assert b"secret-detection-regex" not in config_body

            status, _, body = request(configured_port, "/api/v1/auth/session")
            assert status == 200
            assert json.loads(body) == {"mode": "gateway", "authenticated": False}
            gateway_headers = {"X-Smithproxy-GUI-Gateway": gateway_secret}
            status, _, body = request(
                configured_port, "/api/v1/auth/session", headers=gateway_headers)
            assert status == 200
            assert json.loads(body) == {"mode": "gateway", "authenticated": True}
            assert json.loads(request(configured_port, "/api/v1/capabilities")[2])[
                "features"]["config_read"] is False
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["config_read"] is True
            assert json.loads(request(
                configured_port, "/api/v1/capabilities", headers=gateway_headers)[2])[
                "features"]["drafts"] is True

            assert request(configured_port, "/api/v1/config/draft")[0] == 401
            status, _, body = request(
                configured_port, "/api/v1/config/draft", headers=gateway_headers)
            assert status == 200
            assert json.loads(body) == {
                "id": "workspace-draft", "base_revision": None, "version": 0, "changes": []}
            draft_change = json.dumps({
                "expected_version": 0, "path": "policy.[0].action", "value": "accept"})
            status, _, _ = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers={**gateway_headers, "Content-Type": "application/json"}, body=draft_change)
            assert status == 403
            mutation_headers = {
                **gateway_headers,
                "Host": f"127.0.0.1:{configured_port}",
                "Origin": f"http://127.0.0.1:{configured_port}",
                "Sec-Fetch-Site": "same-origin",
                "X-Smithproxy-GUI-CSRF": "1",
                "Content-Type": "application/json",
            }
            status, _, body = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=draft_change)
            assert status == 200
            assert json.loads(body)["changes"] == [
                {"path": "policy.[0].action", "value": "accept"}]
            assert json.loads(body)["version"] == 1
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=draft_change)[0] == 409
            cross_origin_headers = {**mutation_headers, "Origin": "https://attacker.invalid"}
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=cross_origin_headers,
                body=json.dumps({"expected_version": 1, "path": "settings.enabled", "value": True}),
            )[0] == 403
            assert request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({"expected_version": 1, "path": "../unsafe", "value": True}),
            )[0] == 400
            batch_change = json.dumps({
                "expected_version": 1,
                "changes": [
                    {"path": "policy.[0].name", "value": "Office outbound"},
                    {"path": "policy.[0].disabled", "value": True},
                    {"path": "policy.[0].dst", "value": ["internet", "backup"]},
                ],
            })
            status, _, body = request(
                configured_port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers, body=batch_change)
            assert status == 200
            batch_snapshot = json.loads(body)
            assert batch_snapshot["version"] == 2
            assert batch_snapshot["changes"][-1] == {
                "path": "policy.[0].dst", "value": ["internet", "backup"]}
            clear_change = json.dumps({"expected_version": 2})
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
            assert cleared_snapshot["version"] == 3
            assert cleared_snapshot["changes"] == []
            assert request(
                configured_port, "/api/v1/config/draft/clear", "POST",
                headers=mutation_headers, body=clear_change,
            )[0] == 409

            FakeSmithproxy.response_status = 503
            snapshot = wait_for_snapshot_state(configured_port, "error")
            assert snapshot["smithproxy"]["consecutive_failures"] == 1
            assert snapshot["smithproxy"]["last_success_at_unix_ms"] == last_success
            assert snapshot["smithproxy"]["history"][-1]["state"] == "error"
            status, _, body = request(configured_port, "/api/v1/events/recent")
            events = json.loads(body)["events"]
            assert events[-1]["severity"] == "error"
            assert events[-1]["message"] == "Smithproxy control plane changed to error"
            assert snapshot["smithproxy"]["availability_window"]["samples"] >= 2
            status, _, body = request(configured_port, "/api/v1/metrics/summary")
            stale_metrics = json.loads(body)
            assert status == 200
            assert stale_metrics["state"] == "unavailable"
            assert stale_metrics["last_success_at_unix_ms"] == metrics_last_success
            assert stale_metrics["totals"]["sessions_active"] == 4
            status, _, body = request(configured_port, "/api/v1/tls/cache/summary")
            stale_tls_cache = json.loads(body)
            assert status == 200
            assert stale_tls_cache["state"] == "unavailable"
            assert stale_tls_cache["last_success_at_unix_ms"] == tls_cache_last_success
            assert stale_tls_cache["size"] == 42
            status, _, body = request(configured_port, "/api/v1/network/neighbors/summary")
            stale_neighbors = json.loads(body)
            assert status == 200
            assert stale_neighbors["state"] == "unavailable"
            assert stale_neighbors["last_success_at_unix_ms"] == neighbor_last_success
            assert stale_neighbors["hosts_total"] == 2
            status, _, body = request(configured_port, "/api/v1/sessions/activity")
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
