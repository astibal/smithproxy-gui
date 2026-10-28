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
            "proto": "tcp", "src": ["office"], "sport": ["any"],
            "dst": ["internet"], "dport": ["https"], "action": "accept",
            "nat": "masquerade", "routing": "main", "tls_profile": "inspect",
        }],
        "address_objects": {
            "office": {"type": "cidr", "value": "10.0.0.0/24"},
            "internet": {"type": "fqdn", "value": "example.test"},
        },
        "port_objects": {"https": {"start": "443", "end": "443"}},
        "proto_objects": {"tcp": {"id": "6"}},
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
    for _ in range(140):
        try:
            status, _, body = request(port, "/api/v1/config/snapshot", headers=headers)
            snapshot = json.loads(body)
            if status == 200 and snapshot["state"] == "ready":
                return snapshot, body
        except OSError:
            pass
        time.sleep(0.05)
    raise AssertionError("configuration endpoint did not become ready")


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

        status, _, body = request(port, "/ws001/smithproxy-gui/api/v1/capabilities")
        capabilities = json.loads(body)
        assert status == 200
        assert capabilities["base_path"] == "/ws001/smithproxy-gui"
        assert capabilities["features"]["config_read"] is False
        assert capabilities["features"]["config_write"] is False
        assert capabilities["features"]["metrics"] is True
        assert capabilities["features"]["session_activity"] is True

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
            assert config_snapshot["policies"][0]["sources"] == ["office"]
            assert len(config_snapshot["addresses"]) == 2
            assert config_snapshot["ports"][0]["start"] == 443
            assert config_snapshot["protocols"][0]["number"] == 6
            assert secret.encode() not in config_body
            assert gateway_secret.encode() not in config_body

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

            FakeSmithproxy.response_status = 503
            snapshot = wait_for_snapshot_state(configured_port, "error")
            assert snapshot["smithproxy"]["consecutive_failures"] == 1
            assert snapshot["smithproxy"]["last_success_at_unix_ms"] == last_success
            assert snapshot["smithproxy"]["history"][-1]["state"] == "error"
            assert snapshot["smithproxy"]["availability_window"]["samples"] >= 2
            status, _, body = request(configured_port, "/api/v1/metrics/summary")
            stale_metrics = json.loads(body)
            assert status == 200
            assert stale_metrics["state"] == "unavailable"
            assert stale_metrics["last_success_at_unix_ms"] == metrics_last_success
            assert stale_metrics["totals"]["sessions_active"] == 4
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
