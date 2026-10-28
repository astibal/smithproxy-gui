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


def request(port: int, path: str, method: str = "GET"):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request(method, path)
    response = connection.getresponse()
    body = response.read()
    headers = dict(response.getheaders())
    connection.close()
    return response.status, headers, body


class FakeSmithproxy(http.server.BaseHTTPRequestHandler):
    api_key = None

    def do_GET(self):
        if self.path == "/api/status/ping":
            FakeSmithproxy.api_key = self.headers.get("X-API-Key")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_error(404)

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


def main() -> int:
    binary, assets = sys.argv[1:]
    port = free_port()
    environment = os.environ.copy()
    for key in ("SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT"):
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
        assert capabilities["features"]["config_write"] is False

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
    with tempfile.NamedTemporaryFile() as certificate:
        configured_port = free_port()
        configured_environment = environment.copy()
        configured_environment.update({
            "SMITHPROXY_API_URL": f"http://127.0.0.1:{fake_port}/",
            "SMITHPROXY_API_KEY": secret,
            "SMITHPROXY_CA_CERT": certificate.name,
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
        finally:
            configured.send_signal(signal.SIGTERM)
            configured.wait(timeout=4)
        output = configured.stdout.read() + configured.stderr.read()
        assert configured.returncode == 0
        assert secret not in output
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
