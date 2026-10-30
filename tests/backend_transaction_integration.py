#!/usr/bin/env python3

import http.server
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

from backend_integration import FakeSmithproxy, free_port, request, wait_for_config, wait_for_state


BASE_REVISION = "sha256:" + "c" * 64
COMMITTED_REVISION = "sha256:" + "d" * 64
SCHEMA_REVISION = "sha256:" + "a" * 64
PRIVATE_VALUE = "transaction-private-password"


class TransactionSmithproxy(FakeSmithproxy):
    requests = []
    request_lock = threading.Lock()
    reject_first_commit_transport = True

    def do_POST(self):
        if self.path != "/api/config/v2/transaction":
            super().do_POST()
            return
        FakeSmithproxy.api_key = self.headers.get("X-API-Key")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            document = json.loads(self.rfile.read(length))
            mode = document["mode"]
            operations = document["operations"]
            base_revision = document["base_revision"]
            idempotency_key = document["idempotency_key"]
            if mode not in ("validate", "commit") or not isinstance(operations, list):
                raise ValueError
            if base_revision != BASE_REVISION or not re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    idempotency_key):
                raise ValueError
        except (KeyError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        with TransactionSmithproxy.request_lock:
            TransactionSmithproxy.requests.append(document)
            lose_response = mode == "commit" and TransactionSmithproxy.reject_first_commit_transport
            if lose_response:
                TransactionSmithproxy.reject_first_commit_transport = False

        revision = BASE_REVISION
        warnings = ["reviewed integration warning"]
        restart = "not-required"
        if mode == "commit":
            revision = COMMITTED_REVISION
            warnings = []
            restart = "required"
            FakeSmithproxy.config_revision = COMMITTED_REVISION
        if lose_response:
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "success": {
                "revision": revision,
                "previous_revision": BASE_REVISION,
                "validated_operations": len(operations),
                "warnings": warnings,
                "restart": restart,
            },
        }).encode())


def wait_for_ready_capability(port: int, headers):
    last = None
    for _ in range(160):
        status, _, body = request(port, "/api/v1/capabilities", headers=headers)
        last = json.loads(body)
        if status == 200 and last["config_transaction_state"] == "ready":
            return last
        time.sleep(0.05)
    raise AssertionError(f"transaction capability did not become ready: {last}")


def wait_for_refresh_job(port: int, headers, expected_id: str):
    last = None
    for _ in range(160):
        status, _, body = request(port, "/api/v1/jobs", headers=headers)
        document = json.loads(body)
        last = next((job for job in document["jobs"] if job["id"] == expected_id), None)
        if status == 200 and last is not None and last["state"] == "succeeded":
            return last
        time.sleep(0.05)
    raise AssertionError(f"configuration refresh job did not succeed: {last}")


def main() -> int:
    binary, assets = sys.argv[1:]
    FakeSmithproxy.config_revision = BASE_REVISION
    FakeSmithproxy.response_status = 200
    FakeSmithproxy.transaction_capabilities = {
        "success": {
            "transaction_version": 1,
            "operation_version": 1,
            "stable_entity_ids": True,
            "operations": ["set", "create", "delete", "move"],
            "maximum_operations": 4096,
            "maximum_request_bytes": 1048576,
            "collections": [{
                "id": "policy",
                "ordered": True,
                "nested": False,
                "schema_revision": SCHEMA_REVISION,
            }],
        },
    }
    TransactionSmithproxy.requests = []
    TransactionSmithproxy.reject_first_commit_transport = True

    fake_port = free_port()
    fake = http.server.ThreadingHTTPServer(("127.0.0.1", fake_port), TransactionSmithproxy)
    fake_thread = threading.Thread(target=fake.serve_forever, daemon=True)
    fake_thread.start()

    port = free_port()
    api_key = "transaction-api-key-that-must-not-leak"
    gateway_secret = "transaction-gateway-secret-for-tests"
    environment = os.environ.copy()
    for key in (
            "SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT",
            "SMITHPROXY_GUI_GATEWAY_SECRET", "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS"):
        environment.pop(key, None)
    with tempfile.NamedTemporaryFile() as certificate:
        environment.update({
            "SMITHPROXY_API_URL": f"http://127.0.0.1:{fake_port}/",
            "SMITHPROXY_API_KEY": api_key,
            "SMITHPROXY_CA_CERT": certificate.name,
            "SMITHPROXY_GUI_GATEWAY_SECRET": gateway_secret,
            "HTTP_PROXY": "http://127.0.0.1:1",
        })
        process = subprocess.Popen(
            [binary, "--port", str(port), "--assets", assets],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            wait_for_state(port, "ready")
            wait_for_config(port, gateway_secret)
            gateway_headers = {"X-Smithproxy-GUI-Gateway": gateway_secret}
            capabilities = wait_for_ready_capability(port, gateway_headers)
            assert capabilities["features"]["config_write"] is True
            assert capabilities["features"]["structural_drafts"] is False

            status, _, body = request(
                port, "/api/v1/config/draft", headers=gateway_headers)
            draft = json.loads(body)
            assert status == 200
            assert draft["base_revision"] == BASE_REVISION
            mutation_headers = {
                **gateway_headers,
                "Host": f"127.0.0.1:{port}",
                "Origin": f"http://127.0.0.1:{port}",
                "Sec-Fetch-Site": "same-origin",
                "X-Smithproxy-GUI-CSRF": "1",
                "Content-Type": "application/json",
            }
            status, _, body = request(
                port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({
                    "expected_version": draft["version"],
                    "changes": [
                        {"path": "policy.[0].action", "value": "reject"},
                        {"path": "settings.certs_ca_key_password", "value": PRIVATE_VALUE},
                    ],
                }),
            )
            mutated = json.loads(body)
            assert status == 200
            assert PRIVATE_VALUE.encode() not in body
            assert mutated["changes"][-1]["value"] == "[redacted:replace]"

            status, _, body = request(
                port, "/api/v1/config/draft/validate", "POST",
                headers=mutation_headers,
                body=json.dumps({"expected_version": mutated["version"]}),
            )
            validation = json.loads(body)
            assert status == 200
            assert validation == {
                "source": "gui-core",
                "draft_id": "workspace-draft",
                "draft_version": mutated["version"],
                "base_revision": BASE_REVISION,
                "upstream_validation": "valid",
                "validated_operations": 2,
                "warning_count": 1,
                "restart": "not-required",
            }
            assert PRIVATE_VALUE.encode() not in body

            commit_body = json.dumps({"expected_version": mutated["version"]})
            first_commit = request(
                port, "/api/v1/config/draft/commit", "POST",
                headers=mutation_headers, body=commit_body)
            assert first_commit[0] == 503
            assert PRIVATE_VALUE.encode() not in first_commit[2]
            status, _, body = request(
                port, "/api/v1/config/draft/commit", "POST",
                headers=mutation_headers, body=commit_body)
            receipt = json.loads(body)
            assert status == 200
            assert receipt["previous_revision"] == BASE_REVISION
            assert receipt["revision"] == COMMITTED_REVISION
            assert receipt["committed_operations"] == 2
            assert receipt["warning_count"] == 0
            assert receipt["restart"] == "required"
            assert isinstance(receipt["refresh_job_id"], str)
            assert PRIVATE_VALUE.encode() not in body

            with TransactionSmithproxy.request_lock:
                upstream_requests = list(TransactionSmithproxy.requests)
            assert [item["mode"] for item in upstream_requests] == [
                "validate", "commit", "commit"]
            assert upstream_requests[1]["idempotency_key"] == upstream_requests[2]["idempotency_key"]
            assert upstream_requests[0]["idempotency_key"] != upstream_requests[1]["idempotency_key"]
            assert upstream_requests[1]["operations"] == [
                {"op": "set", "path": "policy.[0].action", "value": "reject"},
                {"op": "set", "path": "settings.certs_ca_key_password", "value": PRIVATE_VALUE},
            ]

            status, _, body = request(
                port, "/api/v1/config/draft", headers=gateway_headers)
            finalized = json.loads(body)
            assert status == 200
            assert finalized["base_revision"] == COMMITTED_REVISION
            assert finalized["version"] == mutated["version"] + 1
            assert finalized["changes"] == []
            assert finalized["structural_operations"] == []

            job = wait_for_refresh_job(
                port, gateway_headers, receipt["refresh_job_id"])
            assert job["type"] == "config-refresh"
            assert job["phase"] == "synchronized"
            assert job["progress_percent"] == 100
            assert job["result"] == "Configuration snapshot synchronized"

            status, _, audit_body = request(
                port, "/api/v1/audit/recent", headers=gateway_headers)
            assert status == 200
            audits = json.loads(audit_body)["entries"]
            assert [item["outcome"] for item in audits[-3:]] == [
                "succeeded", "rejected", "succeeded"]
            assert [item["operation"] for item in audits[-3:]] == [
                "config.draft.validate", "config.draft.commit", "config.draft.commit"]
            assert PRIVATE_VALUE.encode() not in audit_body
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            fake.shutdown()
            fake.server_close()
            fake_thread.join(timeout=2)

        output = process.stdout.read() + process.stderr.read()
        assert process.returncode == 0
        assert PRIVATE_VALUE not in output
        assert api_key not in output
        assert gateway_secret not in output
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
