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


BASE_REVISION = "c" * 32
COMMITTED_REVISION = "d" * 32
SCHEMA_REVISION = "sha256:" + "a" * 64
PRIVATE_VALUE = "transaction-private-password"


class TransactionSmithproxy(FakeSmithproxy):
    requests = []
    request_lock = threading.Lock()
    transactions = {}
    next_transaction = 1
    reject_next_prepare = False

    def do_GET(self):
        if self.path == "/api/config/v2/capabilities":
            self.send_error(404)
            return
        super().do_GET()

    def do_POST(self):
        if not self.path.startswith("/api/config/transaction/"):
            super().do_POST()
            return
        if self.headers.get("X-API-Key") != "transaction-api-key-that-must-not-leak" or \
                self.headers.get("Cookie") is not None:
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            document = json.loads(self.rfile.read(length))
            params = document["params"]
        except (KeyError, ValueError, json.JSONDecodeError):
            self.send_error(400)
            return

        action = self.path.rsplit("/", 1)[-1]
        with TransactionSmithproxy.request_lock:
            TransactionSmithproxy.requests.append({"action": action, "params": params})

        if action == "begin":
            if params.get("base_revision") != BASE_REVISION:
                self.send_error(409)
                return
            token = f"transaction-{TransactionSmithproxy.next_transaction}"
            TransactionSmithproxy.next_transaction += 1
            TransactionSmithproxy.transactions[token] = None
            response = {
                "state": "open", "transaction": token,
                "base_revision": BASE_REVISION, "expires_in_ms": 15000,
            }
        elif action == "prepare":
            token = params.get("transaction")
            operations = params.get("operations")
            if token not in TransactionSmithproxy.transactions or not isinstance(operations, list):
                self.send_error(404)
                return
            if TransactionSmithproxy.reject_next_prepare:
                TransactionSmithproxy.reject_next_prepare = False
                self.send_response(422)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "state": "error",
                    "error": {
                        "code": "duplicate_entry",
                        "detail": f"Entry already exists: {PRIVATE_VALUE}",
                        "path": "address_objects",
                        "operation": 0,
                    },
                }).encode())
                return
            TransactionSmithproxy.transactions[token] = operations
            response = {
                "state": "prepared", "content_hash": "sha256:" + "e" * 64,
                "operation_count": len(operations), "expires_in_ms": 15000,
            }
        elif action == "abort":
            token = params.get("transaction")
            if token not in TransactionSmithproxy.transactions:
                self.send_error(404)
                return
            del TransactionSmithproxy.transactions[token]
            response = {"state": "aborted"}
        elif action == "commit":
            token = params.get("transaction")
            if token not in TransactionSmithproxy.transactions or \
                    TransactionSmithproxy.transactions[token] is None:
                self.send_error(409)
                return
            del TransactionSmithproxy.transactions[token]
            FakeSmithproxy.config_revision = COMMITTED_REVISION
            response = {
                "state": "committed", "revision": COMMITTED_REVISION,
                "content_hash": "sha256:" + "e" * 64, "unsaved": True,
            }
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())


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
    FakeSmithproxy.authorization_access_key = None
    FakeSmithproxy.authorization_requests = 0
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
    TransactionSmithproxy.transactions = {}
    TransactionSmithproxy.next_transaction = 1
    TransactionSmithproxy.reject_next_prepare = False
    script_profiles = FakeSmithproxy.config_sections.pop("script_profiles")
    auth_profiles = FakeSmithproxy.config_sections.pop("auth_profiles")
    captures = FakeSmithproxy.config_sections.pop("captures")
    tls_ca = FakeSmithproxy.config_sections.pop("tls_ca")
    detection_signatures = FakeSmithproxy.config_sections.pop("detection_signatures")
    content_rules = FakeSmithproxy.config_sections["content_profiles"]["safe-content"].pop(
        "content_rules")

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
            assert capabilities["features"]["primitive_structural_drafts"] is True
            assert capabilities["features"]["named_structural_drafts"] is True
            assert capabilities["features"]["named_renames"] is False
            assert capabilities["features"]["policy_structural_drafts"] is True
            assert capabilities["features"]["content_rule_structural_drafts"] is True
            assert capabilities["features"]["signature_structural_drafts"] is True

            status, _, body = request(port, "/api/v1/config/snapshot", headers=gateway_headers)
            live_config = json.loads(body)
            assert status == 200
            assert live_config["state"] == "ready"
            assert live_config["captures"] is None
            assert live_config["captures_present"] is False
            assert live_config["tls_ca_present"] is False
            assert live_config["starttls_signatures_present"] is True
            assert live_config["detection_signatures_present"] is False
            assert live_config["security_assets"]["certificate_authority_count"] == 0
            assert live_config["security_assets"]["starttls_signature_count"] == 1
            assert live_config["security_assets"]["detection_signature_count"] == 0

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
            unavailable_script_create = {
                "expected_version": draft["version"],
                "operation": {
                    "op": "create", "local_id": "create-script-1",
                    "collection": "script_profiles", "client_id": "audit-script",
                    "position": {"last": True},
                    "fields": {"name": "audit-script", "type": "0"},
                },
            }
            status, _, body = request(
                port, "/api/v1/config/draft/operations", "POST",
                headers=mutation_headers, body=json.dumps(unavailable_script_create))
            assert status == 422
            assert json.loads(body)["error"]["code"] == "draft.change_rejected"
            unavailable_authority_create = {
                "expected_version": draft["version"],
                "operation": {
                    "op": "create", "local_id": "create-ca-1",
                    "collection": "tls_ca", "client_id": "audit-ca",
                    "position": {"last": True},
                    "fields": {"name": "audit-ca", "path": "/private/ca"},
                },
            }
            status, _, body = request(
                port, "/api/v1/config/draft/operations", "POST",
                headers=mutation_headers, body=json.dumps(unavailable_authority_create))
            assert status == 422
            assert json.loads(body)["error"]["code"] == "draft.change_rejected"
            unavailable_rule_create = {
                "expected_version": draft["version"],
                "operation": {
                    "op": "create", "local_id": "create-content-rule-1",
                    "collection": "content_profiles.content_rules",
                    "client_id": "new-content-rule", "parent_id": "content-0",
                    "position": {"last": True},
                    "fields": {
                        "match": "request", "replace": "", "fill_length": False,
                        "replace_each_nth": 0,
                    },
                },
            }
            status, _, body = request(
                port, "/api/v1/config/draft/operations", "POST",
                headers=mutation_headers, body=json.dumps(unavailable_rule_create))
            assert status == 422
            assert json.loads(body)["error"]["code"] == "draft.change_rejected"
            status, _, body = request(
                port, "/api/v1/config/draft/changes", "POST",
                headers=mutation_headers,
                body=json.dumps({
                    "expected_version": draft["version"],
                    "changes": [
                        {"path": "policy.[0].action", "value": "reject"},
                        {"path": "address_objects.[1].value", "value": "10.0.1.0/24"},
                        {"path": "settings.certs_ca_key_password", "value": PRIVATE_VALUE},
                    ],
                }),
            )
            mutated = json.loads(body)
            assert status == 200
            assert PRIVATE_VALUE.encode() not in body
            assert mutated["changes"][-1]["value"] == "[redacted:replace]"

            status, _, body = request(
                port, "/api/v1/config/draft/operations/batch", "POST",
                headers=mutation_headers,
                body=json.dumps({
                    "expected_version": mutated["version"],
                    "operations": [
                        {
                            "op": "create", "local_id": "create-address-branch",
                            "collection": "address_objects", "client_id": "branch-address",
                            "position": {"last": True},
                            "fields": {"name": "branch", "type": "cidr", "value": "203.0.113.0/24"},
                        },
                        {
                            "op": "delete", "local_id": "delete-address-office",
                            "collection": "address_objects", "entity_id": "address-0",
                        },
                        {
                            "op": "create", "local_id": "create-policy-branch",
                            "collection": "policy", "client_id": "branch-policy",
                            "position": {"first": True}, "fields": {"name": "branch policy"},
                        },
                        {
                            "op": "create", "local_id": "create-signature-imap",
                            "collection": "starttls_signatures", "client_id": "imap-signature",
                            "position": {"last": True},
                            "fields": {"cat": "mail", "name": "imap/starttls", "side": "server"},
                        },
                        {
                            "op": "create", "local_id": "create-signature-imap-flow",
                            "collection": "starttls_signatures.flow", "client_id": "imap-flow",
                            "parent_id": "imap-signature", "position": {"last": True},
                            "fields": {
                                "side": "r", "type": "regex", "bytes_start": 0,
                                "bytes_max": 64, "signature": "private signature matcher",
                            },
                        },
                    ],
                }),
            )
            mutated = json.loads(body)
            assert status == 200
            assert len(mutated["structural_operations"]) == 5
            assert b"private signature matcher" not in body

            TransactionSmithproxy.reject_next_prepare = True
            status, _, body = request(
                port, "/api/v1/config/draft/validate", "POST",
                headers=mutation_headers,
                body=json.dumps({"expected_version": mutated["version"]}),
            )
            rejected = json.loads(body)
            assert status == 422
            assert rejected["error"]["code"] == "config.validation_rejected"
            assert rejected["error"]["details"] == {
                "code": "duplicate_entry",
                "detail": "Duplicate entry.",
                "path": "address_objects",
                "operation": 0,
            }
            assert PRIVATE_VALUE.encode() not in body

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
                "validated_operations": 8,
                "warning_count": 0,
                "restart": "not-required",
            }
            assert PRIVATE_VALUE.encode() not in body

            commit_body = json.dumps({"expected_version": mutated["version"]})
            status, _, body = request(
                port, "/api/v1/config/draft/commit", "POST",
                headers=mutation_headers, body=commit_body)
            receipt = json.loads(body)
            assert status == 200
            assert receipt["previous_revision"] == BASE_REVISION
            assert receipt["revision"] == COMMITTED_REVISION
            assert receipt["committed_operations"] == 8
            assert receipt["warning_count"] == 0
            assert receipt["restart"] == "not-required"
            assert isinstance(receipt["refresh_job_id"], str)
            assert PRIVATE_VALUE.encode() not in body

            with TransactionSmithproxy.request_lock:
                upstream_requests = list(TransactionSmithproxy.requests)
            assert [item["action"] for item in upstream_requests] == [
                "begin", "prepare", "abort",
                "begin", "prepare", "abort",
                "begin", "prepare", "commit"]
            assert upstream_requests[4]["params"]["operations"] == [
                {"op": "add", "path": "address_objects", "name": "branch"},
                {"op": "set", "path": "address_objects.branch.type",
                 "value": {"type": "string", "data": "cidr"}},
                {"op": "set", "path": "address_objects.branch.value",
                 "value": {"type": "string", "data": "203.0.113.0/24"}},
                {"op": "set", "path": "policy.[0].action",
                 "value": {"type": "string", "data": "reject"}},
                {"op": "set", "path": "address_objects.office.value",
                 "value": {"type": "string", "data": "10.0.1.0/24"}},
                {"op": "set", "path": "settings.certs_ca_key_password",
                 "value": {"type": "string", "data": PRIVATE_VALUE}},
                {"op": "remove", "path": "address_objects", "entries": ["internet"]},
                {"op": "add", "path": "policy", "name": ""},
                {"op": "set", "path": "policy.[1].name",
                 "value": {"type": "string", "data": "branch policy"}},
                {"op": "move", "path": "policy", "source": 1, "target": 0,
                 "position": "before"},
                {"op": "add", "path": "starttls_signatures", "name": "imap/starttls"},
                {"op": "set", "path": "starttls_signatures.[1].cat",
                 "value": {"type": "string", "data": "mail"}},
                {"op": "set", "path": "starttls_signatures.[1].name",
                 "value": {"type": "string", "data": "imap/starttls"}},
                {"op": "set", "path": "starttls_signatures.[1].side",
                 "value": {"type": "string", "data": "server"}},
                {"op": "add", "path": "starttls_signatures.[1].flow", "name": ""},
                {"op": "set", "path": "starttls_signatures.[1].flow.[0].bytes_max",
                 "value": {"type": "int", "data": 64}},
                {"op": "set", "path": "starttls_signatures.[1].flow.[0].bytes_start",
                 "value": {"type": "int", "data": 0}},
                {"op": "set", "path": "starttls_signatures.[1].flow.[0].side",
                 "value": {"type": "string", "data": "r"}},
                {"op": "set", "path": "starttls_signatures.[1].flow.[0].signature",
                 "value": {"type": "string", "data": "private signature matcher"}},
                {"op": "set", "path": "starttls_signatures.[1].flow.[0].type",
                 "value": {"type": "string", "data": "regex"}},
            ], upstream_requests[4]["params"]["operations"]

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
                "rejected", "succeeded", "succeeded"]
            assert [item["operation"] for item in audits[-3:]] == [
                "config.draft.validate", "config.draft.validate", "config.draft.commit"]
            assert PRIVATE_VALUE.encode() not in audit_body
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        output = process.stdout.read() + process.stderr.read()
        assert process.returncode == 0
        assert PRIVATE_VALUE not in output
        assert api_key not in output
        assert gateway_secret not in output
    FakeSmithproxy.config_sections["script_profiles"] = script_profiles
    FakeSmithproxy.config_sections["auth_profiles"] = auth_profiles
    FakeSmithproxy.config_sections["captures"] = captures
    FakeSmithproxy.config_sections["tls_ca"] = tls_ca
    FakeSmithproxy.config_sections["detection_signatures"] = detection_signatures
    FakeSmithproxy.config_sections["content_profiles"]["safe-content"][
        "content_rules"] = content_rules
    fake.shutdown()
    fake.server_close()
    fake_thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
