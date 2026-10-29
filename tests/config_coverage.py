#!/usr/bin/env python3

import json
import pathlib
import sys


EXPECTED_SECTIONS = {
    "settings",
    "debug",
    "address_objects",
    "port_objects",
    "proto_objects",
    "detection_profiles",
    "captures",
    "content_profiles",
    "tls_ca",
    "tls_profiles",
    "ssh_profiles",
    "alg_dns_profiles",
    "routing",
    "policy",
    "starttls_signatures",
    "detection_signatures",
    "script_profiles",
    "auth_profiles",
}
READ_STATUSES = {"full", "partial", "metadata", "unsupported"}
EDIT_STATUSES = {"typed", "partial", "none"}
ORIGINS = {"reference_config", "api_extension"}

FULL_TYPED_FIELDS = {
    "detection_profiles": {"name", "mode", "engines_enabled", "kb_enabled"},
    "captures": {
        "local.enabled", "local.dir", "local.file_prefix", "local.file_suffix",
        "local.pcap_quota", "local.format", "remote.enabled", "remote.tun_type",
        "remote.gre_format", "remote.tun_dst", "remote.tun_ttl",
        "remote.bind_interface", "options.calculate_checksums",
    },
    "ssh_profiles": {
        "name", "host_key", "hostkey_policy", "shell", "exec", "subsystem",
        "pty", "environment", "local_forward", "remote_forward", "x11", "agent",
    },
    "routing": {
        "name", "dnat_address", "dnat_port", "dnat_lb_method", "rewrite_sni", "rewrite_sni_to",
    },
    "script_profiles": {"name", "type", "script-file"},
}

FULL_READ_FIELDS = {
    "starttls_signatures": {
        "cat", "name", "side", "severity", "group", "enables", "engine",
        "flow", "type", "signature", "bytes_start", "bytes_max",
    },
    "detection_signatures": {
        "cat", "name", "side", "severity", "group", "enables", "engine",
        "flow", "type", "signature", "bytes_start", "bytes_max",
    },
}


def fail(message: str) -> None:
    raise AssertionError(message)


def main() -> None:
    manifest_path = pathlib.Path(sys.argv[1])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_version") != 1:
        fail("coverage schema_version must be 1")

    upstream = manifest.get("upstream", {})
    revision = upstream.get("revision", "")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        fail("upstream revision must be a full lowercase Git commit hash")

    sections = manifest.get("sections")
    if not isinstance(sections, list):
        fail("sections must be a list")

    names = [section.get("name") for section in sections]
    if len(names) != len(set(names)):
        fail("coverage section names must be unique")
    if set(names) != EXPECTED_SECTIONS:
        missing = sorted(EXPECTED_SECTIONS - set(names))
        extra = sorted(set(names) - EXPECTED_SECTIONS)
        fail(f"coverage inventory drifted; missing={missing}, extra={extra}")

    for section in sections:
        name = section["name"]
        if section.get("origin") not in ORIGINS:
            fail(f"{name}: invalid origin")
        if section.get("read") not in READ_STATUSES:
            fail(f"{name}: invalid read status")
        if section.get("edit") not in EDIT_STATUSES:
            fail(f"{name}: invalid edit status")
        if not isinstance(section.get("tracked_fields"), list):
            fail(f"{name}: tracked_fields must be a list")
        if len(section["tracked_fields"]) != len(set(section["tracked_fields"])):
            fail(f"{name}: tracked_fields must be unique")
        if not isinstance(section.get("notes"), str) or not section["notes"].strip():
            fail(f"{name}: notes are required")
        if section["read"] in {"metadata", "unsupported"} and section["edit"] != "none":
            fail(f"{name}: metadata-only or unsupported sections cannot be editable")
        if section["read"] == "unsupported" and section["tracked_fields"]:
            fail(f"{name}: unsupported sections cannot claim tracked fields")
        if section["edit"] == "typed" and section["read"] != "full":
            fail(f"{name}: typed editing requires full read coverage")
        expected_fields = FULL_TYPED_FIELDS.get(name)
        if expected_fields is not None:
            if section["read"] != "full" or section["edit"] != "typed":
                fail(f"{name}: audited active schema must remain full and typed")
            actual_fields = set(section["tracked_fields"])
            if actual_fields != expected_fields:
                missing = sorted(expected_fields - actual_fields)
                extra = sorted(actual_fields - expected_fields)
                fail(f"{name}: audited field inventory drifted; missing={missing}, extra={extra}")
        expected_read_fields = FULL_READ_FIELDS.get(name)
        if expected_read_fields is not None:
            if section["read"] != "full":
                fail(f"{name}: audited active schema must retain full read coverage")
            actual_fields = set(section["tracked_fields"])
            if actual_fields != expected_read_fields:
                missing = sorted(expected_read_fields - actual_fields)
                extra = sorted(actual_fields - expected_read_fields)
                fail(f"{name}: audited read inventory drifted; missing={missing}, extra={extra}")


if __name__ == "__main__":
    main()
