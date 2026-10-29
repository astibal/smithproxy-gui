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
API_EXTENSION_SECTIONS = {"captures", "script_profiles", "auth_profiles"}
SENSITIVITIES = {
    "configuration", "operational", "secret-bearing", "path-bearing",
    "rule-bearing", "security-critical", "code-bearing", "identity-bearing",
}

FULL_TYPED_FIELDS = {
    "settings": {
        "accept_tproxy", "accept_redirect", "accept_socks", "accept_http_connect",
        "accept_api", "policy_fail_open",
        "policy_access_request_fail_open", "plaintext_workers", "ssl_workers",
        "udp_workers", "dtls_workers", "quic_workers", "socks_workers",
        "http_connect_workers", "plaintext_port", "ssl_port", "udp_port", "dtls_port",
        "quic_port", "socks_port", "http_connect_port", "ssl_ocsp_status_ttl",
        "ssl_crl_status_ttl", "default_write_payload", "write_payload_dir",
        "write_pcap_single_quota", "log_level", "log_file", "log_console",
        "sslkeylog_file", "syslog_server", "syslog_port", "syslog_facility",
        "syslog_level", "syslog_family", "ssl_autodetect", "udp_quick_ports",
        "certs_path", "certs_ca_key_password", "certs_ctlog", "ca_bundle_path",
        "ca_bundle_file", "admin", "tuning", "messages_dir",
        "write_payload_file_prefix", "write_payload_file_suffix", "cli", "web_rating",
        "tpool_log", "socks", "ssl_autodetect_harder", "ssl_use_ktls", "nameservers",
        "http_api", "webhook",
    },
    "debug": {
        "log_data_crc", "log_sockets", "log_online_cx_name", "log_srclines",
        "log_srclines_always", "log",
    },
    "address_objects": {"name", "type", "value"},
    "port_objects": {"name", "start", "end"},
    "proto_objects": {"name", "id"},
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
    "tls_profiles": {
        "name", "inspect", "no_fallback_bypass", "client_hello_timeout",
        "handshake_timeout", "use_pfs", "left_use_pfs", "right_use_pfs",
        "left_disable_reuse", "right_disable_reuse", "allow_untrusted_issuers",
        "allow_invalid_certs", "allow_self_signed", "ocsp_mode", "ocsp_stapling",
        "ocsp_stapling_mode", "ct_enable", "alpn_block",
        "failed_certcheck_replacement", "failed_certcheck_override",
        "failed_certcheck_override_timeout", "failed_certcheck_override_timeout_type",
        "client_cert_action", "sni_based_cert", "ip_based_cert", "only_custom_certs",
        "sni_filter_bypass", "sni_filter_use_dns_cache",
        "sni_filter_use_dns_domain_tree", "redirect_warning_ports", "sslkeylog", "alerts",
    },
    "alg_dns_profiles": {"name", "match_request_id", "randomize_id", "cached_responses"},
    "policy": {
        "name", "action", "proto", "src", "sport", "dst", "dport", "features",
        "tls_profile", "ssh_profile", "detection_profile", "content_profile",
        "alg_dns_profile", "script_profile", "auth_profile", "nat", "routing", "disabled",
    },
    "script_profiles": {"name", "type", "script-file"},
}

FULL_READ_FIELDS = {
    "content_profiles": {
        "name", "write_payload", "write_format", "webhook_enable",
        "webhook_lock_traffic", "ja4_tls_ch", "ja4_tls_ch_ignore_sni", "ja4_tls_sh",
        "ja4_http", "rules_session_filter", "content_rules",
    },
    "starttls_signatures": {
        "cat", "name", "side", "severity", "group", "enables", "engine",
        "flow", "type", "signature", "bytes_start", "bytes_max",
    },
    "detection_signatures": {
        "cat", "name", "side", "severity", "group", "enables", "engine",
        "flow", "type", "signature", "bytes_start", "bytes_max",
    },
}

PARTIAL_FIELDS = {
    "tls_ca": {"name", "path_configured"},
    "auth_profiles": {"name", "authenticate", "resolve", "identity_count"},
}


def fail(message: str) -> None:
    raise AssertionError(message)


def main() -> None:
    manifest_path = pathlib.Path(sys.argv[1])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if manifest.get("schema_version") != 1:
        fail("coverage schema_version must be 1")

    upstream = manifest.get("upstream", {})
    if upstream.get("repository") != "astibal/smithproxy":
        fail("upstream repository must be astibal/smithproxy")
    if upstream.get("reference_config") != "etc/smithproxy.cfg":
        fail("upstream reference_config must be etc/smithproxy.cfg")
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
        expected_origin = "api_extension" if name in API_EXTENSION_SECTIONS else "reference_config"
        if section["origin"] != expected_origin:
            fail(f"{name}: origin drifted from {expected_origin}")
        if section.get("sensitivity") not in SENSITIVITIES:
            fail(f"{name}: invalid sensitivity")
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
            if section["read"] != "full" or section["edit"] != "partial":
                fail(f"{name}: audited rule-bearing schema must remain full read and partial edit")
            actual_fields = set(section["tracked_fields"])
            if actual_fields != expected_read_fields:
                missing = sorted(expected_read_fields - actual_fields)
                extra = sorted(actual_fields - expected_read_fields)
                fail(f"{name}: audited read inventory drifted; missing={missing}, extra={extra}")
        expected_partial_fields = PARTIAL_FIELDS.get(name)
        if expected_partial_fields is not None:
            if section["read"] != "partial" or section["edit"] != "partial":
                fail(f"{name}: audited partial schema status drifted")
            actual_fields = set(section["tracked_fields"])
            if actual_fields != expected_partial_fields:
                missing = sorted(expected_partial_fields - actual_fields)
                extra = sorted(actual_fields - expected_partial_fields)
                fail(f"{name}: audited partial inventory drifted; missing={missing}, extra={extra}")


if __name__ == "__main__":
    main()
