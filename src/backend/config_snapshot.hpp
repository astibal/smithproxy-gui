#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct ConfigAddressObject {
    std::string id;
    std::string name;
    std::string type;
    std::string value;
};

struct ConfigPortObject {
    std::string id;
    std::string name;
    std::uint64_t start{};
    std::uint64_t end{};
};

struct ConfigProtocolObject {
    std::string id;
    std::string name;
    std::uint64_t number{};
};

struct ConfigRoutingProfile {
    std::vector<std::string> destination_addresses;
    std::vector<std::string> destination_ports;
    std::string load_balancing_method;
    std::string rewrite_sni;
    std::string rewrite_sni_to;
};

struct ConfigTlsProfile {
    bool inspect{};
    bool allow_untrusted_issuers{};
    bool allow_invalid_certificates{};
    bool allow_self_signed{};
    bool certificate_transparency{};
    bool ocsp_stapling{};
    bool block_alpn{};
    bool only_custom_certificates{};
    bool no_fallback_bypass{};
    bool ssl_key_log{};
    std::uint64_t client_hello_timeout_ms{};
    std::uint64_t handshake_timeout_ms{};
    std::uint64_t sni_bypass_entries{};
    std::string client_certificate_action;
    std::string alerts;
};

struct ConfigDetectionProfile {
    std::uint64_t mode{};
    bool engines_enabled{};
    bool knowledge_base_enabled{};
};

struct ConfigContentProfile {
    bool write_payload{};
    std::string write_format;
    bool webhook_enabled{};
    bool webhook_locks_traffic{};
    bool ja4_tls_client_hello{};
    bool ja4_tls_client_hello_ignores_sni{};
    bool ja4_tls_server_hello{};
    bool ja4_http{};
    bool session_filter_configured{};
    std::uint64_t rule_count{};
};

struct ConfigProfile {
    std::string id;
    std::string name;
    std::string type;
    std::optional<ConfigRoutingProfile> routing;
    std::optional<ConfigTlsProfile> tls;
    std::optional<ConfigDetectionProfile> detection;
    std::optional<ConfigContentProfile> content;
};

struct ConfigPolicy {
    std::string id;
    std::string name;
    bool enabled{true};
    std::string protocol;
    std::vector<std::string> sources;
    std::vector<std::string> source_ports;
    std::vector<std::string> destinations;
    std::vector<std::string> destination_ports;
    std::vector<std::string> features;
    std::string action;
    std::string nat;
    std::string routing;
    std::string tls_profile;
    std::string ssh_profile;
    std::string detection_profile;
    std::string content_profile;
    std::string auth_profile;
    std::string dns_profile;
    std::string script_profile;
};

struct ConfigSnapshot {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy configuration is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::vector<ConfigPolicy> policies;
    std::vector<ConfigAddressObject> addresses;
    std::vector<ConfigPortObject> ports;
    std::vector<ConfigProtocolObject> protocols;
    std::vector<ConfigProfile> profiles;
};

struct ConfigSnapshotParseResult {
    std::optional<ConfigSnapshot> snapshot;
    std::string error;
};

ConfigSnapshotParseResult parse_config_snapshot(
    std::string_view policy_payload,
    std::string_view address_payload,
    std::string_view port_payload,
    std::string_view protocol_payload);

struct ConfigProfileParseResult {
    std::optional<std::vector<ConfigProfile>> profiles;
    std::string error;
};

ConfigProfileParseResult parse_config_profiles(
    std::string_view payload,
    std::string_view section,
    std::string_view type);

} // namespace smithproxy::gui
