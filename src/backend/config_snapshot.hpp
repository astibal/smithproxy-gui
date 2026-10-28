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

struct ConfigSshProfile {
    std::string host_key_policy;
    bool shell{};
    bool exec{};
    bool subsystem{};
    bool pty{};
    bool environment{};
    bool local_forward{};
    bool remote_forward{};
    bool x11{};
    bool agent{};
};

struct ConfigDnsProfile {
    bool match_request_id{};
    bool randomize_id{};
    bool cached_responses{};
};

struct ConfigScriptProfile {
    std::string runtime;
    bool module_path_configured{};
};

struct ConfigAuthProfile {
    bool authenticate{};
    bool resolve{};
    std::uint64_t identity_count{};
};

struct ConfigProfile {
    std::string id;
    std::string name;
    std::string type;
    std::optional<ConfigRoutingProfile> routing;
    std::optional<ConfigTlsProfile> tls;
    std::optional<ConfigDetectionProfile> detection;
    std::optional<ConfigContentProfile> content;
    std::optional<ConfigSshProfile> ssh;
    std::optional<ConfigDnsProfile> dns;
    std::optional<ConfigScriptProfile> script;
    std::optional<ConfigAuthProfile> authentication;
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

struct ConfigSystemSettings {
    bool accept_tproxy{};
    bool accept_redirect{};
    bool accept_socks{};
    bool accept_http_connect{};
    bool accept_api{};
    bool policy_fail_open{};
    bool access_request_fail_open{};
    std::int64_t plaintext_workers{};
    std::int64_t tls_workers{};
    std::int64_t udp_workers{};
    std::int64_t dtls_workers{};
    std::int64_t quic_workers{};
    std::int64_t socks_workers{};
    std::int64_t http_connect_workers{};
    std::uint64_t plaintext_port{};
    std::uint64_t tls_port{};
    std::uint64_t udp_port{};
    std::uint64_t quic_port{};
    std::uint64_t http_connect_port{};
    std::uint64_t ocsp_status_ttl{};
    std::uint64_t crl_status_ttl{};
    bool default_write_payload{};
    bool payload_directory_configured{};
    std::uint64_t write_pcap_single_quota{};
    std::uint64_t log_level{};
    bool log_file_configured{};
    bool log_console{};
    bool ssl_key_log_file_configured{};
    bool syslog_server_configured{};
    std::uint64_t syslog_port{};
    std::uint64_t syslog_facility{};
    std::uint64_t syslog_level{};
    std::uint64_t syslog_family{};
    std::uint64_t udp_quick_port_count{};
    std::vector<std::string> udp_quick_ports;
    bool certificates_path_configured{};
    bool certificate_password_configured{};
    bool ca_bundle_path_configured{};
    bool messages_directory_configured{};
    bool payload_file_prefix_configured{};
    bool payload_file_suffix_configured{};
    std::uint64_t cli_port{};
    bool cli_password_configured{};
    bool web_rating_key_configured{};
    bool socks_async_dns{};
    bool tls_autodetect{};
    bool tls_autodetect_harder{};
    bool kernel_tls{};
    std::uint64_t nameserver_count{};
    std::vector<std::string> nameservers;
    std::uint64_t api_key_count{};
    std::uint64_t api_allowed_ip_count{};
    std::vector<std::string> api_allowed_ips;
    bool api_loopback_only{};
    bool api_pam_login{};
    bool api_header_allowed{};
    bool webhook_enabled{};
    bool webhook_tls_verify{};
    bool webhook_url_configured{};
    bool webhook_sift_enabled{};
    bool webhook_api_override{};
};

struct ConfigDebugSettings {
    bool log_data_crc{};
    bool log_sockets{};
    bool log_online_connection_name{};
    bool log_source_lines{};
    bool log_source_lines_always{};
    std::uint64_t module_override_count{};
};

struct ConfigCaptureSettings {
    bool local_enabled{};
    bool local_directory_configured{};
    bool local_file_prefix_configured{};
    bool local_file_suffix_configured{};
    std::string local_format;
    std::uint64_t local_quota_mib{};
    bool remote_enabled{};
    std::string remote_tunnel_type;
    std::string remote_gre_format;
    bool remote_destination_configured{};
    std::uint64_t remote_ttl{};
    bool remote_bind_interface_configured{};
    bool calculate_checksums{};
};

struct ConfigSecurityAssets {
    std::uint64_t certificate_authority_count{};
    std::uint64_t certificate_authority_path_count{};
    std::uint64_t starttls_signature_count{};
    std::uint64_t starttls_flow_step_count{};
    std::uint64_t detection_signature_count{};
    std::uint64_t detection_flow_step_count{};
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
    std::optional<ConfigSystemSettings> settings;
    std::optional<ConfigDebugSettings> debug;
    std::optional<ConfigCaptureSettings> captures;
    std::optional<ConfigSecurityAssets> security_assets;
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

struct ConfigSettingsParseResult {
    std::optional<ConfigSystemSettings> settings;
    std::string error;
};

ConfigSettingsParseResult parse_config_settings(std::string_view payload);

struct ConfigDebugParseResult {
    std::optional<ConfigDebugSettings> debug;
    std::string error;
};

ConfigDebugParseResult parse_config_debug(std::string_view payload);

struct ConfigCapturesParseResult {
    std::optional<ConfigCaptureSettings> captures;
    std::string error;
};

ConfigCapturesParseResult parse_config_captures(std::string_view payload);

struct ConfigSecurityAssetsParseResult {
    std::optional<ConfigSecurityAssets> security_assets;
    std::string error;
};

ConfigSecurityAssetsParseResult parse_config_security_assets(
    std::string_view certificate_authority_payload,
    std::string_view starttls_signature_payload,
    std::string_view detection_signature_payload);

} // namespace smithproxy::gui
