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
    bool use_pfs{};
    bool left_use_pfs{};
    bool right_use_pfs{};
    bool left_disable_reuse{};
    bool right_disable_reuse{};
    bool allow_untrusted_issuers{};
    bool allow_invalid_certificates{};
    bool allow_self_signed{};
    bool certificate_transparency{};
    std::uint64_t ocsp_mode{};
    bool ocsp_stapling{};
    std::uint64_t ocsp_stapling_mode{};
    bool block_alpn{};
    bool sni_based_certificates{};
    bool ip_based_certificates{};
    bool only_custom_certificates{};
    bool no_fallback_bypass{};
    bool sni_filter_uses_dns_cache{};
    bool sni_filter_uses_dns_domain_tree{};
    std::vector<std::uint64_t> redirect_warning_ports;
    bool failed_certificate_replacement{};
    bool failed_certificate_override{};
    std::uint64_t failed_certificate_override_timeout{};
    std::uint64_t failed_certificate_override_timeout_type{};
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

struct ConfigContentRule {
    std::string id;
    bool match_configured{};
    bool replacement_configured{};
    bool replacement_has_value{};
    bool fill_length{};
    std::int64_t replace_each_nth{};
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
    std::vector<ConfigContentRule> rules;
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
    std::uint64_t dtls_port{};
    std::uint64_t quic_port{};
    std::uint64_t socks_port{};
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
    bool certificate_transparency_log_configured{};
    bool ca_bundle_path_configured{};
    bool ca_bundle_file_configured{};
    bool messages_directory_configured{};
    bool payload_file_prefix_configured{};
    bool payload_file_suffix_configured{};
    std::uint64_t cli_port{};
    bool cli_password_configured{};
    bool web_rating_key_configured{};
    bool admin_group_configured{};
    std::uint64_t tuning_host_buffer_min{};
    std::uint64_t tuning_host_buffer_max_multiplier{};
    std::uint64_t tuning_host_write_full{};
    std::uint64_t tuning_host_io_batch{};
    std::uint64_t tuning_tls_write_chunk{};
    std::uint64_t tuning_host_open_timeout{};
    std::uint64_t tuning_host_idle_timeout{};
    std::uint64_t tuning_neighbor_cache_size{};
    bool thread_pool_logging{};
    bool socks_async_dns{};
    bool socks_ip_version_mixing{};
    bool socks_prefer_ipv6{};
    bool tls_autodetect{};
    bool tls_autodetect_harder{};
    bool kernel_tls{};
    std::uint64_t nameserver_count{};
    std::vector<std::string> nameservers;
    std::uint64_t api_key_count{};
    std::uint64_t api_allowed_ip_count{};
    std::vector<std::string> api_allowed_ips;
    std::uint64_t api_key_timeout{};
    std::uint64_t api_port{};
    bool api_key_extend_on_access{};
    bool api_loopback_only{};
    bool api_pam_login{};
    bool api_header_allowed{};
    bool api_bind_address_configured{};
    bool api_bind_interface_configured{};
    bool webhook_enabled{};
    bool webhook_tls_verify{};
    bool webhook_url_configured{};
    bool webhook_sift_enabled{};
    bool webhook_sift_url_configured{};
    bool webhook_sift_tenant_configured{};
    bool webhook_sift_instance_configured{};
    std::uint64_t webhook_sift_payload_limit{};
    bool webhook_host_id_configured{};
    bool webhook_bind_interface_configured{};
    bool webhook_api_override{};
    std::uint64_t webhook_ping_interval{};
    std::uint64_t webhook_neighbor_update_interval{};
    std::uint64_t webhook_neighbor_tag_refresh_age{};
    bool webhook_task_debug{};
    bool webhook_task_debug_dump{};
};

struct ConfigDebugSettings {
    struct ModuleOverride {
        std::string name;
        std::string kind;
        std::string value;
    };

    bool log_data_crc{};
    bool log_sockets{};
    bool log_online_connection_name{};
    bool log_source_lines{};
    bool log_source_lines_always{};
    std::uint64_t module_override_count{};
    std::vector<ModuleOverride> module_overrides;
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

struct ConfigCertificateAuthority {
    std::string id;
    std::string name;
    bool path_configured{};
};

struct ConfigSignatureFlowStep {
    std::string id;
    std::string side;
    std::string type;
    bool expression_configured{};
    std::uint64_t bytes_start{};
    std::uint64_t bytes_max{};
};

struct ConfigSignature {
    std::string id;
    std::string kind;
    std::string category;
    std::string name;
    std::string side;
    std::int64_t severity{};
    std::string group;
    std::string enables;
    std::string engine;
    std::vector<ConfigSignatureFlowStep> flow;
};

struct ConfigSecurityAssets {
    std::vector<ConfigCertificateAuthority> certificate_authorities;
    std::uint64_t certificate_authority_count{};
    std::uint64_t certificate_authority_path_count{};
    std::uint64_t starttls_signature_count{};
    std::uint64_t starttls_flow_step_count{};
    std::uint64_t detection_signature_count{};
    std::uint64_t detection_flow_step_count{};
    std::vector<ConfigSignature> signatures;
};

struct ConfigSnapshot {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy configuration is not configured"};
    std::optional<std::string> revision;
    // Legacy multi-section reads synthesize index IDs and must keep this false.
    bool stable_entity_ids{};
    // Local monotonic time prevents a late pre-commit fetch from rebinding the draft.
    std::chrono::steady_clock::time_point observation_started_at{};
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

struct ConfigRevisionParseResult {
    std::optional<std::string> revision;
    std::string error;
};

ConfigRevisionParseResult parse_config_revision(std::string_view payload);

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
