#include "config_snapshot.hpp"

#include <nlohmann/json.hpp>

#include <charconv>

namespace smithproxy::gui {
namespace {

using Json = nlohmann::json;

constexpr std::size_t maximum_named_objects = 4096U;
constexpr std::size_t maximum_policies = 4096U;
constexpr std::size_t maximum_references = 256U;
constexpr std::size_t maximum_name_length = 128U;
constexpr std::size_t maximum_value_length = 1024U;
constexpr std::size_t maximum_rule_length = 65536U;

bool valid_name(const std::string& value);

std::optional<Json> section_value(const std::string_view payload, const char* section) {
    const auto document = Json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) return std::nullopt;
    const auto success = document.find("success");
    if (success == document.end() || !success->is_object()) return std::nullopt;
    const auto value = success->find(section);
    if (value == success->end()) return std::nullopt;
    return std::optional<Json>(std::in_place, *value);
}

std::optional<std::string> bounded_string(const Json& object, const char* key,
                                          const std::size_t maximum, const bool optional = false) {
    const auto value = object.find(key);
    if (value == object.end()) return optional ? std::optional<std::string>{std::string{}} : std::nullopt;
    if (!value->is_string()) return std::nullopt;
    auto result = value->get<std::string>();
    if (result.size() > maximum) return std::nullopt;
    return result;
}

std::optional<std::vector<std::string>> string_array(
    const Json& object, const char* key, const bool optional = false) {
    const auto value = object.find(key);
    if (value == object.end()) {
        return optional ? std::optional<std::vector<std::string>>{std::vector<std::string>{}} : std::nullopt;
    }
    if (!value->is_array() || value->size() > maximum_references) {
        return std::nullopt;
    }
    std::vector<std::string> result;
    result.reserve(value->size());
    for (const auto& item : *value) {
        if (!item.is_string()) return std::nullopt;
        auto text = item.get<std::string>();
        if (text.empty() || text.size() > maximum_name_length) return std::nullopt;
        result.push_back(std::move(text));
    }
    return result;
}

std::optional<std::uint64_t> decimal(const Json& object, const char* key) {
    const auto text = bounded_string(object, key, 20U);
    if (!text || text->empty()) return std::nullopt;
    std::uint64_t result{};
    const auto [end, error] = std::from_chars(text->data(), text->data() + text->size(), result);
    if (error != std::errc{} || end != text->data() + text->size()) return std::nullopt;
    return result;
}

std::optional<std::uint64_t> optional_decimal(
    const Json& object, const char* key, const std::uint64_t fallback, const std::uint64_t maximum) {
    if (object.find(key) == object.end()) return fallback;
    const auto result = decimal(object, key);
    if (!result || *result > maximum) return std::nullopt;
    return result;
}

std::optional<std::size_t> optional_object_array_size(const Json& object, const char* key) {
    const auto value = object.find(key);
    if (value == object.end()) return 0U;
    if (!value->is_array() || value->size() > maximum_references) return std::nullopt;
    for (const auto& item : *value) {
        if (!item.is_object()) return std::nullopt;
    }
    return value->size();
}

std::optional<std::size_t> optional_named_object_size(const Json& object, const char* key) {
    const auto value = object.find(key);
    if (value == object.end()) return 0U;
    if (!value->is_object() || value->size() > maximum_references) return std::nullopt;
    for (const auto& [name, item] : value->items()) {
        if (!valid_name(name) || !item.is_object()) return std::nullopt;
    }
    return value->size();
}

std::optional<std::size_t> optional_string_array_size(
    const Json& object, const char* key, const std::size_t maximum_item_length = maximum_value_length) {
    const auto value = object.find(key);
    if (value == object.end()) return 0U;
    if (!value->is_array() || value->size() > maximum_references) return std::nullopt;
    for (const auto& item : *value) {
        if (!item.is_string() || item.get_ref<const std::string&>().size() > maximum_item_length) return std::nullopt;
    }
    return value->size();
}

std::optional<bool> boolean_scalar(const Json& object, const char* key, const bool fallback) {
    const auto value = object.find(key);
    if (value == object.end()) return fallback;
    if (!value->is_string()) return std::nullopt;
    const auto text = value->get<std::string>();
    if (text == "0" || text == "false") return false;
    if (text == "1" || text == "true") return true;
    return std::nullopt;
}

std::optional<bool> required_boolean_scalar(const Json& object, const char* key) {
    if (object.find(key) == object.end()) return std::nullopt;
    return boolean_scalar(object, key, false);
}

bool valid_name(const std::string& value) {
    if (value.empty() || value.size() > maximum_name_length) return false;
    for (const unsigned char character : value) {
        if (character < 0x20U || character == 0x7fU) return false;
    }
    return true;
}

std::string stable_id(const char* prefix, const std::size_t index) {
    return std::string(prefix) + '-' + std::to_string(index);
}

bool parse_addresses(const Json& section, ConfigSnapshot& snapshot, std::string& error) {
    if (!section.is_object() || section.size() > maximum_named_objects) {
        error = "Smithproxy returned an invalid address object collection";
        return false;
    }
    snapshot.addresses.reserve(section.size());
    std::size_t index{};
    for (const auto& [name, value] : section.items()) {
        if (!valid_name(name) || !value.is_object()) {
            error = "Smithproxy returned an invalid address object";
            return false;
        }
        const auto raw_type = bounded_string(value, "type", 16U);
        if (!raw_type) {
            error = "Smithproxy address object type is invalid";
            return false;
        }
        std::string type;
        std::optional<std::string> address;
        if (*raw_type == "cidr" || *raw_type == "fqdn") {
            type = *raw_type;
            address = bounded_string(value, "value", maximum_value_length);
        } else if (*raw_type == "0") {
            type = "cidr";
            address = bounded_string(value, "cidr", maximum_value_length);
        } else if (*raw_type == "1") {
            type = "fqdn";
            address = bounded_string(value, "fqdn", maximum_value_length);
        }
        if (!address || address->empty()) {
            error = "Smithproxy address object value is invalid";
            return false;
        }
        snapshot.addresses.push_back({stable_id("address", index++), name, type, *address});
    }
    return true;
}

bool parse_ports(const Json& section, ConfigSnapshot& snapshot, std::string& error) {
    if (!section.is_object() || section.size() > maximum_named_objects) {
        error = "Smithproxy returned an invalid port object collection";
        return false;
    }
    snapshot.ports.reserve(section.size());
    std::size_t index{};
    for (const auto& [name, value] : section.items()) {
        const auto start = value.is_object() ? decimal(value, "start") : std::nullopt;
        const auto end = value.is_object() ? decimal(value, "end") : std::nullopt;
        if (!valid_name(name) || !start || !end || *start > *end || *end > 65535U) {
            error = "Smithproxy returned an invalid port object";
            return false;
        }
        snapshot.ports.push_back({stable_id("port", index++), name, *start, *end});
    }
    return true;
}

bool parse_protocols(const Json& section, ConfigSnapshot& snapshot, std::string& error) {
    if (!section.is_object() || section.size() > maximum_named_objects) {
        error = "Smithproxy returned an invalid protocol object collection";
        return false;
    }
    snapshot.protocols.reserve(section.size());
    std::size_t index{};
    for (const auto& [name, value] : section.items()) {
        const auto number = value.is_object() ? decimal(value, "id") : std::nullopt;
        if (!valid_name(name) || !number || *number > 255U) {
            error = "Smithproxy returned an invalid protocol object";
            return false;
        }
        snapshot.protocols.push_back({stable_id("protocol", index++), name, *number});
    }
    return true;
}

bool parse_policies(const Json& section, ConfigSnapshot& snapshot, std::string& error) {
    if (!section.is_array() || section.size() > maximum_policies) {
        error = "Smithproxy returned an invalid policy collection";
        return false;
    }
    snapshot.policies.reserve(section.size());
    for (std::size_t index = 0; index < section.size(); ++index) {
        const auto& value = section[index];
        if (!value.is_object()) {
            error = "Smithproxy returned an invalid policy entry";
            return false;
        }
        const auto configured_name = bounded_string(value, "name", maximum_name_length, true);
        const auto disabled = boolean_scalar(value, "disabled", false);
        const auto protocol = bounded_string(value, "proto", maximum_name_length);
        const auto sources = string_array(value, "src");
        const auto source_ports = string_array(value, "sport");
        const auto destinations = string_array(value, "dst");
        const auto destination_ports = string_array(value, "dport");
        const auto features = string_array(value, "features", true);
        const auto action = bounded_string(value, "action", 32U);
        const auto nat = bounded_string(value, "nat", maximum_name_length, true);
        const auto routing = bounded_string(value, "routing", maximum_name_length, true);
        const auto tls_profile = bounded_string(value, "tls_profile", maximum_name_length, true);
        const auto ssh_profile = bounded_string(value, "ssh_profile", maximum_name_length, true);
        const auto detection_profile = bounded_string(value, "detection_profile", maximum_name_length, true);
        const auto content_profile = bounded_string(value, "content_profile", maximum_name_length, true);
        const auto auth_profile = bounded_string(value, "auth_profile", maximum_name_length, true);
        const auto dns_profile = bounded_string(value, "alg_dns_profile", maximum_name_length, true);
        const auto script_profile = bounded_string(value, "script_profile", maximum_name_length, true);
        if (!configured_name || !disabled || !protocol || protocol->empty() || !sources || !source_ports || !destinations ||
            !destination_ports || !features || !action || action->empty() || !nat || !routing || !tls_profile ||
            !ssh_profile || !detection_profile || !content_profile || !auth_profile || !dns_profile || !script_profile) {
            error = "Smithproxy policy fields are invalid";
            return false;
        }
        snapshot.policies.push_back({
            stable_id("policy", index),
            configured_name->empty() ? "Policy " + std::to_string(index + 1U) : *configured_name,
            !*disabled, *protocol,
            *sources, *source_ports, *destinations, *destination_ports,
            *features, *action, *nat, *routing, *tls_profile, *ssh_profile,
            *detection_profile, *content_profile, *auth_profile, *dns_profile, *script_profile,
        });
    }
    return true;
}

} // namespace

ConfigSnapshotParseResult parse_config_snapshot(
    const std::string_view policy_payload,
    const std::string_view address_payload,
    const std::string_view port_payload,
    const std::string_view protocol_payload) {
    const auto policies = section_value(policy_payload, "policy");
    const auto addresses = section_value(address_payload, "address_objects");
    const auto ports = section_value(port_payload, "port_objects");
    const auto protocols = section_value(protocol_payload, "proto_objects");
    if (!policies || !addresses || !ports || !protocols) {
        return {std::nullopt, "Smithproxy returned an invalid configuration envelope"};
    }

    ConfigSnapshot result;
    result.state = "ready";
    result.detail = "Smithproxy runtime configuration is current";
    std::string error;
    if (!parse_addresses(*addresses, result, error) ||
        !parse_ports(*ports, result, error) ||
        !parse_protocols(*protocols, result, error) ||
        !parse_policies(*policies, result, error)) {
        return {std::nullopt, std::move(error)};
    }
    return {std::move(result), {}};
}

ConfigProfileParseResult parse_config_profiles(
    const std::string_view payload,
    const std::string_view section,
    const std::string_view type) {
    if (!valid_name(std::string(section)) || !valid_name(std::string(type))) {
        return {std::nullopt, "Invalid configuration profile category"};
    }
    const auto value = section_value(payload, std::string(section).c_str());
    if (!value || !value->is_object() || value->size() > maximum_named_objects) {
        return {std::nullopt, "Smithproxy returned an invalid profile collection"};
    }
    std::vector<ConfigProfile> result;
    result.reserve(value->size());
    std::size_t index{};
    for (const auto& [name, profile] : value->items()) {
        if (!valid_name(name) || !profile.is_object()) {
            return {std::nullopt, "Smithproxy returned an invalid profile entry"};
        }
        std::optional<ConfigRoutingProfile> routing;
        std::optional<ConfigTlsProfile> tls;
        std::optional<ConfigDetectionProfile> detection;
        std::optional<ConfigContentProfile> content;
        std::optional<ConfigSshProfile> ssh;
        std::optional<ConfigDnsProfile> dns;
        std::optional<ConfigScriptProfile> script;
        std::optional<ConfigAuthProfile> authentication;
        if (type == "routing") {
            const auto addresses = string_array(profile, "dnat_address", true);
            const auto ports = string_array(profile, "dnat_port", true);
            const auto method = bounded_string(profile, "dnat_lb_method", 32U, true);
            const auto rewrite_sni = bounded_string(profile, "rewrite_sni", maximum_value_length, true);
            const auto rewrite_sni_to = bounded_string(profile, "rewrite_sni_to", maximum_value_length, true);
            if (!addresses || !ports || !method ||
                (*method != "" && *method != "round-robin" && *method != "sticky-l3" && *method != "sticky-l4") ||
                !rewrite_sni || !rewrite_sni_to || (rewrite_sni->empty() != rewrite_sni_to->empty())) {
                return {std::nullopt, "Smithproxy returned an invalid routing profile"};
            }
            routing = ConfigRoutingProfile{
                *addresses,
                *ports,
                method->empty() ? "round-robin" : *method,
                *rewrite_sni,
                *rewrite_sni_to,
            };
        } else if (type == "tls") {
            const auto inspect = boolean_scalar(profile, "inspect", false);
            const auto allow_untrusted = boolean_scalar(profile, "allow_untrusted_issuers", false);
            const auto allow_invalid = boolean_scalar(profile, "allow_invalid_certs", false);
            const auto allow_self_signed = boolean_scalar(profile, "allow_self_signed", false);
            const auto ct = boolean_scalar(profile, "ct_enable", true);
            const auto stapling = boolean_scalar(profile, "ocsp_stapling", true);
            const auto alpn = boolean_scalar(profile, "alpn_block", false);
            const auto custom_only = boolean_scalar(profile, "only_custom_certs", false);
            const auto no_fallback = boolean_scalar(profile, "no_fallback_bypass", false);
            const auto key_log = boolean_scalar(profile, "sslkeylog", false);
            const auto hello_timeout = optional_decimal(profile, "client_hello_timeout", 3000U, 3600000U);
            const auto handshake_timeout = optional_decimal(profile, "handshake_timeout", 10000U, 3600000U);
            const auto bypass = string_array(profile, "sni_filter_bypass", true);
            const auto client_action = bounded_string(profile, "client_cert_action", 32U, true);
            const auto alerts = bounded_string(profile, "alerts", 16U, true);
            if (!inspect || !allow_untrusted || !allow_invalid || !allow_self_signed || !ct || !stapling || !alpn ||
                !custom_only || !no_fallback || !key_log || !hello_timeout || *hello_timeout == 0U ||
                !handshake_timeout || *handshake_timeout == 0U || !bypass || !client_action ||
                (*client_action != "" && *client_action != "block_or_replacement" &&
                 *client_action != "empty_client_cert" && *client_action != "tls_bypass" &&
                 *client_action != "use_configured") || !alerts ||
                (*alerts != "" && *alerts != "all" && *alerts != "unusual" && *alerts != "mute")) {
                return {std::nullopt, "Smithproxy returned an invalid TLS profile"};
            }
            tls = ConfigTlsProfile{
                *inspect, *allow_untrusted, *allow_invalid, *allow_self_signed, *ct, *stapling, *alpn,
                *custom_only, *no_fallback, *key_log, *hello_timeout, *handshake_timeout, bypass->size(),
                client_action->empty() ? "use_configured" : *client_action,
                alerts->empty() ? "all" : *alerts,
            };
        } else if (type == "detection") {
            const auto mode = decimal(profile, "mode");
            const auto engines = boolean_scalar(profile, "engines_enabled", true);
            const auto knowledge_base = boolean_scalar(profile, "kb_enabled", true);
            if (!mode || *mode > 2U || !engines || !knowledge_base) {
                return {std::nullopt, "Smithproxy returned an invalid detection profile"};
            }
            detection = ConfigDetectionProfile{*mode, *engines, *knowledge_base};
        } else if (type == "content") {
            const auto write_payload = required_boolean_scalar(profile, "write_payload");
            const auto write_format = bounded_string(profile, "write_format", 16U, true);
            const auto webhook = boolean_scalar(profile, "webhook_enable", false);
            const auto webhook_lock = boolean_scalar(profile, "webhook_lock_traffic", false);
            const auto ja4_client = boolean_scalar(profile, "ja4_tls_ch", false);
            const auto ja4_ignore_sni = boolean_scalar(profile, "ja4_tls_ch_ignore_sni", false);
            const auto ja4_server = boolean_scalar(profile, "ja4_tls_sh", false);
            const auto ja4_http = boolean_scalar(profile, "ja4_http", false);
            const auto session_filter = bounded_string(profile, "rules_session_filter", maximum_rule_length, true);
            const auto rule_count = optional_object_array_size(profile, "content_rules");
            if (!write_payload || !write_format ||
                (*write_format != "" && *write_format != "smcap" && *write_format != "pcap" &&
                 *write_format != "pcap_single") || !webhook || !webhook_lock || !ja4_client ||
                !ja4_ignore_sni || !ja4_server || !ja4_http || !session_filter || !rule_count) {
                return {std::nullopt, "Smithproxy returned an invalid content profile"};
            }
            content = ConfigContentProfile{
                *write_payload, write_format->empty() ? "pcap_single" : *write_format,
                *webhook, *webhook_lock, *ja4_client, *ja4_ignore_sni, *ja4_server, *ja4_http,
                !session_filter->empty(), *rule_count,
            };
        } else if (type == "ssh") {
            const auto host_key = bounded_string(profile, "host_key", maximum_value_length);
            const auto host_key_policy = bounded_string(profile, "hostkey_policy", 16U, true);
            const auto action = [&](const char* key) -> std::optional<bool> {
                const auto configured = bounded_string(profile, key, 16U, true);
                if (!configured || (*configured != "" && *configured != "pass" && *configured != "reject")) {
                    return std::nullopt;
                }
                return configured->empty() || *configured == "pass";
            };
            const auto shell = action("shell");
            const auto exec = action("exec");
            const auto subsystem = action("subsystem");
            const auto pty = action("pty");
            const auto environment = action("environment");
            const auto local_forward = action("local_forward");
            const auto remote_forward = action("remote_forward");
            const auto x11 = action("x11");
            const auto agent = action("agent");
            if (!host_key || host_key->empty() || !host_key_policy ||
                (*host_key_policy != "" && *host_key_policy != "insecure" &&
                 *host_key_policy != "accept-new" && *host_key_policy != "strict") ||
                !shell || !exec || !subsystem || !pty || !environment || !local_forward ||
                !remote_forward || !x11 || !agent) {
                return {std::nullopt, "Smithproxy returned an invalid SSH profile"};
            }
            ssh = ConfigSshProfile{
                host_key_policy->empty() ? "accept-new" : *host_key_policy,
                *shell, *exec, *subsystem, *pty, *environment, *local_forward, *remote_forward, *x11, *agent,
            };
        } else if (type == "dns") {
            const auto match = boolean_scalar(profile, "match_request_id", false);
            const auto randomize = boolean_scalar(profile, "randomize_id", false);
            const auto cached = boolean_scalar(profile, "cached_responses", false);
            if (!match || !randomize || !cached) {
                return {std::nullopt, "Smithproxy returned an invalid DNS ALG profile"};
            }
            dns = ConfigDnsProfile{*match, *randomize, *cached};
        } else if (type == "script") {
            const auto configured_type = bounded_string(profile, "type", 4U, true);
            const auto module_path = bounded_string(profile, "script-file", maximum_value_length, true);
            if (!configured_type ||
                (*configured_type != "" && *configured_type != "-1" &&
                 *configured_type != "0" && *configured_type != "1") || !module_path) {
                return {std::nullopt, "Smithproxy returned an invalid script profile"};
            }
            const auto runtime = *configured_type == "0" ? "python" :
                                 *configured_type == "1" ? "go" : "unknown";
            script = ConfigScriptProfile{runtime, !module_path->empty()};
        } else if (type == "authentication") {
            const auto authenticate = boolean_scalar(profile, "authenticate", false);
            const auto resolve = boolean_scalar(profile, "resolve", true);
            const auto identity_count = optional_named_object_size(profile, "identities");
            if (!authenticate || !resolve || !identity_count) {
                return {std::nullopt, "Smithproxy returned an invalid authentication profile"};
            }
            authentication = ConfigAuthProfile{*authenticate, *resolve, *identity_count};
        }
        result.push_back({stable_id(std::string(type).c_str(), index++), name, std::string(type),
                          std::move(routing), std::move(tls), std::move(detection), std::move(content),
                          std::move(ssh), std::move(dns), std::move(script), std::move(authentication)});
    }
    return {std::move(result), {}};
}

ConfigSettingsParseResult parse_config_settings(const std::string_view payload) {
    const auto value = section_value(payload, "settings");
    if (!value || !value->is_object()) {
        return {std::nullopt, "Smithproxy returned invalid system settings"};
    }
    const auto accept_tproxy = boolean_scalar(*value, "accept_tproxy", false);
    const auto accept_redirect = boolean_scalar(*value, "accept_redirect", false);
    const auto accept_socks = boolean_scalar(*value, "accept_socks", false);
    const auto accept_http_connect = boolean_scalar(*value, "accept_http_connect", false);
    const auto accept_api = boolean_scalar(*value, "accept_api", false);
    const auto policy_fail_open = boolean_scalar(*value, "policy_fail_open", false);
    const auto access_fail_open = boolean_scalar(*value, "policy_access_request_fail_open", false);
    const auto plaintext_workers = optional_decimal(*value, "plaintext_workers", 0U, 4096U);
    const auto tls_workers = optional_decimal(*value, "ssl_workers", 0U, 4096U);
    const auto udp_workers = optional_decimal(*value, "udp_workers", 0U, 4096U);
    const auto dtls_workers = optional_decimal(*value, "dtls_workers", 0U, 4096U);
    const auto quic_workers = optional_decimal(*value, "quic_workers", 0U, 4096U);
    const auto socks_workers = optional_decimal(*value, "socks_workers", 0U, 4096U);
    const auto http_connect_workers = optional_decimal(*value, "http_connect_workers", 0U, 4096U);
    const auto tls_autodetect = boolean_scalar(*value, "ssl_autodetect", false);
    const auto tls_autodetect_harder = boolean_scalar(*value, "ssl_autodetect_harder", false);
    const auto kernel_tls = boolean_scalar(*value, "ssl_use_ktls", false);
    const auto nameservers = optional_string_array_size(*value, "nameservers", maximum_name_length);

    Json empty = Json::object();
    const auto http_api_value = value->find("http_api");
    if (http_api_value != value->end() && !http_api_value->is_object()) {
        return {std::nullopt, "Smithproxy returned invalid HTTP API settings"};
    }
    const Json& http_api = http_api_value != value->end() && http_api_value->is_object() ? *http_api_value : empty;
    const auto api_keys = optional_string_array_size(http_api, "keys");
    const auto allowed_ips = optional_string_array_size(http_api, "allowed_ips", maximum_name_length);
    const auto loopback_only = boolean_scalar(http_api, "loopback_only", true);
    const auto pam_login = boolean_scalar(http_api, "pam_login", false);
    const auto api_header = boolean_scalar(http_api, "allow_api_header", false);

    const auto webhook_value = value->find("webhook");
    if (webhook_value != value->end() && !webhook_value->is_object()) {
        return {std::nullopt, "Smithproxy returned invalid webhook settings"};
    }
    const Json& webhook = webhook_value != value->end() && webhook_value->is_object() ? *webhook_value : empty;
    const auto webhook_enabled = boolean_scalar(webhook, "enabled", false);
    const auto webhook_tls_verify = boolean_scalar(webhook, "tls_verify", true);
    const auto webhook_url = bounded_string(webhook, "url", maximum_value_length, true);
    const auto webhook_sift = boolean_scalar(webhook, "sift", false);
    const auto webhook_api_override = boolean_scalar(webhook, "api_override", false);

    if (!accept_tproxy || !accept_redirect || !accept_socks || !accept_http_connect || !accept_api ||
        !policy_fail_open || !access_fail_open || !plaintext_workers || !tls_workers || !udp_workers ||
        !dtls_workers || !quic_workers || !socks_workers || !http_connect_workers || !tls_autodetect ||
        !tls_autodetect_harder || !kernel_tls || !nameservers || !api_keys || !allowed_ips || !loopback_only ||
        !pam_login || !api_header || !webhook_enabled || !webhook_tls_verify || !webhook_url || !webhook_sift ||
        !webhook_api_override) {
        return {std::nullopt, "Smithproxy returned invalid system settings fields"};
    }
    return {ConfigSystemSettings{
                *accept_tproxy, *accept_redirect, *accept_socks, *accept_http_connect, *accept_api,
                *policy_fail_open, *access_fail_open, *plaintext_workers, *tls_workers, *udp_workers,
                *dtls_workers, *quic_workers, *socks_workers, *http_connect_workers, *tls_autodetect,
                *tls_autodetect_harder, *kernel_tls, *nameservers, *api_keys, *allowed_ips,
                *loopback_only, *pam_login, *api_header, *webhook_enabled, *webhook_tls_verify,
                !webhook_url->empty(), *webhook_sift, *webhook_api_override,
            }, {}};
}

ConfigCapturesParseResult parse_config_captures(const std::string_view payload) {
    const auto value = section_value(payload, "captures");
    if (!value || !value->is_object()) {
        return {std::nullopt, "Smithproxy returned invalid capture settings"};
    }
    const auto local_value = value->find("local");
    const auto remote_value = value->find("remote");
    const auto options_value = value->find("options");
    if (local_value == value->end() || !local_value->is_object() ||
        remote_value == value->end() || !remote_value->is_object() ||
        (options_value != value->end() && !options_value->is_object())) {
        return {std::nullopt, "Smithproxy returned invalid capture setting groups"};
    }
    Json empty = Json::object();
    const Json& options = options_value == value->end() ? empty : *options_value;
    const auto local_enabled = required_boolean_scalar(*local_value, "enabled");
    const auto local_dir = bounded_string(*local_value, "dir", maximum_value_length);
    const auto local_format = bounded_string(*local_value, "format", 16U);
    const auto local_quota = optional_decimal(*local_value, "pcap_quota", 0U, 1024U * 1024U);
    const auto remote_enabled = required_boolean_scalar(*remote_value, "enabled");
    const auto tunnel_type = bounded_string(*remote_value, "tun_type", 16U);
    const auto gre_format = bounded_string(*remote_value, "gre_format", 16U);
    const auto destination = bounded_string(*remote_value, "tun_dst", maximum_name_length);
    const auto ttl = optional_decimal(*remote_value, "tun_ttl", 0U, 255U);
    const auto bind_interface = bounded_string(*remote_value, "bind_interface", maximum_name_length, true);
    const auto checksums = boolean_scalar(options, "calculate_checksums", false);
    if (!local_enabled || !local_dir || !local_format ||
        (*local_format != "pcap_single" && *local_format != "pcap" && *local_format != "smcap") ||
        !local_quota || !remote_enabled || !tunnel_type || *tunnel_type != "gre" || !gre_format ||
        (*gre_format != "traffic" && *gre_format != "pcapng") || !destination || !ttl ||
        !bind_interface || !checksums) {
        return {std::nullopt, "Smithproxy returned invalid capture setting fields"};
    }
    return {ConfigCaptureSettings{
                *local_enabled, !local_dir->empty(), *local_format, *local_quota,
                *remote_enabled, *tunnel_type, *gre_format, !destination->empty(), *ttl,
                !bind_interface->empty(), *checksums,
            }, {}};
}

} // namespace smithproxy::gui
