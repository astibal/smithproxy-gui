#include "draft_schema.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {
namespace {

using Result = DraftSchemaResult;

template <std::size_t Size>
bool one_of(const std::string_view value, const std::array<std::string_view, Size>& choices) {
    return std::find(choices.begin(), choices.end(), value) != choices.end();
}

std::optional<std::string_view> indexed_suffix(
    const std::string_view path, const std::string_view root) {
    const std::string prefix = std::string(root) + ".[";
    if (!path.starts_with(prefix)) return std::nullopt;
    const auto close = path.find(']', prefix.size());
    if (close == std::string_view::npos || close + 2U > path.size() || path[close + 1U] != '.') {
        return std::nullopt;
    }
    const auto index_text = path.substr(prefix.size(), close - prefix.size());
    if (index_text.empty() || (index_text.size() > 1U && index_text.front() == '0')) return std::nullopt;
    std::uint64_t index{};
    const auto [end, error] = std::from_chars(
        index_text.data(), index_text.data() + index_text.size(), index);
    if (error != std::errc{} || end != index_text.data() + index_text.size() || index >= 4096U) {
        return std::nullopt;
    }
    const auto suffix = path.substr(close + 2U);
    return suffix.empty() ? std::nullopt : std::optional<std::string_view>{suffix};
}

const std::string* text(const DraftScalar& value) {
    return std::get_if<std::string>(&value);
}

const std::vector<std::string>* strings(const DraftScalar& value) {
    return std::get_if<std::vector<std::string>>(&value);
}

const std::vector<std::int64_t>* integers(const DraftScalar& value) {
    return std::get_if<std::vector<std::int64_t>>(&value);
}

const DraftAuthIdentities* auth_identities(const DraftScalar& value) {
    return std::get_if<DraftAuthIdentities>(&value);
}

const std::int64_t* integer(const DraftScalar& value) {
    return std::get_if<std::int64_t>(&value);
}

bool boolean(const DraftScalar& value) {
    return std::holds_alternative<bool>(value);
}

bool printable(const std::string_view value, const std::size_t maximum, const bool empty = false) {
    if ((!empty && value.empty()) || value.size() > maximum) return false;
    return std::none_of(value.begin(), value.end(), [](const unsigned char character) {
        return character < 0x20U || character == 0x7fU;
    });
}

bool safe_identity_name(const std::string_view value) {
    const auto ascii_alpha = [](const unsigned char character) {
        return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z');
    };
    if (value.empty() || value.size() > 128U ||
        !(ascii_alpha(static_cast<unsigned char>(value.front())) || value.front() == '_')) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [&](const unsigned char character) {
        return ascii_alpha(character) || (character >= '0' && character <= '9') ||
               character == '_' || character == '-';
    });
}

bool valid_auth_identities(const DraftScalar& value) {
    if (const auto* cleared = strings(value); cleared != nullptr && cleared->empty()) return true;
    const auto* identities = auth_identities(value);
    if (identities == nullptr || identities->empty() || identities->size() > 256U) return false;
    for (std::size_t index = 0; index < identities->size(); ++index) {
        const auto& identity = (*identities)[index];
        const auto duplicate = std::find_if(
            identities->begin(), identities->begin() + static_cast<std::ptrdiff_t>(index),
            [&](const DraftAuthIdentity& candidate) { return candidate.name == identity.name; });
        if (!safe_identity_name(identity.name) ||
            duplicate != identities->begin() + static_cast<std::ptrdiff_t>(index)) {
            return false;
        }
        const std::array references{
            std::string_view{identity.detection_profile}, std::string_view{identity.content_profile},
            std::string_view{identity.tls_profile}, std::string_view{identity.alg_dns_profile},
        };
        if (std::all_of(references.begin(), references.end(), [](const auto reference) {
                return reference.empty();
            }) || std::any_of(references.begin(), references.end(), [](const auto reference) {
                return !reference.empty() && !printable(reference, 128U);
            })) {
            return false;
        }
    }
    return true;
}

bool bounded_text(const DraftScalar& value, const std::size_t maximum, const bool empty = false) {
    const auto* item = text(value);
    return item != nullptr && printable(*item, maximum, empty);
}

bool opaque_text(const DraftScalar& value, const std::size_t maximum, const bool empty = false) {
    const auto* item = text(value);
    return item != nullptr && (empty || !item->empty()) && item->size() <= maximum &&
           item->find('\0') == std::string::npos;
}

bool enumerated(const DraftScalar& value, const std::initializer_list<std::string_view> choices) {
    const auto* item = text(value);
    return item != nullptr && std::find(choices.begin(), choices.end(), *item) != choices.end();
}

bool bounded_integer(const DraftScalar& value, const std::int64_t minimum, const std::int64_t maximum) {
    const auto* item = integer(value);
    return item != nullptr && *item >= minimum && *item <= maximum;
}

bool string_list(const DraftScalar& value, const std::size_t maximum_length = 128U,
                 const bool empty = true) {
    const auto* items = strings(value);
    if (items == nullptr || (!empty && items->empty()) || items->size() > 256U) return false;
    for (std::size_t index = 0; index < items->size(); ++index) {
        if (!printable((*items)[index], maximum_length)) return false;
        if (std::find(items->begin(), items->begin() + static_cast<std::ptrdiff_t>(index),
                      (*items)[index]) != items->begin() + static_cast<std::ptrdiff_t>(index)) {
            return false;
        }
    }
    return true;
}

bool enumerated_string_list(
    const DraftScalar& value, const std::initializer_list<std::string_view> choices) {
    if (!string_list(value)) return false;
    const auto& items = *strings(value);
    return std::all_of(items.begin(), items.end(), [&](const auto& item) {
        return std::find(choices.begin(), choices.end(), item) != choices.end();
    });
}

bool opaque_string_list(const DraftScalar& value, const std::size_t maximum_length) {
    const auto* items = strings(value);
    if (items == nullptr || items->size() > 256U) return false;
    for (std::size_t index = 0; index < items->size(); ++index) {
        const auto& item = (*items)[index];
        if (item.empty() || item.size() > maximum_length || item.find('\0') != std::string::npos ||
            std::find(items->begin(), items->begin() + static_cast<std::ptrdiff_t>(index), item) !=
                items->begin() + static_cast<std::ptrdiff_t>(index)) {
            return false;
        }
    }
    return true;
}

bool integer_list(const DraftScalar& value, const std::int64_t minimum, const std::int64_t maximum) {
    const auto* items = integers(value);
    if (items == nullptr || items->size() > 256U) return false;
    for (std::size_t index = 0; index < items->size(); ++index) {
        if ((*items)[index] < minimum || (*items)[index] > maximum ||
            std::find(items->begin(), items->begin() + static_cast<std::ptrdiff_t>(index),
                      (*items)[index]) != items->begin() + static_cast<std::ptrdiff_t>(index)) {
            return false;
        }
    }
    return true;
}

Result valid(const bool condition) {
    return condition ? Result::Valid : Result::InvalidValue;
}

Result validate_policy(const std::string_view field, const DraftScalar& value) {
    if (field == "name") return valid(bounded_text(value, 128U));
    if (field == "disabled") return valid(boolean(value));
    if (field == "proto") return valid(bounded_text(value, 128U));
    if (field == "src" || field == "dst") return valid(string_list(value));
    if (field == "sport" || field == "dport") return valid(string_list(value));
    if (field == "features") {
        return valid(enumerated_string_list(value, {
            "sink-left", "sink-right", "sink-all", "statistics", "access-request",
        }));
    }
    if (field == "action") return valid(enumerated(value, {"accept", "deny", "reject"}));
    if (field == "nat") return valid(enumerated(value, {"auto", "none"}));
    constexpr std::array references{
        std::string_view{"routing"}, std::string_view{"tls_profile"},
        std::string_view{"ssh_profile"}, std::string_view{"detection_profile"},
        std::string_view{"content_profile"}, std::string_view{"auth_profile"},
        std::string_view{"alg_dns_profile"}, std::string_view{"script_profile"},
    };
    if (one_of(field, references)) return valid(bounded_text(value, 128U, true));
    return Result::UnknownPath;
}

Result validate_tls(const std::string_view field, const DraftScalar& value) {
    constexpr std::array booleans{
        std::string_view{"inspect"}, std::string_view{"use_pfs"}, std::string_view{"left_use_pfs"},
        std::string_view{"right_use_pfs"}, std::string_view{"left_disable_reuse"},
        std::string_view{"right_disable_reuse"}, std::string_view{"allow_untrusted_issuers"},
        std::string_view{"allow_invalid_certs"}, std::string_view{"allow_self_signed"},
        std::string_view{"ct_enable"}, std::string_view{"ocsp_stapling"},
        std::string_view{"alpn_block"}, std::string_view{"sni_based_cert"},
        std::string_view{"ip_based_cert"}, std::string_view{"only_custom_certs"},
        std::string_view{"no_fallback_bypass"}, std::string_view{"sni_filter_use_dns_cache"},
        std::string_view{"sni_filter_use_dns_domain_tree"},
        std::string_view{"failed_certcheck_replacement"},
        std::string_view{"failed_certcheck_override"}, std::string_view{"sslkeylog"},
    };
    if (field == "name") return valid(bounded_text(value, 128U));
    if (one_of(field, booleans)) return valid(boolean(value));
    if (field == "ocsp_mode" || field == "ocsp_stapling_mode") {
        return valid(bounded_integer(value, 0, 2));
    }
    if (field == "failed_certcheck_override_timeout_type") {
        return valid(bounded_integer(value, 0, 1));
    }
    if (field == "failed_certcheck_override_timeout" || field == "client_hello_timeout" ||
        field == "handshake_timeout") {
        return valid(bounded_integer(value, 1, 2147483647));
    }
    if (field == "redirect_warning_ports") return valid(integer_list(value, 0, 65535));
    if (field == "sni_filter_bypass") return valid(string_list(value, 1024U));
    if (field == "client_cert_action") {
        return valid(enumerated(value, {"block_or_replacement", "empty_client_cert",
                                        "tls_bypass", "use_configured"}));
    }
    if (field == "alerts") return valid(enumerated(value, {"all", "unusual", "mute"}));
    return Result::UnknownPath;
}

Result validate_content(const std::string_view field, const DraftScalar& value) {
    if (const auto nested = indexed_suffix(field, "content_rules")) {
        if (*nested == "fill_length") return valid(boolean(value));
        if (*nested == "replace_each_nth") {
            return valid(bounded_integer(value, -2147483648LL, 2147483647LL));
        }
        if (*nested == "match") return valid(opaque_text(value, 65536U));
        if (*nested == "replace") return valid(opaque_text(value, 65536U, true));
        return Result::UnknownPath;
    }
    constexpr std::array booleans{
        std::string_view{"write_payload"}, std::string_view{"webhook_enable"},
        std::string_view{"webhook_lock_traffic"}, std::string_view{"ja4_tls_ch"},
        std::string_view{"ja4_tls_ch_ignore_sni"}, std::string_view{"ja4_tls_sh"},
        std::string_view{"ja4_http"},
    };
    if (field == "name") return valid(bounded_text(value, 128U));
    if (one_of(field, booleans)) return valid(boolean(value));
    if (field == "write_format") return valid(enumerated(value, {"smcap", "pcap", "pcap_single"}));
    if (field == "rules_session_filter") return valid(opaque_text(value, 65536U, true));
    return Result::UnknownPath;
}

Result validate_signature(const std::string_view field, const DraftScalar& value) {
    if (const auto nested = indexed_suffix(field, "flow")) {
        if (*nested == "side") return valid(enumerated(value, {"r", "w"}));
        if (*nested == "type") return valid(enumerated(value, {"regex", "simple"}));
        if (*nested == "bytes_start" || *nested == "bytes_max") {
            return valid(bounded_integer(value, 0, 9007199254740991LL));
        }
        if (*nested == "signature") return valid(opaque_text(value, 65536U));
        return Result::UnknownPath;
    }
    if (field == "severity") return valid(bounded_integer(value, -2147483648LL, 2147483647LL));
    if (field == "side") return valid(enumerated(value, {"client", "server"}));
    constexpr std::array metadata{
        std::string_view{"cat"}, std::string_view{"name"}, std::string_view{"group"},
        std::string_view{"enables"}, std::string_view{"engine"},
    };
    if (one_of(field, metadata)) return valid(bounded_text(value, 128U, field != "name"));
    return Result::UnknownPath;
}

Result validate_indexed(const std::string_view path, const DraftScalar& value) {
    if (const auto field = indexed_suffix(path, "policy")) return validate_policy(*field, value);
    if (const auto field = indexed_suffix(path, "address_objects")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "type") return valid(enumerated(value, {"cidr", "fqdn"}));
        if (*field == "value") return valid(bounded_text(value, 1024U));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "port_objects")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "start" || *field == "end") return valid(bounded_integer(value, 0, 65535));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "proto_objects")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "id") return valid(bounded_integer(value, 1, 255));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "routing")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "dnat_address" || *field == "dnat_port") return valid(string_list(value));
        if (*field == "dnat_lb_method") return valid(enumerated(value, {"round-robin", "sticky-l3", "sticky-l4"}));
        if (*field == "rewrite_sni" || *field == "rewrite_sni_to") return valid(bounded_text(value, 1024U, true));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "tls_profiles")) return validate_tls(*field, value);
    if (const auto field = indexed_suffix(path, "content_profiles")) return validate_content(*field, value);
    if (const auto field = indexed_suffix(path, "ssh_profiles")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "hostkey_policy") return valid(enumerated(value, {"insecure", "accept-new", "strict"}));
        if (*field == "host_key") return valid(bounded_text(value, 1024U, true));
        constexpr std::array actions{
            std::string_view{"shell"}, std::string_view{"exec"}, std::string_view{"subsystem"},
            std::string_view{"pty"}, std::string_view{"environment"},
            std::string_view{"local_forward"}, std::string_view{"remote_forward"},
            std::string_view{"x11"}, std::string_view{"agent"},
        };
        if (one_of(*field, actions)) return valid(enumerated(value, {"pass", "reject"}));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "script_profiles")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "type") return valid(enumerated(value, {"-1", "0", "1"}));
        if (*field == "script-file") return valid(bounded_text(value, 1024U, true));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "auth_profiles")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "authenticate" || *field == "resolve") return valid(boolean(value));
        if (*field == "identities") return valid(valid_auth_identities(value));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "detection_profiles")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "mode") return valid(bounded_integer(value, 0, 2));
        if (*field == "engines_enabled" || *field == "kb_enabled") return valid(boolean(value));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "alg_dns_profiles")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "match_request_id" || *field == "randomize_id" || *field == "cached_responses") {
            return valid(boolean(value));
        }
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "tls_ca")) {
        if (*field == "name") return valid(bounded_text(value, 128U));
        if (*field == "path") return valid(bounded_text(value, 1024U, true));
        return Result::UnknownPath;
    }
    if (const auto field = indexed_suffix(path, "starttls_signatures")) {
        return validate_signature(*field, value);
    }
    if (const auto field = indexed_suffix(path, "detection_signatures")) {
        return validate_signature(*field, value);
    }
    return Result::UnknownPath;
}

Result validate_settings(const std::string_view field, const DraftScalar& value) {
    constexpr std::array booleans{
        std::string_view{"accept_tproxy"}, std::string_view{"accept_redirect"},
        std::string_view{"accept_socks"}, std::string_view{"accept_http_connect"},
        std::string_view{"accept_api"},
        std::string_view{"policy_fail_open"}, std::string_view{"policy_access_request_fail_open"},
        std::string_view{"ssl_autodetect"}, std::string_view{"ssl_autodetect_harder"},
        std::string_view{"ssl_use_ktls"}, std::string_view{"http_api.key_extend_on_access"},
        std::string_view{"http_api.loopback_only"}, std::string_view{"http_api.pam_login"},
        std::string_view{"http_api.allow_api_header"}, std::string_view{"webhook.enabled"},
        std::string_view{"webhook.tls_verify"}, std::string_view{"webhook.sift"},
        std::string_view{"webhook.api_override"},
        std::string_view{"webhook.task_debug"}, std::string_view{"webhook.task_debug_dump"},
        std::string_view{"default_write_payload"}, std::string_view{"log_console"},
        std::string_view{"tpool_log"}, std::string_view{"socks.async_dns"},
        std::string_view{"socks.ipver_mixing"}, std::string_view{"socks.prefer_ipv6"},
    };
    if (one_of(field, booleans)) return valid(boolean(value));
    struct IntegerRule { std::string_view path; std::int64_t minimum; std::int64_t maximum; };
    constexpr std::array integer_rules{
        IntegerRule{"plaintext_workers", -1, 4096}, IntegerRule{"ssl_workers", -1, 4096},
        IntegerRule{"udp_workers", -1, 4096}, IntegerRule{"dtls_workers", -1, 4096},
        IntegerRule{"quic_workers", -1, 4096}, IntegerRule{"socks_workers", -1, 4096},
        IntegerRule{"http_connect_workers", -1, 4096}, IntegerRule{"plaintext_port", 1024, 65535},
        IntegerRule{"ssl_port", 1024, 65535}, IntegerRule{"udp_port", 1024, 65535},
        IntegerRule{"dtls_port", 1024, 65535}, IntegerRule{"quic_port", 1, 65535},
        IntegerRule{"socks_port", 1024, 65535}, IntegerRule{"http_connect_port", 1024, 65535},
        IntegerRule{"write_pcap_single_quota", 0, 9007199254740991LL}, IntegerRule{"log_level", 0, 8},
        IntegerRule{"syslog_port", 0, 65535}, IntegerRule{"syslog_facility", 0, 32},
        IntegerRule{"syslog_level", 0, 8}, IntegerRule{"syslog_family", 4, 6},
        IntegerRule{"cli.port", 1024, 65535}, IntegerRule{"webhook.ping_interval", 0, 2147483647},
        IntegerRule{"webhook.nbr_update_interval", 0, 2147483647},
        IntegerRule{"webhook.nbr_tag_refresh_age", 0, 2147483647},
        IntegerRule{"http_api.key_timeout", 1, 4294967295LL}, IntegerRule{"http_api.port", 1024, 65535},
        IntegerRule{"tuning.host_bufsz_min", 1500, 10000000},
        IntegerRule{"tuning.host_bufsz_max_multiplier", 1, 1024000000},
        IntegerRule{"tuning.host_write_full", 1024, 1024000000},
        IntegerRule{"tuning.host_io_batch", 16384, 16777216},
        IntegerRule{"tuning.tls_write_chunk", 1024, 1048576},
        IntegerRule{"tuning.host_open_timeout", 0, 65535},
        IntegerRule{"tuning.host_idle_timeout", 0, 65535},
        IntegerRule{"tuning.nbr_cache_size", 1, 2147483647},
        IntegerRule{"webhook.sift_payload_limit_per_direction", 1, 1073741824},
    };
    const auto integer_rule = std::find_if(integer_rules.begin(), integer_rules.end(),
        [&](const IntegerRule& rule) { return rule.path == field; });
    if (integer_rule != integer_rules.end()) {
        if (field == "syslog_family") return valid(bounded_integer(value, 4, 4) || bounded_integer(value, 6, 6));
        return valid(bounded_integer(value, integer_rule->minimum, integer_rule->maximum));
    }
    if (field == "nameservers" || field == "http_api.allowed_ips") {
        const auto* items = strings(value);
        return valid(string_list(value) && items != nullptr && std::all_of(items->begin(), items->end(),
            [](const std::string& item) {
                return std::all_of(item.begin(), item.end(), [](const unsigned char character) {
                    return std::isalnum(character) != 0 || character == ':' || character == '.' ||
                           character == '_' || character == '-' || character == '/';
                });
            }));
    }
    if (field == "udp_quick_ports") {
        const auto* items = strings(value);
        if (items == nullptr || !string_list(value, 5U)) return Result::InvalidValue;
        return valid(std::all_of(items->begin(), items->end(), [](const std::string& item) {
            std::uint64_t port{};
            const auto [end, error] = std::from_chars(item.data(), item.data() + item.size(), port);
            return error == std::errc{} && end == item.data() + item.size() && port <= 65535U;
        }));
    }
    if (field == "http_api.keys") return valid(opaque_string_list(value, 65536U));
    constexpr std::array write_only{
        std::string_view{"webhook.url"}, std::string_view{"syslog_server"},
        std::string_view{"write_payload_dir"}, std::string_view{"log_file"},
        std::string_view{"sslkeylog_file"}, std::string_view{"certs_path"},
        std::string_view{"certs_ca_key_password"}, std::string_view{"certs_ctlog"},
        std::string_view{"ca_bundle_path"}, std::string_view{"ca_bundle_file"},
        std::string_view{"admin.group"}, std::string_view{"messages_dir"},
        std::string_view{"write_payload_file_prefix"}, std::string_view{"write_payload_file_suffix"},
        std::string_view{"cli.enable_password"}, std::string_view{"web_rating.wot_key"},
        std::string_view{"http_api.bind_address"}, std::string_view{"http_api.bind_interface"},
        std::string_view{"webhook.sift_url"}, std::string_view{"webhook.sift_tenant_id"},
        std::string_view{"webhook.sift_instance_id"}, std::string_view{"webhook.hostid"},
        std::string_view{"webhook.bind_interface"},
    };
    if (one_of(field, write_only)) return valid(bounded_text(value, 1024U, true));
    return Result::UnknownPath;
}

Result validate_capture(const std::string_view field, const DraftScalar& value) {
    if (field == "local.enabled" || field == "remote.enabled" || field == "options.calculate_checksums") {
        return valid(boolean(value));
    }
    if (field == "local.format") return valid(enumerated(value, {"pcap_single", "pcap", "smcap"}));
    if (field == "remote.tun_type") return valid(enumerated(value, {"gre"}));
    if (field == "remote.gre_format") return valid(enumerated(value, {"traffic", "pcapng"}));
    if (field == "local.pcap_quota") return valid(bounded_integer(value, 0, 9007199254740991LL));
    if (field == "remote.tun_ttl") return valid(bounded_integer(value, 0, 255));
    constexpr std::array write_only{
        std::string_view{"local.dir"}, std::string_view{"local.file_prefix"},
        std::string_view{"local.file_suffix"}, std::string_view{"remote.tun_dst"},
        std::string_view{"remote.bind_interface"},
    };
    if (one_of(field, write_only)) return valid(bounded_text(value, 1024U, true));
    return Result::UnknownPath;
}

Result validate_debug(const std::string_view field, const DraftScalar& value) {
    constexpr std::array globals{
        std::string_view{"log_data_crc"}, std::string_view{"log_sockets"},
        std::string_view{"log_online_cx_name"}, std::string_view{"log_srclines"},
        std::string_view{"log_srclines_always"},
    };
    if (one_of(field, globals)) return valid(boolean(value));
    if (!field.starts_with("log.") || field.size() <= 4U || field.find('.', 4U) != std::string_view::npos) {
        return Result::UnknownPath;
    }
    const auto module = field.substr(4U);
    if (!std::all_of(module.begin(), module.end(), [](const unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '_' || character == '-';
    })) return Result::UnknownPath;
    if (boolean(value)) return Result::Valid;
    if (integer(value) != nullptr) return valid(bounded_integer(value, -2147483648LL, 2147483647LL));
    return valid(bounded_text(value, 32U, true));
}

} // namespace

DraftSchemaResult validate_draft_schema(const DraftChange& change) {
    if (change.path.starts_with("settings.")) {
        return validate_settings(std::string_view(change.path).substr(9U), change.value);
    }
    if (change.path.starts_with("captures.")) {
        return validate_capture(std::string_view(change.path).substr(9U), change.value);
    }
    if (change.path.starts_with("debug.")) {
        return validate_debug(std::string_view(change.path).substr(6U), change.value);
    }
    return validate_indexed(change.path, change.value);
}

} // namespace smithproxy::gui
