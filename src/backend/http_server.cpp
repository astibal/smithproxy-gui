#include "http_server.hpp"

#include "draft_store.hpp"
#include "json.hpp"
#include "path.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <sstream>
#include <string_view>
#include <utility>

namespace smithproxy::gui {
namespace {

struct RequestState final : lmh::ConnectionState {
    explicit RequestState(lmh::Controller& controller) : ConnectionState(controller) {}
    bool body_too_large{};
};

struct Response {
    unsigned status{200};
    std::string content_type{"application/json; charset=utf-8"};
    std::string body;
    std::string cache_control{"no-store"};
};

constexpr std::size_t maximum_request_body = 64U * 1024U;

std::string mime_type(const std::filesystem::path& path) {
    const auto extension = path.extension().string();
    if (extension == ".html") return "text/html; charset=utf-8";
    if (extension == ".css") return "text/css; charset=utf-8";
    if (extension == ".js" || extension == ".mjs") return "text/javascript; charset=utf-8";
    if (extension == ".json" || extension == ".map") return "application/json; charset=utf-8";
    if (extension == ".svg") return "image/svg+xml";
    if (extension == ".png") return "image/png";
    if (extension == ".ico") return "image/x-icon";
    if (extension == ".woff2") return "font/woff2";
    return "application/octet-stream";
}

std::string timestamp_json(const std::chrono::system_clock::time_point value) {
    if (value.time_since_epoch().count() == 0) return "null";
    return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                              value.time_since_epoch()).count());
}

std::string optional_number_json(const std::optional<std::uint64_t> value) {
    return value ? std::to_string(*value) : "null";
}

std::string string_array_json(const std::vector<std::string>& values) {
    std::string result{"["};
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) result += ',';
        result += json_string(values[index]);
    }
    result += ']';
    return result;
}

bool constant_time_equal(const std::string_view left, const std::string_view right) {
    const auto size = std::max(left.size(), right.size());
    std::size_t difference = left.size() ^ right.size();
    for (std::size_t index = 0; index < size; ++index) {
        const auto left_byte = index < left.size() ? static_cast<unsigned char>(left[index]) : 0U;
        const auto right_byte = index < right.size() ? static_cast<unsigned char>(right[index]) : 0U;
        difference |= left_byte ^ right_byte;
    }
    return difference == 0U;
}

bool confined_to_root(const std::filesystem::path& root, const std::filesystem::path& candidate) {
    std::error_code error;
    const auto canonical_root = std::filesystem::weakly_canonical(root, error);
    if (error) return false;
    const auto canonical_candidate = std::filesystem::weakly_canonical(candidate, error);
    if (error) return false;
    auto root_part = canonical_root.begin();
    auto candidate_part = canonical_candidate.begin();
    for (; root_part != canonical_root.end(); ++root_part, ++candidate_part) {
        if (candidate_part == canonical_candidate.end() || *root_part != *candidate_part) return false;
    }
    return true;
}

class GuiController final : public lmh::Controller {
public:
    GuiController(const AppConfig& config, SmithproxyMonitor& monitor)
        : config_(config), monitor_(monitor), started_at_(std::chrono::steady_clock::now()),
          draft_("workspace-draft") {}

    bool validPath(const char*, const char*) override { return true; }
    lmh::ConnectionState* create_state() override { return new RequestState(*this); }

    int handleRequest(MHD_Connection* connection, const char* url, const char* method,
                      const char* upload_data, std::size_t* upload_data_size, void** ptr) override {
        if (*ptr == nullptr) {
            *ptr = create_state();
            return MHD_YES;
        }
        auto& state = *static_cast<RequestState*>(*ptr);
        if (*upload_data_size > 0U) {
            if (state.request_data.size() > maximum_request_body ||
                *upload_data_size > maximum_request_body - state.request_data.size()) {
                state.body_too_large = true;
            } else if (!state.body_too_large) {
                state.request_data.append(upload_data, *upload_data_size);
            }
            *upload_data_size = 0U;
            return MHD_YES;
        }
        if (state.response_sent) return MHD_YES;

        const bool head = std::string_view(method) == "HEAD";
        Response response;
        if (state.body_too_large) {
            response = {413, "application/json; charset=utf-8", "{\"error\":\"request body too large\"}"};
        } else if (std::string_view(method) == "POST") {
            response = route_mutation(connection, url, state.request_data);
        } else if (std::string_view(method) != "GET" && !head) {
            response = {405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}"};
        } else {
            response = route(connection, url);
        }
        return send(connection, state, std::move(response), head);
    }

private:
    bool same_origin_mutation(MHD_Connection* connection) const {
        const auto* origin = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin");
        const auto* host = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Host");
        const auto* csrf = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "X-Smithproxy-GUI-CSRF");
        const auto* fetch_site = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "Sec-Fetch-Site");
        const auto* content_type = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONTENT_TYPE);
        if (origin == nullptr || host == nullptr || csrf == nullptr || content_type == nullptr) return false;
        const std::string_view type{content_type};
        if (!type.starts_with("application/json") ||
            (type.size() > 16U && type[16U] != ';')) return false;
        if (!constant_time_equal(csrf, "1")) return false;
        if (fetch_site != nullptr && std::string_view(fetch_site) != "same-origin") return false;
        const std::string expected_http = "http://" + std::string(host);
        const std::string expected_https = "https://" + std::string(host);
        return constant_time_equal(origin, expected_http) || constant_time_equal(origin, expected_https);
    }

    Response route_mutation(MHD_Connection* connection, const std::string_view url,
                            const std::string_view body) {
        if (url == "/healthz") {
            return {405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}"};
        }
        const auto relative = path_below_base(url, config_.base_path);
        if (!relative) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"API endpoint not found\"}"};
        }
        if (*relative != "/api/v1/config/draft/changes" &&
            *relative != "/api/v1/config/draft/clear") {
            return relative->starts_with("/api/")
                ? Response{404, "application/json; charset=utf-8", "{\"error\":\"API endpoint not found\"}"}
                : Response{405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}"};
        }
        if (!gateway_authenticated(connection)) {
            return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
        }
        if (!same_origin_mutation(connection)) {
            return {403, "application/json; charset=utf-8", "{\"error\":\"same-origin CSRF check failed\"}"};
        }
        const auto document = nlohmann::json::parse(body, nullptr, false);
        if (*relative == "/api/v1/config/draft/clear") {
            if (document.is_discarded() || !document.is_object() || document.size() != 1U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft clear request\"}"};
            }
            const auto result = draft_.clear(document["expected_version"].get<std::uint64_t>());
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            return draft_snapshot();
        }
        if (document.is_discarded() || !document.is_object() ||
            !document.contains("expected_version") || !document["expected_version"].is_number_unsigned()) {
            return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
        }
        const auto parse_value = [](const nlohmann::json& raw) -> std::optional<DraftScalar> {
            if (raw.is_boolean()) return DraftScalar{raw.get<bool>()};
            if (raw.is_number_unsigned()) {
                const auto number = raw.get<std::uint64_t>();
                if (number > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                    return std::nullopt;
                }
                return DraftScalar{static_cast<std::int64_t>(number)};
            }
            if (raw.is_number_integer()) return DraftScalar{raw.get<std::int64_t>()};
            if (raw.is_number_float()) return DraftScalar{raw.get<double>()};
            if (raw.is_string()) return DraftScalar{raw.get<std::string>()};
            if (raw.is_array()) {
                std::vector<std::string> values;
                values.reserve(raw.size());
                for (const auto& item : raw) {
                    if (!item.is_string()) return std::nullopt;
                    values.push_back(item.get<std::string>());
                }
                return DraftScalar{std::move(values)};
            }
            return std::nullopt;
        };
        std::vector<DraftChange> changes;
        if (document.size() == 3U && document.contains("path") && document["path"].is_string() &&
            document.contains("value")) {
            auto value = parse_value(document["value"]);
            if (!value) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft value\"}"};
            }
            changes.push_back({document["path"].get<std::string>(), std::move(*value)});
        } else if (document.size() == 2U && document.contains("changes") &&
                   document["changes"].is_array() && document["changes"].size() <= 4096U) {
            for (const auto& item : document["changes"]) {
                if (!item.is_object() || item.size() != 2U || !item.contains("path") ||
                    !item["path"].is_string() || !item.contains("value")) {
                    return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
                }
                auto value = parse_value(item["value"]);
                if (!value) {
                    return {400, "application/json; charset=utf-8",
                            "{\"error\":\"invalid draft value\"}"};
                }
                changes.push_back({item["path"].get<std::string>(), std::move(*value)});
            }
        } else {
            return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
        }

        const auto result = draft_.upsert_many(
            document["expected_version"].get<std::uint64_t>(), std::move(changes));
        if (result == DraftMutationResult::VersionConflict) {
            return {409, "application/json; charset=utf-8", "{\"error\":\"draft version conflict\"}"};
        }
        if (result != DraftMutationResult::Applied) {
            return {400, "application/json; charset=utf-8", "{\"error\":\"draft change rejected\"}"};
        }
        return draft_snapshot();
    }

    Response route(MHD_Connection* connection, const std::string_view url) const {
        if (url == "/healthz") return health();
        const auto relative = path_below_base(url, config_.base_path);
        if (!relative) return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        if (*relative == "/healthz") return health();
        if (*relative == "/api/v1/status") return status();
        if (*relative == "/api/v1/metrics/summary") return metrics_summary();
        if (*relative == "/api/v1/tls/cache/summary") return tls_cache_summary();
        if (*relative == "/api/v1/network/neighbors/summary") return neighbor_summary();
        if (*relative == "/api/v1/sessions/activity") return session_activity();
        if (*relative == "/api/v1/events/recent") return recent_events();
        if (*relative == "/api/v1/capabilities") return capabilities(connection);
        if (*relative == "/api/v1/auth/session") return auth_session(connection);
        if (*relative == "/api/v1/config/draft") {
            if (!gateway_authenticated(connection)) {
                return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/snapshot") {
            if (!gateway_authenticated(connection)) {
                return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
            }
            return config_snapshot();
        }
        if (relative->starts_with("/api/")) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"API endpoint not found\"}"};
        }
        return static_asset(*relative);
    }

    Response health() const {
        const auto status = monitor_.status();
        return {200, "application/json; charset=utf-8",
                "{\"status\":\"ok\",\"smithproxy\":{\"state\":" + json_string(status.state) +
                    ",\"detail\":" + json_string(status.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(status.checked_at) + "}}"};
    }

    Response capabilities(MHD_Connection* connection) const {
        const auto status = monitor_.status();
        const bool config_read = monitor_.config_enabled() && gateway_authenticated(connection);
        return {200, "application/json; charset=utf-8",
                "{\"service\":\"smithproxy-gui\",\"api_version\":\"v1\",\"base_path\":" +
                    json_string(config_.base_path) + ",\"smithproxy_state\":" + json_string(status.state) +
                    ",\"features\":{\"config_read\":" + (config_read ? "true" : "false") +
                    ",\"config_write\":false,"
                    "\"drafts\":" + (config_read ? "true" : "false") +
                    ",\"jobs\":false,\"events\":true,\"smithproxy_events\":false,\"metrics\":true,"
                    "\"session_activity\":true,\"tls_monitoring\":true,"
                    "\"neighbor_monitoring\":true}}"};
    }

    bool gateway_authenticated(MHD_Connection* connection) const {
        if (!config_.gateway_secret) return false;
        const auto* supplied = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "X-Smithproxy-GUI-Gateway");
        return supplied != nullptr && constant_time_equal(supplied, *config_.gateway_secret);
    }

    Response auth_session(MHD_Connection* connection) const {
        const bool enabled = config_.gateway_secret.has_value();
        const bool authenticated = enabled && gateway_authenticated(connection);
        return {200, "application/json; charset=utf-8",
                "{\"mode\":" + json_string(enabled ? "gateway" : "disabled") +
                    ",\"authenticated\":" + (authenticated ? "true" : "false") + "}"};
    }

    Response draft_snapshot() const {
        const auto draft = draft_.snapshot();
        nlohmann::json document{
            {"id", draft.id},
            {"base_revision", draft.base_revision ? nlohmann::json(*draft.base_revision) : nlohmann::json(nullptr)},
            {"version", draft.version},
            {"changes", nlohmann::json::array()},
        };
        for (const auto& change : draft.changes) {
            auto value = std::visit([](const auto& item) { return nlohmann::json(item); }, change.value);
            document["changes"].push_back({{"path", change.path}, {"value", std::move(value)}});
        }
        return {200, "application/json; charset=utf-8", document.dump()};
    }

    Response config_snapshot() const {
        const auto snapshot = monitor_.status().config_snapshot;

        std::string policies{"["};
        for (std::size_t index = 0; index < snapshot.policies.size(); ++index) {
            if (index != 0U) policies += ',';
            const auto& policy = snapshot.policies[index];
            policies += "{\"id\":" + json_string(policy.id) +
                        ",\"name\":" + json_string(policy.name) +
                        ",\"enabled\":" + (policy.enabled ? "true" : "false") +
                        ",\"protocol\":" + json_string(policy.protocol) +
                        ",\"sources\":" + string_array_json(policy.sources) +
                        ",\"source_ports\":" + string_array_json(policy.source_ports) +
                        ",\"destinations\":" + string_array_json(policy.destinations) +
                        ",\"destination_ports\":" + string_array_json(policy.destination_ports) +
                        ",\"features\":" + string_array_json(policy.features) +
                        ",\"action\":" + json_string(policy.action) +
                        ",\"nat\":" + json_string(policy.nat) +
                        ",\"routing\":" + json_string(policy.routing) +
                        ",\"tls_profile\":" + json_string(policy.tls_profile) +
                        ",\"ssh_profile\":" + json_string(policy.ssh_profile) +
                        ",\"detection_profile\":" + json_string(policy.detection_profile) +
                        ",\"content_profile\":" + json_string(policy.content_profile) +
                        ",\"auth_profile\":" + json_string(policy.auth_profile) +
                        ",\"dns_profile\":" + json_string(policy.dns_profile) +
                        ",\"script_profile\":" + json_string(policy.script_profile) + "}";
        }
        policies += ']';

        std::string addresses{"["};
        for (std::size_t index = 0; index < snapshot.addresses.size(); ++index) {
            if (index != 0U) addresses += ',';
            const auto& address = snapshot.addresses[index];
            addresses += "{\"id\":" + json_string(address.id) +
                         ",\"name\":" + json_string(address.name) +
                         ",\"type\":" + json_string(address.type) +
                         ",\"value\":" + json_string(address.value) + "}";
        }
        addresses += ']';

        std::string ports{"["};
        for (std::size_t index = 0; index < snapshot.ports.size(); ++index) {
            if (index != 0U) ports += ',';
            const auto& port = snapshot.ports[index];
            ports += "{\"id\":" + json_string(port.id) +
                     ",\"name\":" + json_string(port.name) +
                     ",\"start\":" + std::to_string(port.start) +
                     ",\"end\":" + std::to_string(port.end) + "}";
        }
        ports += ']';

        std::string protocols{"["};
        for (std::size_t index = 0; index < snapshot.protocols.size(); ++index) {
            if (index != 0U) protocols += ',';
            const auto& protocol = snapshot.protocols[index];
            protocols += "{\"id\":" + json_string(protocol.id) +
                         ",\"name\":" + json_string(protocol.name) +
                         ",\"number\":" + std::to_string(protocol.number) + "}";
        }
        protocols += ']';

        std::string profiles{"["};
        for (std::size_t index = 0; index < snapshot.profiles.size(); ++index) {
            if (index != 0U) profiles += ',';
            const auto& profile = snapshot.profiles[index];
            profiles += "{\"id\":" + json_string(profile.id) +
                        ",\"name\":" + json_string(profile.name) +
                        ",\"type\":" + json_string(profile.type) + ",\"routing\":";
            if (!profile.routing) {
                profiles += "null";
            } else {
                profiles += "{\"destination_addresses\":" + string_array_json(profile.routing->destination_addresses) +
                            ",\"destination_ports\":" + string_array_json(profile.routing->destination_ports) +
                            ",\"load_balancing_method\":" + json_string(profile.routing->load_balancing_method) +
                            ",\"rewrite_sni\":" + json_string(profile.routing->rewrite_sni) +
                            ",\"rewrite_sni_to\":" + json_string(profile.routing->rewrite_sni_to) + "}";
            }
            profiles += ",\"tls\":";
            if (!profile.tls) {
                profiles += "null";
            } else {
                const auto& tls = *profile.tls;
                profiles += "{\"inspect\":" + std::string(tls.inspect ? "true" : "false") +
                            ",\"allow_untrusted_issuers\":" + (tls.allow_untrusted_issuers ? "true" : "false") +
                            ",\"allow_invalid_certificates\":" + (tls.allow_invalid_certificates ? "true" : "false") +
                            ",\"allow_self_signed\":" + (tls.allow_self_signed ? "true" : "false") +
                            ",\"certificate_transparency\":" + (tls.certificate_transparency ? "true" : "false") +
                            ",\"ocsp_stapling\":" + (tls.ocsp_stapling ? "true" : "false") +
                            ",\"block_alpn\":" + (tls.block_alpn ? "true" : "false") +
                            ",\"only_custom_certificates\":" + (tls.only_custom_certificates ? "true" : "false") +
                            ",\"no_fallback_bypass\":" + (tls.no_fallback_bypass ? "true" : "false") +
                            ",\"ssl_key_log\":" + (tls.ssl_key_log ? "true" : "false") +
                            ",\"client_hello_timeout_ms\":" + std::to_string(tls.client_hello_timeout_ms) +
                            ",\"handshake_timeout_ms\":" + std::to_string(tls.handshake_timeout_ms) +
                            ",\"sni_bypass_entries\":" + std::to_string(tls.sni_bypass_entries) +
                            ",\"client_certificate_action\":" + json_string(tls.client_certificate_action) +
                            ",\"alerts\":" + json_string(tls.alerts) + "}";
            }
            profiles += ",\"detection\":";
            if (!profile.detection) {
                profiles += "null";
            } else {
                const auto& detection = *profile.detection;
                profiles += "{\"mode\":" + std::to_string(detection.mode) +
                            ",\"engines_enabled\":" + (detection.engines_enabled ? "true" : "false") +
                            ",\"knowledge_base_enabled\":" +
                            (detection.knowledge_base_enabled ? "true" : "false") + "}";
            }
            profiles += ",\"content\":";
            if (!profile.content) {
                profiles += "null";
            } else {
                const auto& content = *profile.content;
                profiles += "{\"write_payload\":" + std::string(content.write_payload ? "true" : "false") +
                            ",\"write_format\":" + json_string(content.write_format) +
                            ",\"webhook_enabled\":" + (content.webhook_enabled ? "true" : "false") +
                            ",\"webhook_locks_traffic\":" +
                            (content.webhook_locks_traffic ? "true" : "false") +
                            ",\"ja4_tls_client_hello\":" +
                            (content.ja4_tls_client_hello ? "true" : "false") +
                            ",\"ja4_tls_client_hello_ignores_sni\":" +
                            (content.ja4_tls_client_hello_ignores_sni ? "true" : "false") +
                            ",\"ja4_tls_server_hello\":" +
                            (content.ja4_tls_server_hello ? "true" : "false") +
                            ",\"ja4_http\":" + (content.ja4_http ? "true" : "false") +
                            ",\"session_filter_configured\":" +
                            (content.session_filter_configured ? "true" : "false") +
                            ",\"rule_count\":" + std::to_string(content.rule_count) + "}";
            }
            profiles += ",\"ssh\":";
            if (!profile.ssh) {
                profiles += "null";
            } else {
                const auto& ssh = *profile.ssh;
                profiles += "{\"host_key_configured\":true,\"host_key_policy\":" +
                            json_string(ssh.host_key_policy) +
                            ",\"shell\":" + (ssh.shell ? "true" : "false") +
                            ",\"exec\":" + (ssh.exec ? "true" : "false") +
                            ",\"subsystem\":" + (ssh.subsystem ? "true" : "false") +
                            ",\"pty\":" + (ssh.pty ? "true" : "false") +
                            ",\"environment\":" + (ssh.environment ? "true" : "false") +
                            ",\"local_forward\":" + (ssh.local_forward ? "true" : "false") +
                            ",\"remote_forward\":" + (ssh.remote_forward ? "true" : "false") +
                            ",\"x11\":" + (ssh.x11 ? "true" : "false") +
                            ",\"agent\":" + (ssh.agent ? "true" : "false") + "}";
            }
            profiles += ",\"dns\":";
            if (!profile.dns) {
                profiles += "null";
            } else {
                const auto& dns = *profile.dns;
                profiles += "{\"match_request_id\":" +
                            std::string(dns.match_request_id ? "true" : "false") +
                            ",\"randomize_id\":" + (dns.randomize_id ? "true" : "false") +
                            ",\"cached_responses\":" + (dns.cached_responses ? "true" : "false") + "}";
            }
            profiles += ",\"script\":";
            if (!profile.script) {
                profiles += "null";
            } else {
                profiles += "{\"runtime\":" + json_string(profile.script->runtime) +
                            ",\"module_path_configured\":" +
                            (profile.script->module_path_configured ? "true" : "false") + "}";
            }
            profiles += ",\"authentication\":";
            if (!profile.authentication) {
                profiles += "null";
            } else {
                const auto& authentication = *profile.authentication;
                profiles += "{\"authenticate\":" +
                            std::string(authentication.authenticate ? "true" : "false") +
                            ",\"resolve\":" + (authentication.resolve ? "true" : "false") +
                            ",\"identity_count\":" + std::to_string(authentication.identity_count) +
                            ",\"deprecated\":true}";
            }
            profiles += '}';
        }
        profiles += ']';

        std::string settings{"null"};
        if (snapshot.settings) {
            const auto& value = *snapshot.settings;
            settings = "{\"accept_tproxy\":" + std::string(value.accept_tproxy ? "true" : "false") +
                       ",\"accept_redirect\":" + (value.accept_redirect ? "true" : "false") +
                       ",\"accept_socks\":" + (value.accept_socks ? "true" : "false") +
                       ",\"accept_http_connect\":" + (value.accept_http_connect ? "true" : "false") +
                       ",\"accept_api\":" + (value.accept_api ? "true" : "false") +
                       ",\"policy_fail_open\":" + (value.policy_fail_open ? "true" : "false") +
                       ",\"access_request_fail_open\":" +
                       (value.access_request_fail_open ? "true" : "false") +
                       ",\"workers\":{\"plaintext\":" + std::to_string(value.plaintext_workers) +
                       ",\"tls\":" + std::to_string(value.tls_workers) +
                       ",\"udp\":" + std::to_string(value.udp_workers) +
                       ",\"dtls\":" + std::to_string(value.dtls_workers) +
                       ",\"quic\":" + std::to_string(value.quic_workers) +
                       ",\"socks\":" + std::to_string(value.socks_workers) +
                       ",\"http_connect\":" + std::to_string(value.http_connect_workers) + "}" +
                       ",\"ports\":{\"plaintext\":" + std::to_string(value.plaintext_port) +
                       ",\"tls\":" + std::to_string(value.tls_port) +
                       ",\"udp\":" + std::to_string(value.udp_port) +
                       ",\"quic\":" + std::to_string(value.quic_port) +
                       ",\"http_connect\":" + std::to_string(value.http_connect_port) + "}" +
                       ",\"ocsp_status_ttl\":" + std::to_string(value.ocsp_status_ttl) +
                       ",\"crl_status_ttl\":" + std::to_string(value.crl_status_ttl) +
                       ",\"logging\":{\"default_write_payload\":" +
                       (value.default_write_payload ? "true" : "false") +
                       ",\"payload_directory_configured\":" +
                       (value.payload_directory_configured ? "true" : "false") +
                       ",\"pcap_single_quota\":" + std::to_string(value.write_pcap_single_quota) +
                       ",\"level\":" + std::to_string(value.log_level) +
                       ",\"file_configured\":" + (value.log_file_configured ? "true" : "false") +
                       ",\"console\":" + (value.log_console ? "true" : "false") +
                       ",\"ssl_key_file_configured\":" +
                       (value.ssl_key_log_file_configured ? "true" : "false") +
                       ",\"syslog_server_configured\":" +
                       (value.syslog_server_configured ? "true" : "false") +
                       ",\"syslog_port\":" + std::to_string(value.syslog_port) +
                       ",\"syslog_facility\":" + std::to_string(value.syslog_facility) +
                       ",\"syslog_level\":" + std::to_string(value.syslog_level) +
                       ",\"syslog_family\":" + std::to_string(value.syslog_family) + "}" +
                       ",\"auxiliary\":{\"udp_quick_port_count\":" +
                       std::to_string(value.udp_quick_port_count) +
                       ",\"udp_quick_ports\":" + string_array_json(value.udp_quick_ports) +
                       ",\"certificates_path_configured\":" +
                       (value.certificates_path_configured ? "true" : "false") +
                       ",\"certificate_password_configured\":" +
                       (value.certificate_password_configured ? "true" : "false") +
                       ",\"ca_bundle_path_configured\":" +
                       (value.ca_bundle_path_configured ? "true" : "false") +
                       ",\"messages_directory_configured\":" +
                       (value.messages_directory_configured ? "true" : "false") +
                       ",\"payload_file_prefix_configured\":" +
                       (value.payload_file_prefix_configured ? "true" : "false") +
                       ",\"payload_file_suffix_configured\":" +
                       (value.payload_file_suffix_configured ? "true" : "false") +
                       ",\"cli_port\":" + std::to_string(value.cli_port) +
                       ",\"cli_password_configured\":" +
                       (value.cli_password_configured ? "true" : "false") +
                       ",\"web_rating_key_configured\":" +
                       (value.web_rating_key_configured ? "true" : "false") +
                       ",\"socks_async_dns\":" + (value.socks_async_dns ? "true" : "false") + "}" +
                       ",\"tls_autodetect\":" + (value.tls_autodetect ? "true" : "false") +
                       ",\"tls_autodetect_harder\":" + (value.tls_autodetect_harder ? "true" : "false") +
                       ",\"kernel_tls\":" + (value.kernel_tls ? "true" : "false") +
                       ",\"nameserver_count\":" + std::to_string(value.nameserver_count) +
                       ",\"nameservers\":" + string_array_json(value.nameservers) +
                       ",\"http_api\":{\"key_count\":" + std::to_string(value.api_key_count) +
                       ",\"allowed_ip_count\":" + std::to_string(value.api_allowed_ip_count) +
                       ",\"loopback_only\":" + (value.api_loopback_only ? "true" : "false") +
                       ",\"pam_login\":" + (value.api_pam_login ? "true" : "false") +
                       ",\"allow_api_header\":" + (value.api_header_allowed ? "true" : "false") + "}" +
                       ",\"webhook\":{\"enabled\":" + (value.webhook_enabled ? "true" : "false") +
                       ",\"tls_verify\":" + (value.webhook_tls_verify ? "true" : "false") +
                       ",\"url_configured\":" + (value.webhook_url_configured ? "true" : "false") +
                       ",\"sift_enabled\":" + (value.webhook_sift_enabled ? "true" : "false") +
                       ",\"api_override\":" + (value.webhook_api_override ? "true" : "false") + "}}";
        }
        std::string captures{"null"};
        std::string debug{"null"};
        if (snapshot.debug) {
            const auto& value = *snapshot.debug;
            debug = "{\"log_data_crc\":" + std::string(value.log_data_crc ? "true" : "false") +
                    ",\"log_sockets\":" + (value.log_sockets ? "true" : "false") +
                    ",\"log_online_cx_name\":" +
                    (value.log_online_connection_name ? "true" : "false") +
                    ",\"log_srclines\":" + (value.log_source_lines ? "true" : "false") +
                    ",\"log_srclines_always\":" +
                    (value.log_source_lines_always ? "true" : "false") +
                    ",\"module_override_count\":" +
                    std::to_string(value.module_override_count) + "}";
        }
        if (snapshot.captures) {
            const auto& value = *snapshot.captures;
            captures = "{\"local\":{\"enabled\":" + std::string(value.local_enabled ? "true" : "false") +
                       ",\"directory_configured\":" +
                       (value.local_directory_configured ? "true" : "false") +
                       ",\"format\":" + json_string(value.local_format) +
                       ",\"quota_mib\":" + std::to_string(value.local_quota_mib) + "}" +
                       ",\"remote\":{\"enabled\":" + (value.remote_enabled ? "true" : "false") +
                       ",\"tunnel_type\":" + json_string(value.remote_tunnel_type) +
                       ",\"gre_format\":" + json_string(value.remote_gre_format) +
                       ",\"destination_configured\":" +
                       (value.remote_destination_configured ? "true" : "false") +
                       ",\"ttl\":" + std::to_string(value.remote_ttl) +
                       ",\"bind_interface_configured\":" +
                       (value.remote_bind_interface_configured ? "true" : "false") + "}" +
                       ",\"calculate_checksums\":" + (value.calculate_checksums ? "true" : "false") + "}";
        }
        std::string security_assets{"null"};
        if (snapshot.security_assets) {
            const auto& value = *snapshot.security_assets;
            security_assets = "{\"certificate_authority_count\":" +
                              std::to_string(value.certificate_authority_count) +
                              ",\"certificate_authority_path_count\":" +
                              std::to_string(value.certificate_authority_path_count) +
                              ",\"starttls_signature_count\":" +
                              std::to_string(value.starttls_signature_count) +
                              ",\"starttls_flow_step_count\":" +
                              std::to_string(value.starttls_flow_step_count) +
                              ",\"detection_signature_count\":" +
                              std::to_string(value.detection_signature_count) +
                              ",\"detection_flow_step_count\":" +
                              std::to_string(value.detection_flow_step_count) + "}";
        }

        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(snapshot.state) +
                    ",\"detail\":" + json_string(snapshot.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(snapshot.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(snapshot.last_success_at) +
                    ",\"view\":\"runtime\",\"revision\":null,\"policies\":" + policies +
                    ",\"addresses\":" + addresses + ",\"ports\":" + ports +
                    ",\"protocols\":" + protocols + ",\"profiles\":" + profiles +
                    ",\"settings\":" + settings + ",\"debug\":" + debug +
                    ",\"captures\":" + captures +
                    ",\"security_assets\":" + security_assets +
                    ",\"augment_support\":false,\"value_origins\":[]}"};
    }

    Response status() const {
        const auto status = monitor_.status();
        const auto uptime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started_at_).count();
        const auto successful = std::count_if(status.history.begin(), status.history.end(),
                                              [](const ProbeSample& sample) { return sample.state == "ready"; });

        std::string history = "[";
        for (std::size_t index = 0; index < status.history.size(); ++index) {
            if (index != 0U) history += ',';
            const auto& sample = status.history[index];
            history += "{\"state\":" + json_string(sample.state) +
                       ",\"checked_at_unix_ms\":" + timestamp_json(sample.checked_at) +
                       ",\"latency_ms\":" + optional_number_json(sample.latency_ms) + "}";
        }
        history += ']';

        return {200, "application/json; charset=utf-8",
                "{\"service\":\"smithproxy-gui\",\"uptime_ms\":" + std::to_string(uptime_ms) +
                    ",\"smithproxy\":{\"configured\":" + (monitor_.configured() ? "true" : "false") +
                    ",\"state\":" + json_string(status.state) +
                    ",\"detail\":" + json_string(status.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(status.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(status.last_success_at) +
                    ",\"latency_ms\":" + optional_number_json(status.latency_ms) +
                    ",\"total_probes\":" + std::to_string(status.total_probes) +
                    ",\"consecutive_failures\":" + std::to_string(status.consecutive_failures) +
                    ",\"availability_window\":{\"samples\":" + std::to_string(status.history.size()) +
                    ",\"successful\":" + std::to_string(successful) + "},\"history\":" + history + "}}"};
    }

    Response recent_events() const {
        const auto status = monitor_.status();
        std::string events{"["};
        std::string previous_state;
        std::size_t emitted{};
        for (std::size_t index = 0; index < status.history.size(); ++index) {
            const auto& sample = status.history[index];
            if (sample.state == previous_state) continue;
            previous_state = sample.state;
            if (emitted++ != 0U) events += ',';
            const auto severity = sample.state == "ready" ? "info" :
                                  sample.state == "starting" ? "notice" : "error";
            const auto message = sample.state == "ready" ? "Smithproxy control plane is reachable" :
                                 sample.state == "starting" ? "Smithproxy probe is starting" :
                                 "Smithproxy control plane changed to " + sample.state;
            events += "{\"id\":" + json_string(std::to_string(index) + "-" +
                          timestamp_json(sample.checked_at)) +
                      ",\"occurred_at_unix_ms\":" + timestamp_json(sample.checked_at) +
                      ",\"severity\":" + json_string(severity) +
                      ",\"source\":\"gui-core\",\"message\":" + json_string(message) + "}";
        }
        events += ']';
        return {200, "application/json; charset=utf-8",
                "{\"source\":\"gui-core\",\"smithproxy_events_available\":false,\"events\":" +
                    events + "}"};
    }

    Response metrics_summary() const {
        const auto metrics = monitor_.status().runtime_metrics;
        std::string listeners = "[";
        for (std::size_t index = 0; index < metrics.listeners.size(); ++index) {
            if (index != 0U) listeners += ',';
            const auto& listener = metrics.listeners[index];
            listeners += "{\"name\":" + json_string(listener.name) +
                         ",\"workers\":" + std::to_string(listener.workers) +
                         ",\"sessions_total\":" + std::to_string(listener.sessions_total) +
                         ",\"sessions_active\":" + std::to_string(listener.sessions_active) +
                         ",\"bytes_up\":" + std::to_string(listener.bytes_up) +
                         ",\"bytes_down\":" + std::to_string(listener.bytes_down) + "}";
        }
        listeners += ']';
        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(metrics.state) +
                    ",\"detail\":" + json_string(metrics.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(metrics.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(metrics.last_success_at) +
                    ",\"totals\":{\"workers\":" + std::to_string(metrics.workers) +
                    ",\"sessions_total\":" + std::to_string(metrics.sessions_total) +
                    ",\"sessions_active\":" + std::to_string(metrics.sessions_active) +
                    ",\"bytes_up\":" + std::to_string(metrics.bytes_up) +
                    ",\"bytes_down\":" + std::to_string(metrics.bytes_down) +
                    "},\"listeners\":" + listeners + "}"};
    }

    Response tls_cache_summary() const {
        const auto metrics = monitor_.status().tls_cache_metrics;
        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(metrics.state) +
                    ",\"detail\":" + json_string(metrics.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(metrics.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(metrics.last_success_at) +
                    ",\"size\":" + std::to_string(metrics.size) +
                    ",\"capacity\":" + std::to_string(metrics.capacity) + "}"};
    }

    Response neighbor_summary() const {
        const auto metrics = monitor_.status().neighbor_metrics;
        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(metrics.state) +
                    ",\"detail\":" + json_string(metrics.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(metrics.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(metrics.last_success_at) +
                    ",\"hosts_total\":" + std::to_string(metrics.hosts_total) +
                    ",\"active_today\":" + std::to_string(metrics.active_today) +
                    ",\"active_week\":" + std::to_string(metrics.active_week) +
                    ",\"tagged_hosts\":" + std::to_string(metrics.tagged_hosts) +
                    ",\"observations\":" + std::to_string(metrics.observations) +
                    ",\"bytes_up\":" + std::to_string(metrics.bytes_up) +
                    ",\"bytes_down\":" + std::to_string(metrics.bytes_down) + "}"};
    }

    Response session_activity() const {
        const auto snapshot = monitor_.status().live_sessions;
        std::string protocols = "[";
        for (std::size_t index = 0; index < snapshot.protocols.size(); ++index) {
            if (index != 0U) protocols += ',';
            const auto& protocol = snapshot.protocols[index];
            protocols += "{\"protocol\":" + json_string(protocol.protocol) +
                         ",\"sessions\":" + std::to_string(protocol.sessions) +
                         ",\"speed_up\":" + std::to_string(protocol.speed_up) +
                         ",\"speed_down\":" + std::to_string(protocol.speed_down) +
                         ",\"bytes_up\":" + std::to_string(protocol.bytes_up) +
                         ",\"bytes_down\":" + std::to_string(protocol.bytes_down) + "}";
        }
        protocols += ']';
        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(snapshot.state) +
                    ",\"detail\":" + json_string(snapshot.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(snapshot.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(snapshot.last_success_at) +
                    ",\"total\":" + std::to_string(snapshot.total) +
                    ",\"speed_up\":" + std::to_string(snapshot.speed_up) +
                    ",\"speed_down\":" + std::to_string(snapshot.speed_down) +
                    ",\"protocols\":" + protocols + "}"};
    }

    Response static_asset(const std::string_view relative) const {
        auto path = safe_asset_path(config_.asset_root, relative);
        if (!path) return {400, "application/json; charset=utf-8", "{\"error\":\"invalid path\"}"};

        std::error_code error;
        if (!std::filesystem::is_regular_file(*path, error) || error) {
            const bool route_candidate = std::filesystem::path(*path).extension().empty();
            if (!route_candidate) return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
            path = config_.asset_root / "index.html";
        }
        if (!confined_to_root(config_.asset_root, *path)) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        }
        const auto size = std::filesystem::file_size(*path, error);
        if (error || size > 16U * 1024U * 1024U) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        }
        std::ifstream input(*path, std::ios::binary);
        if (!input) return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        std::ostringstream content;
        content << input.rdbuf();
        const bool entrypoint = path->filename() == "index.html";
        return {200, mime_type(*path), content.str(),
                entrypoint ? "no-cache" : "public, max-age=31536000, immutable"};
    }

    static int send(MHD_Connection* connection, RequestState& state, Response response, const bool head) {
        auto* output = MHD_create_response_from_buffer(
            head ? 0U : response.body.size(), head ? nullptr : response.body.data(), MHD_RESPMEM_MUST_COPY);
        if (output == nullptr) return MHD_NO;
        MHD_add_response_header(output, MHD_HTTP_HEADER_CONTENT_TYPE, response.content_type.c_str());
        MHD_add_response_header(output, MHD_HTTP_HEADER_CACHE_CONTROL, response.cache_control.c_str());
        MHD_add_response_header(output, "X-Content-Type-Options", "nosniff");
        MHD_add_response_header(output, "Referrer-Policy", "no-referrer");
        MHD_add_response_header(output, "X-Frame-Options", "SAMEORIGIN");
        MHD_add_response_header(output, "Cross-Origin-Resource-Policy", "same-origin");
        MHD_add_response_header(output, "X-Permitted-Cross-Domain-Policies", "none");
        MHD_add_response_header(output, "Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()");
        MHD_add_response_header(output, "Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                                "worker-src 'self'; manifest-src 'self'; object-src 'none'; "
                                "base-uri 'none'; form-action 'self'; frame-ancestors 'self'");
        const auto queued = MHD_queue_response(connection, response.status, output);
        MHD_destroy_response(output);
        if (queued == MHD_YES) state.response_sent = true;
        return queued;
    }

    const AppConfig& config_;
    SmithproxyMonitor& monitor_;
    const std::chrono::steady_clock::time_point started_at_;
    DraftStore draft_;
};

} // namespace

int run_http_server(const AppConfig& config, SmithproxyMonitor& monitor, std::atomic_bool& stop_requested) {
    lmh::WebServer server(config.port);
    server.options().bind_address = config.bind_address;
    server.options().thread_pool_size = 8;
    server.options().configure_listen_socket = [](const int socket) {
        int enabled = 1;
        return ::setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0;
    };
    server.options().handler_should_terminate = [&stop_requested] { return stop_requested.load(); };
    server.addController(std::make_shared<GuiController>(config, monitor));
    return server.start() ? 0 : 1;
}

} // namespace smithproxy::gui
