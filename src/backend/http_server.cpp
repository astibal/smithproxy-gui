#include "http_server.hpp"

#include "audit_store.hpp"
#include "commit_coordinator.hpp"
#include "draft_operation.hpp"
#include "draft_operation_json.hpp"
#include "draft_store.hpp"
#include "job_store.hpp"
#include "json.hpp"
#include "operational_alerts.hpp"
#include "operational_event_store.hpp"
#include "path.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>
#include <nlohmann/json.hpp>

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string_view>
#include <type_traits>
#include <utility>

namespace smithproxy::gui {
namespace {

struct RequestState final : lmh::ConnectionState {
    RequestState(lmh::Controller& controller, std::string id)
        : ConnectionState(controller), request_id(std::move(id)) {}
    const std::string request_id;
    bool body_too_large{};
};

struct Response {
    Response(unsigned response_status = 200,
             std::string response_content_type = "application/json; charset=utf-8",
             std::string response_body = {}, std::string response_cache_control = "no-store",
             std::vector<std::pair<std::string, std::string>> response_headers = {})
        : status(response_status), content_type(std::move(response_content_type)),
          body(std::move(response_body)), cache_control(std::move(response_cache_control)),
          headers(std::move(response_headers)) {}

    unsigned status{200};
    std::string content_type{"application/json; charset=utf-8"};
    std::string body;
    std::string cache_control{"no-store"};
    std::vector<std::pair<std::string, std::string>> headers;
};

constexpr std::size_t maximum_request_body = 128U * 1024U;

std::string request_id_prefix() {
    std::random_device source;
    const auto random = (static_cast<std::uint64_t>(source()) << 32U) | source();
    std::ostringstream output;
    output << std::hex << random;
    return output.str();
}

std::string error_code(const std::string_view message) {
    if (message == "authentication required") return "auth.required";
    if (message == "same-origin CSRF check failed") return "auth.csrf_failed";
    if (message == "request body too large") return "request.body_too_large";
    if (message == "method not allowed") return "request.method_not_allowed";
    if (message == "invalid request host") return "request.invalid_host";
    if (message == "not found" || message == "API endpoint not found") return "request.not_found";
    if (message == "invalid path") return "request.invalid_path";
    if (message == "invalid event cursor") return "events.invalid_cursor";
    if (message == "draft version conflict") return "draft.version_conflict";
    if (message == "draft change not found") return "draft.change_not_found";
    if (message == "transaction revision conflict") return "config.revision_conflict";
    if (message == "transaction validation unavailable") return "config.validation_unavailable";
    if (message == "transaction validation rejected") return "config.validation_rejected";
    if (message == "transaction validation failed") return "config.validation_failed";
    if (message == "transaction commit in progress") return "config.commit_in_progress";
    if (message == "transaction commit unavailable") return "config.commit_unavailable";
    if (message == "transaction commit rejected") return "config.commit_rejected";
    if (message == "transaction commit failed") return "config.commit_failed";
    if (message == "transaction commit authorization failed") {
        return "config.commit_authorization_failed";
    }
    if (message == "structural draft unavailable") return "config.structural_unavailable";
    if (message == "draft change rejected") return "draft.change_rejected";
    if (message.starts_with("invalid draft") || message.starts_with("invalid structural draft")) {
        return "draft.invalid_request";
    }
    return "request.failed";
}

bool safe_audit_target(const std::string_view path) {
    if (path.empty() || path.size() > 512U) return false;
    return std::all_of(path.begin(), path.end(), [](const unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '_' || character == '-' ||
               character == '.' || character == '[' || character == ']';
    });
}

struct MutationAuditMetadata {
    std::string operation{"api.mutation"};
    std::size_t target_count{};
    std::vector<std::string> targets;
    bool targets_truncated{};
};

MutationAuditMetadata mutation_audit_metadata(
    const std::string_view relative, const std::string_view body) {
    MutationAuditMetadata metadata;
    if (relative == "/api/v1/config/draft/changes") metadata.operation = "config.draft.upsert";
    else if (relative == "/api/v1/config/draft/changes/remove") {
        metadata.operation = "config.draft.remove";
    }
    else if (relative == "/api/v1/config/draft/clear") metadata.operation = "config.draft.clear";
    else if (relative == "/api/v1/config/draft/operations") {
        metadata.operation = "config.draft.operation.upsert";
    }
    else if (relative == "/api/v1/config/draft/operations/batch") {
        metadata.operation = "config.draft.operation.batch";
    }
    else if (relative == "/api/v1/config/draft/operations/remove") {
        metadata.operation = "config.draft.operation.remove";
    }
    else if (relative == "/api/v1/config/draft/validate") metadata.operation = "config.draft.validate";
    else if (relative == "/api/v1/config/draft/commit") metadata.operation = "config.draft.commit";
    else return metadata;

    const auto document = nlohmann::json::parse(body, nullptr, false);
    if (!document.is_object() || metadata.operation == "config.draft.clear") return metadata;
    if (metadata.operation == "config.draft.upsert" && document.contains("remove_paths")) {
        metadata.operation = "config.draft.reconcile";
    }
    const auto append_target = [&](const nlohmann::json& raw) {
        ++metadata.target_count;
        if (!raw.is_string()) {
            metadata.targets_truncated = true;
            return;
        }
        const auto path = raw.get<std::string>();
        if (!safe_audit_target(path) || metadata.targets.size() >= 32U) {
            metadata.targets_truncated = true;
            return;
        }
        metadata.targets.push_back(path);
    };
    if (metadata.operation == "config.draft.operation.batch" &&
        document.contains("operations") && document["operations"].is_array()) {
        for (const auto& operation : document["operations"]) {
            if (operation.is_object() && operation.contains("local_id")) {
                append_target(operation["local_id"]);
            } else {
                ++metadata.target_count;
                metadata.targets_truncated = true;
            }
        }
    } else if (metadata.operation == "config.draft.operation.upsert" &&
        document.contains("operation") && document["operation"].is_object() &&
        document["operation"].contains("local_id")) {
        append_target(document["operation"]["local_id"]);
    } else if (metadata.operation == "config.draft.operation.remove" &&
               document.contains("local_id")) {
        append_target(document["local_id"]);
    } else if (document.contains("path")) {
        append_target(document["path"]);
    } else if (document.contains("paths") && document["paths"].is_array()) {
        for (const auto& path : document["paths"]) append_target(path);
    } else if (document.contains("changes") && document["changes"].is_array()) {
        for (const auto& change : document["changes"]) {
            if (change.is_object() && change.contains("path")) append_target(change["path"]);
            else {
                ++metadata.target_count;
                metadata.targets_truncated = true;
            }
        }
        if (document.contains("remove_paths") && document["remove_paths"].is_array()) {
            for (const auto& path : document["remove_paths"]) append_target(path);
        }
    }
    return metadata;
}

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

bool valid_job_id(const std::string_view value) {
    if (value.size() != 40U || !value.starts_with("job-")) return false;
    for (std::size_t index = 4U; index < value.size(); ++index) {
        const auto uuid_index = index - 4U;
        const bool separator = uuid_index == 8U || uuid_index == 13U ||
                               uuid_index == 18U || uuid_index == 23U;
        const auto character = value[index];
        const bool lowercase_hex = (character >= '0' && character <= '9') ||
                                   (character >= 'a' && character <= 'f');
        if (separator ? character != '-' : !lowercase_hex) {
            return false;
        }
    }
    return true;
}

nlohmann::json job_json(const JobRecord& record) {
    return {
        {"id", record.id},
        {"type", record.type},
        {"state", record.state},
        {"phase", record.phase},
        {"progress_percent", record.progress_percent},
        {"cancelable", record.cancelable},
        {"created_at_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
            record.created_at.time_since_epoch()).count()},
        {"updated_at_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
            record.updated_at.time_since_epoch()).count()},
        {"deadline_at_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
            record.deadline_at.time_since_epoch()).count()},
        {"owner", nullptr},
        {"result", record.result ? nlohmann::json(*record.result) : nlohmann::json(nullptr)},
    };
}

std::string operational_event_json(const OperationalEventRecord& event) {
    return "{\"id\":" + json_string(event.id) +
           ",\"source_revision\":" + std::to_string(event.source_revision) +
           ",\"occurred_at_unix_ms\":" + timestamp_json(event.occurred_at) +
           ",\"category\":" + json_string(event.category) +
           ",\"code\":" + json_string(event.code) +
           ",\"severity\":" + json_string(event.severity) +
           ",\"source\":\"gui-core\",\"message\":" + json_string(event.message) + "}";
}

std::string operational_snapshot_json(const std::vector<OperationalEventRecord>& records) {
    std::string events{"["};
    for (std::size_t index = 0; index < records.size(); ++index) {
        if (index != 0U) events += ',';
        events += operational_event_json(records[index]);
    }
    events += ']';
    return "{\"source\":\"gui-core\",\"smithproxy_events_available\":false,\"events\":" +
           events + "}";
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

std::string number_array_json(const std::vector<std::uint64_t>& values) {
    std::string result{"["};
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0U) result += ',';
        result += std::to_string(values[index]);
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

bool valid_authority_port(const std::string_view suffix) {
    if (suffix.empty()) return true;
    if (!suffix.starts_with(':') || suffix.size() == 1U) return false;
    unsigned port{};
    const auto value = suffix.substr(1U);
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    return error == std::errc{} && end == value.data() + value.size() && port > 0U && port <= 65535U;
}

bool loopback_authority(const std::string_view authority) {
    if (authority.empty() || authority.size() > 255U ||
        authority.find_first_of(" \t\r\n/@?#\\") != std::string_view::npos) {
        return false;
    }
    if (authority.starts_with('[')) {
        const auto closing = authority.find(']');
        return closing != std::string_view::npos && authority.substr(0U, closing + 1U) == "[::1]" &&
               valid_authority_port(authority.substr(closing + 1U));
    }
    const auto separator = authority.find(':');
    if (separator != std::string_view::npos && authority.find(':', separator + 1U) != std::string_view::npos) {
        return false;
    }
    const auto host = authority.substr(0U, separator);
    const auto port = separator == std::string_view::npos ? std::string_view{} : authority.substr(separator);
    if (!valid_authority_port(port)) return false;
    std::string normalized(host);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](const unsigned char character) {
        return character >= 'A' && character <= 'Z' ? static_cast<char>(character + ('a' - 'A')) :
                                                      static_cast<char>(character);
    });
    if (normalized == "localhost" || normalized == "localhost.") return true;
    in_addr parsed{};
    return ::inet_pton(AF_INET, normalized.c_str(), &parsed) == 1 &&
           (ntohl(parsed.s_addr) & 0xff000000U) == 0x7f000000U;
}

bool sensitive_draft_path(const std::string_view path) {
    constexpr std::array sensitive_paths{
        "settings.webhook.url", "settings.syslog_server", "settings.write_payload_dir",
        "settings.log_file", "settings.sslkeylog_file", "settings.certs_path",
        "settings.certs_ca_key_password", "settings.certs_ctlog", "settings.ca_bundle_path",
        "settings.ca_bundle_file", "settings.admin.group", "settings.messages_dir",
        "settings.write_payload_file_prefix", "settings.write_payload_file_suffix",
        "settings.cli.enable_password", "settings.web_rating.wot_key", "settings.http_api.keys",
        "settings.http_api.bind_address", "settings.http_api.bind_interface",
        "settings.webhook.sift_url", "settings.webhook.sift_tenant_id",
        "settings.webhook.sift_instance_id", "settings.webhook.hostid",
        "settings.webhook.bind_interface",
        "captures.local.dir", "captures.local.file_prefix", "captures.local.file_suffix",
        "captures.remote.tun_dst", "captures.remote.bind_interface",
    };
    if (std::find(sensitive_paths.begin(), sensitive_paths.end(), path) != sensitive_paths.end()) {
        return true;
    }
    return (path.starts_with("ssh_profiles.[") && path.ends_with("].host_key")) ||
           (path.starts_with("script_profiles.[") && path.ends_with("].script-file")) ||
           (path.starts_with("tls_profiles.[") && path.ends_with("].sni_filter_bypass")) ||
           (path.starts_with("content_profiles.[") && path.ends_with("].rules_session_filter")) ||
           (path.starts_with("content_profiles.[") &&
            path.find("].content_rules.[") != std::string_view::npos &&
            (path.ends_with("].match") || path.ends_with("].replace"))) ||
           (path.starts_with("tls_ca.[") && path.ends_with("].path")) ||
           ((path.starts_with("starttls_signatures.[") ||
             path.starts_with("detection_signatures.[")) && path.ends_with("].signature"));
}

nlohmann::json draft_value_json(const std::string_view path, const DraftScalar& value) {
    if (!sensitive_draft_path(path)) {
        return std::visit([](const auto& item) { return nlohmann::json(item); }, value);
    }
    if (const auto* text = std::get_if<std::string>(&value); text != nullptr) {
        return text->empty() ? "[redacted:clear]" : "[redacted:replace]";
    }
    if (const auto* items = std::get_if<std::vector<std::string>>(&value); items != nullptr) {
        return items->empty() ? nlohmann::json("[redacted:clear]")
                              : nlohmann::json("[redacted:replace:" +
                                               std::to_string(items->size()) + "]");
    }
    return "[redacted:replace]";
}

nlohmann::json draft_position_json(const DraftPosition& position) {
    switch (position.kind) {
        case DraftPositionKind::First: return {{"first", true}};
        case DraftPositionKind::Last: return {{"last", true}};
        case DraftPositionKind::Before: return {{"before", *position.reference}};
        case DraftPositionKind::After: return {{"after", *position.reference}};
    }
    return nlohmann::json::object();
}

bool structural_operation_supported(
    const DraftStructuralOperation& operation, const TransactionCapabilities& capabilities) {
    if (capabilities.state != "ready") return false;
    const auto collection = draft_structural_collection(operation);
    const auto found = std::find_if(
        capabilities.collections.begin(), capabilities.collections.end(),
        [collection](const auto& item) { return item.id == collection; });
    if (found == capabilities.collections.end()) return false;
    return std::visit([&](const auto& item) {
        using Operation = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            return found->nested == item.parent_id.has_value();
        } else if constexpr (std::is_same_v<Operation, DraftMoveOperation>) {
            return found->ordered;
        } else {
            return true;
        }
    }, operation);
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
          request_id_prefix_(request_id_prefix()), draft_("workspace-draft"),
          commit_coordinator_(draft_), jobs_() {}

    bool validPath(const char*, const char*) override { return true; }
    lmh::ConnectionState* create_state() override {
        const auto sequence = request_sequence_.fetch_add(1U, std::memory_order_relaxed) + 1U;
        return new RequestState(*this, request_id_prefix_ + "-" + std::to_string(sequence));
    }

    int handleComplete(MHD_Connection*, MHD_RequestTerminationCode,
                       lmh::ConnectionState* state) override {
        // lmhpp owns completion dispatch, but its base state has no virtual destructor.
        delete static_cast<RequestState*>(state);
        return MHD_YES;
    }

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
            record_mutation_audit(
                connection, url, state.request_data, response, state.request_id);
        } else if (std::string_view(method) != "GET" && !head) {
            response = {405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}"};
        } else {
            response = route(connection, url);
        }
        if (state.body_too_large && std::string_view(method) == "POST") {
            record_mutation_audit(
                connection, url, state.request_data, response, state.request_id);
        }
        return send(connection, state, std::move(response), head);
    }

private:
    void record_mutation_audit(MHD_Connection* connection, const std::string_view url,
                               const std::string_view body, const Response& response,
                               const std::string& request_id) {
        const auto relative = path_below_base(url, config_.base_path);
        if (!relative || !relative->starts_with("/api/")) return;
        auto metadata = mutation_audit_metadata(*relative, body);
        if (metadata.operation == "config.draft.commit" &&
            response.status >= 200U && response.status < 300U) {
            const auto receipt = nlohmann::json::parse(response.body, nullptr, false);
            if (receipt.is_object() && receipt.contains("committed_operations") &&
                receipt["committed_operations"].is_number_unsigned()) {
                const auto count = receipt["committed_operations"].get<std::uint64_t>();
                if (count <= 4096U) {
                    metadata.target_count = static_cast<std::size_t>(count);
                    metadata.targets_truncated = count > 0U;
                }
            }
        }
        const auto outcome = response.status >= 200U && response.status < 300U ? "succeeded" :
                             response.status == 409U ? "conflict" : "rejected";
        const auto authentication = !config_.gateway_secret ? "disabled" :
                                    gateway_authenticated(connection) ? "gateway" : "none";
        audit_.record(request_id, std::move(metadata.operation), outcome, authentication,
                      metadata.target_count, std::move(metadata.targets), metadata.targets_truncated);
    }

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
        if (relative->starts_with("/api/") && !request_host_allowed(connection)) {
            return {421, "application/json; charset=utf-8", "{\"error\":\"invalid request host\"}"};
        }
        if (relative->starts_with("/api/") && !management_authenticated(connection)) {
            return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
        }
        if (*relative != "/api/v1/config/draft/changes" &&
            *relative != "/api/v1/config/draft/changes/remove" &&
            *relative != "/api/v1/config/draft/operations" &&
            *relative != "/api/v1/config/draft/operations/batch" &&
            *relative != "/api/v1/config/draft/operations/remove" &&
            *relative != "/api/v1/config/draft/clear" &&
            *relative != "/api/v1/config/draft/validate" &&
            *relative != "/api/v1/config/draft/commit") {
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
        bind_empty_draft_revision();
        const auto document = nlohmann::json::parse(body, nullptr, false);
        if (*relative == "/api/v1/config/draft/commit") {
            if (document.is_discarded() || !document.is_object() || document.size() != 1U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft commit request\"}"};
            }
            if (monitor_.status().transaction_capabilities.state != "ready") {
                return {503, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit unavailable\"}"};
            }
            auto lease = commit_coordinator_.begin(
                document["expected_version"].get<std::uint64_t>());
            switch (lease.result()) {
                case CommitPreparationResult::Busy:
                    return {409, "application/json; charset=utf-8",
                            "{\"error\":\"transaction commit in progress\"}"};
                case CommitPreparationResult::VersionConflict:
                    return {409, "application/json; charset=utf-8",
                            "{\"error\":\"draft version conflict\"}"};
                case CommitPreparationResult::Empty:
                case CommitPreparationResult::InvalidDraft:
                    return {422, "application/json; charset=utf-8",
                            "{\"error\":\"transaction commit rejected\"}"};
                case CommitPreparationResult::EntropyUnavailable:
                    return {503, "application/json; charset=utf-8",
                            "{\"error\":\"transaction commit unavailable\"}"};
                case CommitPreparationResult::Ready:
                    break;
            }
            const auto committed_draft = lease.draft();
            const auto transaction = monitor_.commit_transaction(
                committed_draft, lease.idempotency_key());
            if (transaction.state == "conflict") {
                lease.release(false);
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction revision conflict\"}"};
            }
            if (transaction.state == "rejected") {
                lease.release(false);
                return {422, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit rejected\"}"};
            }
            if (transaction.state == "authorization-failed") {
                lease.release(false);
                return {502, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit authorization failed\"}"};
            }
            if (transaction.state == "failed") {
                lease.release(false);
                return {502, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit failed\"}"};
            }
            if (transaction.state == "unavailable") {
                return {503, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit unavailable\"}"};
            }
            if (transaction.state != "succeeded" || !transaction.revision ||
                !transaction.previous_revision) {
                return {502, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit failed\"}"};
            }
            const auto finalized = lease.complete_success(*transaction.revision);
            if (finalized == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (finalized != DraftMutationResult::Applied) {
                return {502, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit failed\"}"};
            }
            (void)monitor_.note_config_committed(*transaction.revision);
            jobs_.reconcile(monitor_.status().config_snapshot);
            const auto refresh_job_id = jobs_.create_config_refresh(*transaction.revision);
            const auto current = draft_.snapshot();
            return {200, "application/json; charset=utf-8", nlohmann::json{
                {"source", "gui-core"},
                {"draft_id", committed_draft.id},
                {"committed_draft_version", committed_draft.version},
                {"draft_version", current.version},
                {"previous_revision", *transaction.previous_revision},
                {"revision", *transaction.revision},
                {"committed_operations", transaction.validated_operations},
                {"warning_count", transaction.warning_count},
                {"restart", transaction.restart},
                {"refresh_job_id", refresh_job_id ? nlohmann::json(*refresh_job_id) : nlohmann::json(nullptr)},
            }.dump()};
        }
        if (*relative == "/api/v1/config/draft/validate") {
            if (document.is_discarded() || !document.is_object() || document.size() != 1U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft validation request\"}"};
            }
            const auto draft = draft_.snapshot();
            if (document["expected_version"].get<std::uint64_t>() != draft.version) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (draft.empty()) {
                return {422, "application/json; charset=utf-8",
                        "{\"error\":\"transaction validation rejected\"}"};
            }
            const auto validation = monitor_.validate_transaction(draft);
            if (validation.state == "conflict") {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction revision conflict\"}"};
            }
            if (validation.state == "rejected") {
                return {422, "application/json; charset=utf-8",
                        "{\"error\":\"transaction validation rejected\"}"};
            }
            if (validation.state == "unavailable") {
                return {503, "application/json; charset=utf-8",
                        "{\"error\":\"transaction validation unavailable\"}"};
            }
            if (validation.state != "succeeded") {
                return {502, "application/json; charset=utf-8",
                        "{\"error\":\"transaction validation failed\"}"};
            }
            return {200, "application/json; charset=utf-8", nlohmann::json{
                {"source", "gui-core"},
                {"draft_id", draft.id},
                {"draft_version", draft.version},
                {"base_revision", *draft.base_revision},
                {"upstream_validation", "valid"},
                {"validated_operations", validation.validated_operations},
                {"warning_count", validation.warning_count},
                {"restart", validation.restart},
            }.dump()};
        }
        if (*relative == "/api/v1/config/draft/clear") {
            if (document.is_discarded() || !document.is_object() || document.size() != 1U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft clear request\"}"};
            }
            const auto result = commit_coordinator_.mutate([&] {
                return draft_.clear(document["expected_version"].get<std::uint64_t>());
            });
            if (result == DraftMutationResult::Busy) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit in progress\"}"};
            }
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/draft/operations/remove") {
            if (document.is_discarded() || !document.is_object() || document.size() != 2U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned() ||
                !document.contains("local_id") || !document["local_id"].is_string()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft remove request\"}"};
            }
            const auto local_id = document["local_id"].get<std::string>();
            if (!valid_draft_structural_local_id(local_id)) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft remove request\"}"};
            }
            const auto result = commit_coordinator_.mutate([&] {
                return draft_.remove_structural(
                    document["expected_version"].get<std::uint64_t>(), local_id);
            });
            if (result == DraftMutationResult::Busy) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit in progress\"}"};
            }
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (result == DraftMutationResult::Missing) {
                return {404, "application/json; charset=utf-8",
                        "{\"error\":\"draft change not found\"}"};
            }
            if (result != DraftMutationResult::Applied) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft remove request\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/draft/operations") {
            if (document.is_discarded() || !document.is_object() || document.size() != 2U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned() ||
                !document.contains("operation")) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft request\"}"};
            }
            auto operation = parse_draft_structural_operation(document["operation"]);
            if (!operation) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft request\"}"};
            }
            const auto status = monitor_.status();
            const auto& capabilities = status.transaction_capabilities;
            const auto current_draft = draft_.snapshot();
            if (capabilities.state != "ready" || !status.config_snapshot.stable_entity_ids ||
                !status.config_snapshot.revision || !current_draft.base_revision ||
                *status.config_snapshot.revision != *current_draft.base_revision) {
                return {503, "application/json; charset=utf-8",
                        "{\"error\":\"structural draft unavailable\"}"};
            }
            if (!structural_operation_supported(*operation, capabilities)) {
                return {422, "application/json; charset=utf-8",
                        "{\"error\":\"draft change rejected\"}"};
            }
            const auto result = commit_coordinator_.mutate([&] {
                return draft_.upsert_structural(
                    document["expected_version"].get<std::uint64_t>(), std::move(*operation));
            });
            if (result == DraftMutationResult::Busy) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit in progress\"}"};
            }
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (result != DraftMutationResult::Applied) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"draft change rejected\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/draft/operations/batch") {
            if (document.is_discarded() || !document.is_object() || document.size() != 2U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned() ||
                !document.contains("operations") || !document["operations"].is_array() ||
                document["operations"].empty() || document["operations"].size() > 256U) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid structural draft batch request\"}"};
            }
            std::vector<DraftStructuralOperation> operations;
            operations.reserve(document["operations"].size());
            for (const auto& raw_operation : document["operations"]) {
                auto operation = parse_draft_structural_operation(raw_operation);
                if (!operation) {
                    return {400, "application/json; charset=utf-8",
                            "{\"error\":\"invalid structural draft batch request\"}"};
                }
                operations.push_back(std::move(*operation));
            }
            const auto status = monitor_.status();
            const auto& capabilities = status.transaction_capabilities;
            const auto current_draft = draft_.snapshot();
            if (capabilities.state != "ready" || !status.config_snapshot.stable_entity_ids ||
                !status.config_snapshot.revision || !current_draft.base_revision ||
                *status.config_snapshot.revision != *current_draft.base_revision) {
                return {503, "application/json; charset=utf-8",
                        "{\"error\":\"structural draft unavailable\"}"};
            }
            if (!std::all_of(operations.begin(), operations.end(), [&](const auto& operation) {
                    return structural_operation_supported(operation, capabilities);
                })) {
                return {422, "application/json; charset=utf-8",
                        "{\"error\":\"draft change rejected\"}"};
            }
            const auto result = commit_coordinator_.mutate([&] {
                return draft_.upsert_structural_many(
                    document["expected_version"].get<std::uint64_t>(), std::move(operations));
            });
            if (result == DraftMutationResult::Busy) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit in progress\"}"};
            }
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (result != DraftMutationResult::Applied) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"draft change rejected\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/draft/changes/remove") {
            if (document.is_discarded() || !document.is_object() || document.size() != 2U ||
                !document.contains("expected_version") ||
                !document["expected_version"].is_number_unsigned()) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft remove request\"}"};
            }
            std::vector<std::string> paths;
            if (document.contains("path") && document["path"].is_string()) {
                paths.push_back(document["path"].get<std::string>());
            } else if (document.contains("paths") && document["paths"].is_array() &&
                       !document["paths"].empty() && document["paths"].size() <= 4096U) {
                paths.reserve(document["paths"].size());
                for (const auto& path : document["paths"]) {
                    if (!path.is_string()) {
                        return {400, "application/json; charset=utf-8",
                                "{\"error\":\"invalid draft remove request\"}"};
                    }
                    paths.push_back(path.get<std::string>());
                }
            } else {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft remove request\"}"};
            }
            const auto result = commit_coordinator_.mutate([&] {
                return draft_.remove_many(document["expected_version"].get<std::uint64_t>(),
                                          std::move(paths));
            });
            if (result == DraftMutationResult::Busy) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"transaction commit in progress\"}"};
            }
            if (result == DraftMutationResult::VersionConflict) {
                return {409, "application/json; charset=utf-8",
                        "{\"error\":\"draft version conflict\"}"};
            }
            if (result == DraftMutationResult::Missing) {
                return {404, "application/json; charset=utf-8",
                        "{\"error\":\"draft change not found\"}"};
            }
            if (result != DraftMutationResult::Applied) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft remove request\"}"};
            }
            return draft_snapshot();
        }
        if (document.is_discarded() || !document.is_object() ||
            !document.contains("expected_version") || !document["expected_version"].is_number_unsigned()) {
            return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
        }
        std::vector<DraftChange> changes;
        std::vector<std::string> remove_paths;
        if (document.size() == 3U && document.contains("path") && document["path"].is_string() &&
            document.contains("value")) {
            auto value = parse_draft_scalar(document["value"]);
            if (!value) {
                return {400, "application/json; charset=utf-8",
                        "{\"error\":\"invalid draft value\"}"};
            }
            changes.push_back({document["path"].get<std::string>(), std::move(*value)});
        } else if ((document.size() == 2U || document.size() == 3U) &&
                   document.contains("changes") && document["changes"].is_array() &&
                   document["changes"].size() <= 4096U &&
                   (document.size() == 2U || (document.contains("remove_paths") &&
                    document["remove_paths"].is_array() &&
                    document["remove_paths"].size() <= 4096U))) {
            for (const auto& item : document["changes"]) {
                if (!item.is_object() || item.size() != 2U || !item.contains("path") ||
                    !item["path"].is_string() || !item.contains("value")) {
                    return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
                }
                auto value = parse_draft_scalar(item["value"]);
                if (!value) {
                    return {400, "application/json; charset=utf-8",
                            "{\"error\":\"invalid draft value\"}"};
                }
                changes.push_back({item["path"].get<std::string>(), std::move(*value)});
            }
            if (document.contains("remove_paths")) {
                remove_paths.reserve(document["remove_paths"].size());
                for (const auto& path : document["remove_paths"]) {
                    if (!path.is_string()) {
                        return {400, "application/json; charset=utf-8",
                                "{\"error\":\"invalid draft change\"}"};
                    }
                    remove_paths.push_back(path.get<std::string>());
                }
            }
        } else {
            return {400, "application/json; charset=utf-8", "{\"error\":\"invalid draft change\"}"};
        }

        const auto result = commit_coordinator_.mutate([&] {
            return draft_.reconcile(
                document["expected_version"].get<std::uint64_t>(),
                std::move(changes), std::move(remove_paths));
        });
        if (result == DraftMutationResult::Busy) {
            return {409, "application/json; charset=utf-8",
                    "{\"error\":\"transaction commit in progress\"}"};
        }
        if (result == DraftMutationResult::VersionConflict) {
            return {409, "application/json; charset=utf-8", "{\"error\":\"draft version conflict\"}"};
        }
        if (result == DraftMutationResult::Missing) {
            return {404, "application/json; charset=utf-8",
                    "{\"error\":\"draft change not found\"}"};
        }
        if (result != DraftMutationResult::Applied) {
            return {400, "application/json; charset=utf-8", "{\"error\":\"draft change rejected\"}"};
        }
        return draft_snapshot();
    }

    Response route(MHD_Connection* connection, const std::string_view url) {
        if (url == "/healthz") return health();
        const auto relative = path_below_base(url, config_.base_path);
        if (!relative) return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        if (*relative == "/healthz") return health();
        if (relative->starts_with("/api/") && !request_host_allowed(connection)) {
            return {421, "application/json; charset=utf-8", "{\"error\":\"invalid request host\"}"};
        }
        const bool public_api_endpoint = *relative == "/api/v1/capabilities" ||
                                         *relative == "/api/v1/auth/session";
        if (relative->starts_with("/api/") && !public_api_endpoint &&
            !management_authenticated(connection)) {
            return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
        }
        if (*relative == "/api/v1/status") return status();
        if (*relative == "/api/v1/metrics/summary") return metrics_summary();
        if (*relative == "/api/v1/tls/cache/summary") return tls_cache_summary();
        if (*relative == "/api/v1/network/neighbors/summary") return neighbor_summary();
        if (*relative == "/api/v1/network/interfaces/summary") return interface_summary();
        if (*relative == "/api/v1/sessions/activity") return session_activity();
        if (*relative == "/api/v1/events/recent") return recent_events();
        if (*relative == "/api/v1/events") return event_stream(connection);
        if (*relative == "/api/v1/alerts") return alerts();
        if (*relative == "/api/v1/audit/recent") return recent_audit();
        if (*relative == "/api/v1/jobs") return jobs();
        if (relative->starts_with("/api/v1/jobs/")) {
            return job(relative->substr(std::string_view{"/api/v1/jobs/"}.size()));
        }
        if (*relative == "/api/v1/capabilities") return capabilities(connection);
        if (*relative == "/api/v1/auth/session") return auth_session(connection);
        if (*relative == "/api/v1/config/draft") {
            if (!gateway_authenticated(connection)) {
                return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
            }
            return draft_snapshot();
        }
        if (*relative == "/api/v1/config/draft/preflight") {
            if (!gateway_authenticated(connection)) {
                return {401, "application/json; charset=utf-8", "{\"error\":\"authentication required\"}"};
            }
            return draft_preflight();
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

    Response capabilities(MHD_Connection* connection) {
        const bool config_read = monitor_.config_enabled() && gateway_authenticated(connection);
        if (config_read) bind_empty_draft_revision();
        const auto status = monitor_.status();
        const bool monitoring = management_authenticated(connection);
        const auto transaction_state = config_read
            ? status.transaction_capabilities.state
            : std::string{"unavailable"};
        const bool config_write = config_read && transaction_state == "ready";
        const auto draft = draft_.snapshot();
        const bool structural_drafts = config_write && status.config_snapshot.stable_entity_ids &&
            status.config_snapshot.revision && draft.base_revision &&
            *status.config_snapshot.revision == *draft.base_revision;
        return {200, "application/json; charset=utf-8",
                "{\"service\":\"smithproxy-gui\",\"api_version\":\"v1\",\"base_path\":" +
                    json_string(config_.base_path) + ",\"smithproxy_state\":" + json_string(status.state) +
                    ",\"config_transaction_state\":" + json_string(transaction_state) +
                    ",\"features\":{\"config_read\":" + (config_read ? "true" : "false") +
                    ",\"config_write\":" + (config_write ? "true" : "false") +
                    ",\"structural_drafts\":" + (structural_drafts ? "true" : "false") +
                    ",\"drafts\":" + (config_read ? "true" : "false") +
                    ",\"draft_preflight\":" + (config_read ? "true" : "false") +
                    ",\"jobs\":" + (monitoring ? "true" : "false") +
                    ",\"events\":" + (monitoring ? "true" : "false") +
                    ",\"alerts\":" + (monitoring ? "true" : "false") +
                    ",\"audit\":" + (monitoring ? "true" : "false") +
                    ",\"smithproxy_events\":false,\"metrics\":" + (monitoring ? "true" : "false") +
                    ",\"session_activity\":" + (monitoring ? "true" : "false") +
                    ",\"tls_monitoring\":" + (monitoring ? "true" : "false") +
                    ",\"neighbor_monitoring\":" + (monitoring ? "true" : "false") +
                    ",\"interface_monitoring\":" + (monitoring ? "true" : "false") + "}}"};
    }

    bool gateway_authenticated(MHD_Connection* connection) const {
        if (!config_.gateway_secret) return false;
        const auto* supplied = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "X-Smithproxy-GUI-Gateway");
        if (supplied == nullptr) return false;
        const bool current = constant_time_equal(supplied, *config_.gateway_secret);
        const bool previous = config_.previous_gateway_secret &&
                              constant_time_equal(supplied, *config_.previous_gateway_secret);
        return current || previous;
    }

    bool management_authenticated(MHD_Connection* connection) const {
        return !config_.gateway_secret || gateway_authenticated(connection);
    }

    bool request_host_allowed(MHD_Connection* connection) const {
        if (config_.gateway_secret) return true;
        const auto* host = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_HOST);
        return host != nullptr && loopback_authority(host);
    }

    Response auth_session(MHD_Connection* connection) const {
        const bool enabled = config_.gateway_secret.has_value();
        const bool authenticated = enabled && gateway_authenticated(connection);
        return {200, "application/json; charset=utf-8",
                "{\"mode\":" + json_string(enabled ? "gateway" : "disabled") +
                    ",\"authenticated\":" + (authenticated ? "true" : "false") + "}"};
    }

    void bind_empty_draft_revision() {
        const auto snapshot = monitor_.status().config_snapshot;
        if (snapshot.state == "ready" && snapshot.revision) {
            draft_.bind_base_revision(
                *snapshot.revision, snapshot.observation_started_at);
        }
    }

    Response draft_snapshot() {
        bind_empty_draft_revision();
        const auto draft = draft_.snapshot();
        nlohmann::json document{
            {"id", draft.id},
            {"base_revision", draft.base_revision ? nlohmann::json(*draft.base_revision) : nlohmann::json(nullptr)},
            {"version", draft.version},
            {"changes", nlohmann::json::array()},
            {"structural_operations", nlohmann::json::array()},
        };
        for (const auto& change : draft.changes) {
            document["changes"].push_back({
                {"path", change.path}, {"value", draft_value_json(change.path, change.value)},
            });
        }
        for (const auto& operation : draft.structural_operations) {
            document["structural_operations"].push_back(std::visit([&](const auto& item) {
                using Operation = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
                    nlohmann::json fields = nlohmann::json::object();
                    for (const auto& [name, value] : item.fields) {
                        const auto path = draft_structural_field_path(item.collection, name);
                        fields[name] = path ? draft_value_json(*path, value)
                                            : nlohmann::json("[redacted:replace]");
                    }
                    nlohmann::json result{
                        {"local_id", item.local_id}, {"op", "create"},
                        {"collection", item.collection}, {"client_id", item.client_id},
                        {"position", draft_position_json(item.position)},
                        {"fields", std::move(fields)},
                    };
                    if (item.parent_id) result["parent_id"] = *item.parent_id;
                    return result;
                } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
                    return nlohmann::json{
                        {"local_id", item.local_id}, {"op", "delete"},
                        {"collection", item.collection}, {"entity_id", item.entity_id},
                    };
                } else {
                    return nlohmann::json{
                        {"local_id", item.local_id}, {"op", "move"},
                        {"collection", item.collection}, {"entity_id", item.entity_id},
                        {"position", draft_position_json(item.position)},
                    };
                }
            }, operation));
        }
        return {200, "application/json; charset=utf-8", document.dump()};
    }

    Response draft_preflight() {
        bind_empty_draft_revision();
        const auto draft = draft_.snapshot();
        const auto transaction = monitor_.status().transaction_capabilities;
        std::map<std::string, std::pair<std::size_t, std::size_t>> sections;
        std::size_t sensitive_changes{};
        for (const auto& change : draft.changes) {
            const auto separator = change.path.find('.');
            const auto section = change.path.substr(0U, separator);
            auto& counts = sections[section];
            ++counts.first;
            if (sensitive_draft_path(change.path)) {
                ++counts.second;
                ++sensitive_changes;
            }
        }
        for (const auto& operation : draft.structural_operations) {
            const auto collection = draft_structural_collection(operation);
            const auto separator = collection.find('.');
            const auto section = std::string(collection.substr(0U, separator));
            auto& counts = sections[section];
            ++counts.first;
            const auto sensitive = std::visit([](const auto& item) {
                using Operation = std::decay_t<decltype(item)>;
                if constexpr (!std::is_same_v<Operation, DraftCreateOperation>) {
                    return false;
                } else {
                    return std::any_of(item.fields.begin(), item.fields.end(), [&](const auto& field) {
                        const auto path = draft_structural_field_path(item.collection, field.first);
                        return !path || sensitive_draft_path(*path);
                    });
                }
            }, operation);
            if (sensitive) {
                ++counts.second;
                ++sensitive_changes;
            }
        }
        nlohmann::json section_list = nlohmann::json::array();
        for (const auto& [name, counts] : sections) {
            section_list.push_back({
                {"name", name},
                {"change_count", counts.first},
                {"sensitive_change_count", counts.second},
            });
        }
        nlohmann::json blockers = nlohmann::json::array();
        const bool validation_available = transaction.state == "ready" && draft.base_revision.has_value();
        const bool commit_available = validation_available && !draft.empty();
        if (draft.empty()) {
            blockers.push_back({
                {"code", "draft.empty"},
                {"message", "The workspace draft has no pending changes."},
            });
        }
        if (transaction.state == "review-required") {
            blockers.push_back({
                {"code", "upstream.schema_review_required"},
                {"message", "Smithproxy transaction schemas are not reviewed by this GUI core."},
            });
        } else if (transaction.state == "incompatible") {
            blockers.push_back({
                {"code", "upstream.transaction_incompatible"},
                {"message", "Smithproxy advertised an incompatible atomic transaction contract."},
            });
        } else if (transaction.state == "ready" && !draft.base_revision) {
            blockers.push_back({
                {"code", "draft.base_revision_unavailable"},
                {"message", "The workspace draft has no canonical Smithproxy base revision."},
            });
        } else if (transaction.state != "ready") {
            blockers.push_back({
                {"code", "upstream.transaction_unavailable"},
                {"message", "Smithproxy does not advertise the reviewed atomic transaction API."},
            });
        }
        return {200, "application/json; charset=utf-8", nlohmann::json{
            {"source", "gui-core"},
            {"draft_id", draft.id},
            {"draft_version", draft.version},
            {"base_revision", draft.base_revision ? nlohmann::json(*draft.base_revision) : nlohmann::json(nullptr)},
            {"change_count", draft.operation_count()},
            {"sensitive_change_count", sensitive_changes},
            {"schema_validation", "valid"},
            {"upstream_validation", "unavailable"},
            {"validation_available", validation_available},
            {"commit_available", commit_available},
            {"sections", std::move(section_list)},
            {"blockers", std::move(blockers)},
        }.dump()};
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
                            ",\"use_pfs\":" + (tls.use_pfs ? "true" : "false") +
                            ",\"left_use_pfs\":" + (tls.left_use_pfs ? "true" : "false") +
                            ",\"right_use_pfs\":" + (tls.right_use_pfs ? "true" : "false") +
                            ",\"left_disable_reuse\":" + (tls.left_disable_reuse ? "true" : "false") +
                            ",\"right_disable_reuse\":" + (tls.right_disable_reuse ? "true" : "false") +
                            ",\"allow_untrusted_issuers\":" + (tls.allow_untrusted_issuers ? "true" : "false") +
                            ",\"allow_invalid_certificates\":" + (tls.allow_invalid_certificates ? "true" : "false") +
                            ",\"allow_self_signed\":" + (tls.allow_self_signed ? "true" : "false") +
                            ",\"certificate_transparency\":" + (tls.certificate_transparency ? "true" : "false") +
                            ",\"ocsp_mode\":" + std::to_string(tls.ocsp_mode) +
                            ",\"ocsp_stapling\":" + (tls.ocsp_stapling ? "true" : "false") +
                            ",\"ocsp_stapling_mode\":" + std::to_string(tls.ocsp_stapling_mode) +
                            ",\"block_alpn\":" + (tls.block_alpn ? "true" : "false") +
                            ",\"sni_based_certificates\":" + (tls.sni_based_certificates ? "true" : "false") +
                            ",\"ip_based_certificates\":" + (tls.ip_based_certificates ? "true" : "false") +
                            ",\"only_custom_certificates\":" + (tls.only_custom_certificates ? "true" : "false") +
                            ",\"no_fallback_bypass\":" + (tls.no_fallback_bypass ? "true" : "false") +
                            ",\"sni_filter_uses_dns_cache\":" +
                            (tls.sni_filter_uses_dns_cache ? "true" : "false") +
                            ",\"sni_filter_uses_dns_domain_tree\":" +
                            (tls.sni_filter_uses_dns_domain_tree ? "true" : "false") +
                            ",\"redirect_warning_ports\":" + number_array_json(tls.redirect_warning_ports) +
                            ",\"failed_certificate_replacement\":" +
                            (tls.failed_certificate_replacement ? "true" : "false") +
                            ",\"failed_certificate_override\":" +
                            (tls.failed_certificate_override ? "true" : "false") +
                            ",\"failed_certificate_override_timeout\":" +
                            std::to_string(tls.failed_certificate_override_timeout) +
                            ",\"failed_certificate_override_timeout_type\":" +
                            std::to_string(tls.failed_certificate_override_timeout_type) +
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
                std::string rules{"["};
                for (std::size_t rule_index = 0; rule_index < content.rules.size(); ++rule_index) {
                    if (rule_index != 0U) rules += ',';
                    const auto& rule = content.rules[rule_index];
                    rules += "{\"id\":" + json_string(rule.id) +
                             ",\"match_configured\":" + (rule.match_configured ? "true" : "false") +
                             ",\"replacement_configured\":" +
                             (rule.replacement_configured ? "true" : "false") +
                             ",\"replacement_has_value\":" +
                             (rule.replacement_has_value ? "true" : "false") +
                             ",\"fill_length\":" + (rule.fill_length ? "true" : "false") +
                             ",\"replace_each_nth\":" + std::to_string(rule.replace_each_nth) + "}";
                }
                rules += ']';
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
                            ",\"rule_count\":" + std::to_string(content.rule_count) +
                            ",\"rules\":" + rules + "}";
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
                       ",\"extended_local_destination_protection\":" +
                       (value.extended_local_destination_protection ? "true" : "false") +
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
                       ",\"dtls\":" + std::to_string(value.dtls_port) +
                       ",\"quic\":" + std::to_string(value.quic_port) +
                       ",\"socks\":" + std::to_string(value.socks_port) +
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
                       ",\"certificate_transparency_log_configured\":" +
                       (value.certificate_transparency_log_configured ? "true" : "false") +
                       ",\"ca_bundle_path_configured\":" +
                       (value.ca_bundle_path_configured ? "true" : "false") +
                       ",\"ca_bundle_file_configured\":" +
                       (value.ca_bundle_file_configured ? "true" : "false") +
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
                       ",\"admin_group_configured\":" + (value.admin_group_configured ? "true" : "false") +
                       ",\"tuning\":{\"host_buffer_min\":" + std::to_string(value.tuning_host_buffer_min) +
                       ",\"host_buffer_max_multiplier\":" + std::to_string(value.tuning_host_buffer_max_multiplier) +
                       ",\"host_write_full\":" + std::to_string(value.tuning_host_write_full) +
                       ",\"host_io_batch\":" + std::to_string(value.tuning_host_io_batch) +
                       ",\"tls_write_chunk\":" + std::to_string(value.tuning_tls_write_chunk) +
                       ",\"host_open_timeout\":" + std::to_string(value.tuning_host_open_timeout) +
                       ",\"host_idle_timeout\":" + std::to_string(value.tuning_host_idle_timeout) +
                       ",\"neighbor_cache_size\":" + std::to_string(value.tuning_neighbor_cache_size) + "}" +
                       ",\"thread_pool_logging\":" + (value.thread_pool_logging ? "true" : "false") +
                       ",\"socks_async_dns\":" + (value.socks_async_dns ? "true" : "false") +
                       ",\"socks_ip_version_mixing\":" + (value.socks_ip_version_mixing ? "true" : "false") +
                       ",\"socks_prefer_ipv6\":" + (value.socks_prefer_ipv6 ? "true" : "false") + "}" +
                       ",\"tls_autodetect\":" + (value.tls_autodetect ? "true" : "false") +
                       ",\"tls_autodetect_harder\":" + (value.tls_autodetect_harder ? "true" : "false") +
                       ",\"kernel_tls\":" + (value.kernel_tls ? "true" : "false") +
                       ",\"nameserver_count\":" + std::to_string(value.nameserver_count) +
                       ",\"nameservers\":" + string_array_json(value.nameservers) +
                       ",\"http_api\":{\"key_count\":" + std::to_string(value.api_key_count) +
                       ",\"allowed_ip_count\":" + std::to_string(value.api_allowed_ip_count) +
                       ",\"allowed_ips\":" + string_array_json(value.api_allowed_ips) +
                       ",\"key_timeout\":" + std::to_string(value.api_key_timeout) +
                       ",\"port\":" + std::to_string(value.api_port) +
                       ",\"key_extend_on_access\":" + (value.api_key_extend_on_access ? "true" : "false") +
                       ",\"loopback_only\":" + (value.api_loopback_only ? "true" : "false") +
                       ",\"pam_login\":" + (value.api_pam_login ? "true" : "false") +
                       ",\"allow_api_header\":" + (value.api_header_allowed ? "true" : "false") +
                       ",\"bind_address_configured\":" +
                       (value.api_bind_address_configured ? "true" : "false") +
                       ",\"bind_interface_configured\":" +
                       (value.api_bind_interface_configured ? "true" : "false") + "}" +
                       ",\"webhook\":{\"enabled\":" + (value.webhook_enabled ? "true" : "false") +
                       ",\"tls_verify\":" + (value.webhook_tls_verify ? "true" : "false") +
                       ",\"url_configured\":" + (value.webhook_url_configured ? "true" : "false") +
                       ",\"sift_enabled\":" + (value.webhook_sift_enabled ? "true" : "false") +
                       ",\"sift_url_configured\":" + (value.webhook_sift_url_configured ? "true" : "false") +
                       ",\"sift_tenant_configured\":" + (value.webhook_sift_tenant_configured ? "true" : "false") +
                       ",\"sift_instance_configured\":" + (value.webhook_sift_instance_configured ? "true" : "false") +
                       ",\"sift_payload_limit_per_direction\":" + std::to_string(value.webhook_sift_payload_limit) +
                       ",\"sift_lored_mode\":" + json_string(value.webhook_sift_lored_mode) +
                       ",\"sift_lored_include_url\":" +
                       (value.webhook_sift_lored_include_url ? "true" : "false") +
                       ",\"hostid_configured\":" + (value.webhook_host_id_configured ? "true" : "false") +
                       ",\"bind_interface_configured\":" + (value.webhook_bind_interface_configured ? "true" : "false") +
                       ",\"api_override\":" + (value.webhook_api_override ? "true" : "false") +
                       ",\"ping_interval\":" + std::to_string(value.webhook_ping_interval) +
                       ",\"nbr_update_interval\":" + std::to_string(value.webhook_neighbor_update_interval) +
                       ",\"nbr_tag_refresh_age\":" + std::to_string(value.webhook_neighbor_tag_refresh_age) +
                       ",\"task_debug\":" + (value.webhook_task_debug ? "true" : "false") +
                       ",\"task_debug_dump\":" + (value.webhook_task_debug_dump ? "true" : "false") + "}}";
        }
        std::string captures{"null"};
        std::string debug{"null"};
        if (snapshot.debug) {
            const auto& value = *snapshot.debug;
            std::string overrides{"["};
            for (std::size_t index = 0; index < value.module_overrides.size(); ++index) {
                if (index != 0U) overrides += ',';
                const auto& item = value.module_overrides[index];
                const auto rendered_value = item.kind == "boolean"
                    ? item.value
                    : item.kind == "integer" ? item.value : json_string(item.value);
                overrides += "{\"name\":" + json_string(item.name) +
                             ",\"kind\":" + json_string(item.kind) +
                             ",\"value\":" + rendered_value + "}";
            }
            overrides += ']';
            debug = "{\"log_data_crc\":" + std::string(value.log_data_crc ? "true" : "false") +
                    ",\"log_sockets\":" + (value.log_sockets ? "true" : "false") +
                    ",\"log_online_cx_name\":" +
                    (value.log_online_connection_name ? "true" : "false") +
                    ",\"log_srclines\":" + (value.log_source_lines ? "true" : "false") +
                    ",\"log_srclines_always\":" +
                    (value.log_source_lines_always ? "true" : "false") +
                    ",\"module_override_count\":" +
                    std::to_string(value.module_override_count) +
                    ",\"module_overrides\":" + overrides + "}";
        }
        if (snapshot.captures) {
            const auto& value = *snapshot.captures;
            captures = "{\"local\":{\"enabled\":" + std::string(value.local_enabled ? "true" : "false") +
                       ",\"directory_configured\":" +
                       (value.local_directory_configured ? "true" : "false") +
                       ",\"file_prefix_configured\":" +
                       (value.local_file_prefix_configured ? "true" : "false") +
                       ",\"file_suffix_configured\":" +
                       (value.local_file_suffix_configured ? "true" : "false") +
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
            std::string authorities{"["};
            for (std::size_t index = 0; index < value.certificate_authorities.size(); ++index) {
                if (index != 0U) authorities += ',';
                const auto& authority = value.certificate_authorities[index];
                authorities += "{\"id\":" + json_string(authority.id) +
                               ",\"name\":" + json_string(authority.name) +
                               ",\"path_configured\":" +
                               (authority.path_configured ? "true" : "false") + "}";
            }
            authorities += ']';
            std::string signatures{"["};
            for (std::size_t index = 0; index < value.signatures.size(); ++index) {
                if (index != 0U) signatures += ',';
                const auto& signature = value.signatures[index];
                std::string flow{"["};
                for (std::size_t flow_index = 0; flow_index < signature.flow.size(); ++flow_index) {
                    if (flow_index != 0U) flow += ',';
                    const auto& step = signature.flow[flow_index];
                    flow += "{\"id\":" + json_string(step.id) +
                            ",\"side\":" + json_string(step.side) +
                            ",\"type\":" + json_string(step.type) +
                            ",\"expression_configured\":" +
                            (step.expression_configured ? "true" : "false") +
                            ",\"bytes_start\":" + std::to_string(step.bytes_start) +
                            ",\"bytes_max\":" + std::to_string(step.bytes_max) + "}";
                }
                flow += ']';
                signatures += "{\"id\":" + json_string(signature.id) +
                              ",\"kind\":" + json_string(signature.kind) +
                              ",\"category\":" + json_string(signature.category) +
                              ",\"name\":" + json_string(signature.name) +
                              ",\"side\":" + json_string(signature.side) +
                              ",\"severity\":" + std::to_string(signature.severity) +
                              ",\"group\":" + json_string(signature.group) +
                              ",\"enables\":" + json_string(signature.enables) +
                              ",\"engine\":" + json_string(signature.engine) +
                              ",\"flow\":" + flow + "}";
            }
            signatures += ']';
            security_assets = "{\"certificate_authorities\":" + authorities +
                              ",\"certificate_authority_count\":" +
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
                              std::to_string(value.detection_flow_step_count) +
                              ",\"signatures\":" + signatures + "}";
        }

        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(snapshot.state) +
                    ",\"detail\":" + json_string(snapshot.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(snapshot.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(snapshot.last_success_at) +
                    ",\"view\":\"runtime\",\"revision\":" +
                    (snapshot.revision ? json_string(*snapshot.revision) : "null") +
                    ",\"policies\":" + policies +
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

    std::vector<JobRecord> observe_operational_state(const SmithproxyStatus& status) {
        jobs_.reconcile(status.config_snapshot);
        auto job_records = jobs_.snapshot();
        operational_events_.observe(status, job_records);
        return job_records;
    }

    Response recent_events() {
        const auto status = monitor_.status();
        (void)observe_operational_state(status);
        return {200, "application/json; charset=utf-8",
                operational_snapshot_json(operational_events_.snapshot())};
    }

    Response event_stream(MHD_Connection* connection) {
        const auto status = monitor_.status();
        (void)observe_operational_state(status);
        const auto records = operational_events_.snapshot();
        const auto* supplied_id = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "Last-Event-ID");
        const std::string_view last_id = supplied_id == nullptr ? std::string_view{} : supplied_id;
        if (last_id.size() > 96U) {
            return {400, "application/json; charset=utf-8", "{\"error\":\"invalid event cursor\"}"};
        }

        std::string body{"retry: 2500\n"};
        const auto append_snapshot = [&](const std::string_view event_name) {
            body += "event: ";
            body += event_name;
            body += '\n';
            if (!records.empty()) body += "id: " + records.back().id + "\n";
            body += "data: " + operational_snapshot_json(records) + "\n\n";
        };

        if (last_id.empty()) {
            append_snapshot("snapshot");
        } else {
            const auto previous = std::find_if(records.begin(), records.end(), [&](const auto& event) {
                return constant_time_equal(event.id, last_id);
            });
            if (previous == records.end()) {
                append_snapshot("reset");
            } else {
                for (auto event = std::next(previous); event != records.end(); ++event) {
                    body += "event: operational\nid: " + event->id +
                            "\ndata: " + operational_event_json(*event) + "\n\n";
                }
                if (std::next(previous) == records.end()) body += ": keepalive\n\n";
            }
        }
        return {200, "text/event-stream; charset=utf-8", std::move(body), "no-store",
                {{"X-Accel-Buffering", "no"}}};
    }

    Response alerts() {
        const auto generated_at = std::chrono::system_clock::now();
        const auto status = monitor_.status();
        const auto job_records = observe_operational_state(status);
        auto active = derive_operational_alerts(
            status, monitor_.configured(), monitor_.config_enabled(), generated_at);
        const auto job_alerts = derive_job_alerts(job_records);
        active.insert(active.end(), job_alerts.begin(), job_alerts.end());
        std::string alerts{"["};
        for (std::size_t index = 0; index < active.size(); ++index) {
            if (index != 0U) alerts += ',';
            const auto& alert = active[index];
            alerts += "{\"id\":" + json_string(alert.id) +
                      ",\"severity\":" + json_string(alert.severity) +
                      ",\"title\":" + json_string(alert.title) +
                      ",\"detail\":" + json_string(alert.detail) + "}";
        }
        alerts += ']';
        return {200, "application/json; charset=utf-8",
                "{\"source\":\"gui-core\",\"generated_at_unix_ms\":" +
                    timestamp_json(generated_at) + ",\"alerts\":" + alerts + "}"};
    }

    Response recent_audit() const {
        nlohmann::json document{
            {"source", "gui-core"},
            {"actor_available", false},
            {"entries", nlohmann::json::array()},
        };
        for (const auto& entry : audit_.snapshot()) {
            document["entries"].push_back({
                {"id", "audit-" + std::to_string(entry.sequence)},
                {"occurred_at_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                    entry.occurred_at.time_since_epoch()).count()},
                {"request_id", entry.request_id},
                {"operation", entry.operation},
                {"outcome", entry.outcome},
                {"authentication", entry.authentication},
                {"actor", nullptr},
                {"target_count", entry.target_count},
                {"targets", entry.targets},
                {"targets_truncated", entry.targets_truncated},
            });
        }
        return {200, "application/json; charset=utf-8", document.dump()};
    }

    Response jobs() {
        const auto records = observe_operational_state(monitor_.status());
        auto generated_at = std::chrono::system_clock::now();
        for (const auto& record : records) {
            generated_at = std::max(generated_at, record.updated_at);
        }
        nlohmann::json document{
            {"source", "gui-core"},
            {"generated_at_unix_ms", std::chrono::duration_cast<std::chrono::milliseconds>(
                generated_at.time_since_epoch()).count()},
            {"owner_available", false},
            {"jobs", nlohmann::json::array()},
        };
        for (const auto& record : records) {
            document["jobs"].push_back(job_json(record));
        }
        return {200, "application/json; charset=utf-8", document.dump()};
    }

    Response job(const std::string_view id) {
        if (!valid_job_id(id)) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"job not found\"}"};
        }
        (void)observe_operational_state(monitor_.status());
        const auto record = jobs_.find(id);
        if (!record) {
            return {404, "application/json; charset=utf-8", "{\"error\":\"job not found\"}"};
        }
        return {200, "application/json; charset=utf-8", nlohmann::json{
            {"source", "gui-core"},
            {"owner_available", false},
            {"job", job_json(*record)},
        }.dump()};
    }

    Response metrics_summary() const {
        const auto metrics = monitor_.status().runtime_metrics;
        std::string history = "[";
        for (std::size_t index = 0; index < metrics.history.size(); ++index) {
            if (index != 0U) history += ',';
            const auto& sample = metrics.history[index];
            history += "{\"state\":" + json_string(sample.state) +
                       ",\"checked_at_unix_ms\":" + timestamp_json(sample.checked_at) +
                       ",\"sessions_active\":" + std::to_string(sample.sessions_active) +
                       ",\"bytes_up\":" + std::to_string(sample.bytes_up) +
                       ",\"bytes_down\":" + std::to_string(sample.bytes_down) + "}";
        }
        history += ']';
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
                    "},\"listeners\":" + listeners + ",\"history\":" + history + "}"};
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

    Response interface_summary() const {
        const auto metrics = monitor_.status().interface_metrics;
        return {200, "application/json; charset=utf-8",
                "{\"state\":" + json_string(metrics.state) +
                    ",\"detail\":" + json_string(metrics.detail) +
                    ",\"checked_at_unix_ms\":" + timestamp_json(metrics.checked_at) +
                    ",\"last_success_at_unix_ms\":" + timestamp_json(metrics.last_success_at) +
                    ",\"generation\":" + std::to_string(metrics.generation) +
                    ",\"synchronization_running\":" +
                    (metrics.synchronization_running ? "true" : "false") +
                    ",\"synchronization_attempts\":" +
                    std::to_string(metrics.synchronization_attempts) +
                    ",\"synchronization_successes\":" +
                    std::to_string(metrics.synchronization_successes) +
                    ",\"synchronization_errors\":" +
                    std::to_string(metrics.synchronization_errors) +
                    ",\"event_datagrams\":" + std::to_string(metrics.event_datagrams) +
                    ",\"changed_event_datagrams\":" +
                    std::to_string(metrics.changed_event_datagrams) +
                    ",\"interfaces\":" + std::to_string(metrics.interfaces) +
                    ",\"addresses\":" + std::to_string(metrics.addresses) +
                    ",\"ipv4_addresses\":" + std::to_string(metrics.ipv4_addresses) +
                    ",\"ipv6_addresses\":" + std::to_string(metrics.ipv6_addresses) +
                    ",\"last_error_code\":" +
                    (metrics.last_error ? json_string(*metrics.last_error) : "null") + "}"};
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
                entrypoint ? "no-store" : "public, max-age=31536000, immutable"};
    }

    static int send(MHD_Connection* connection, RequestState& state, Response response, const bool head) {
        if (response.status >= 400U) {
            const auto legacy = nlohmann::json::parse(response.body, nullptr, false);
            if (legacy.is_object() && legacy.contains("error") && legacy["error"].is_string()) {
                const auto message = legacy["error"].get<std::string>();
                response.content_type = "application/json; charset=utf-8";
                response.body = nlohmann::json{{"error", {
                    {"code", error_code(message)},
                    {"message", message},
                    {"request_id", state.request_id},
                    {"retryable", false},
                    {"fields", nlohmann::json::array()},
                    {"details", nlohmann::json::object()},
                }}}.dump();
            }
        }
        auto* output = MHD_create_response_from_buffer(
            head ? 0U : response.body.size(), head ? nullptr : response.body.data(), MHD_RESPMEM_MUST_COPY);
        if (output == nullptr) return MHD_NO;
        MHD_add_response_header(output, MHD_HTTP_HEADER_CONTENT_TYPE, response.content_type.c_str());
        MHD_add_response_header(output, MHD_HTTP_HEADER_CACHE_CONTROL, response.cache_control.c_str());
        MHD_add_response_header(output, "X-Content-Type-Options", "nosniff");
        MHD_add_response_header(output, "Referrer-Policy", "no-referrer");
        MHD_add_response_header(output, "X-Frame-Options", "SAMEORIGIN");
        MHD_add_response_header(output, "Cross-Origin-Opener-Policy", "same-origin");
        MHD_add_response_header(output, "Cross-Origin-Resource-Policy", "same-origin");
        MHD_add_response_header(output, "Origin-Agent-Cluster", "?1");
        MHD_add_response_header(output, "X-Request-ID", state.request_id.c_str());
        MHD_add_response_header(output, "X-Permitted-Cross-Domain-Policies", "none");
        MHD_add_response_header(output, "Permissions-Policy",
                                "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()");
        MHD_add_response_header(output, "Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                                "worker-src 'self'; manifest-src 'self'; object-src 'none'; "
                                "base-uri 'none'; form-action 'self'; frame-ancestors 'self'");
        for (const auto& [name, value] : response.headers) {
            MHD_add_response_header(output, name.c_str(), value.c_str());
        }
        const auto queued = MHD_queue_response(connection, response.status, output);
        MHD_destroy_response(output);
        if (queued == MHD_YES) state.response_sent = true;
        return queued;
    }

    const AppConfig& config_;
    SmithproxyMonitor& monitor_;
    const std::chrono::steady_clock::time_point started_at_;
    const std::string request_id_prefix_;
    std::atomic<std::uint64_t> request_sequence_{};
    DraftStore draft_;
    CommitCoordinator commit_coordinator_;
    JobStore jobs_;
    OperationalEventStore operational_events_;
    AuditStore audit_;
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
