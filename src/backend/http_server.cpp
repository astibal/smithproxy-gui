#include "http_server.hpp"

#include "json.hpp"
#include "path.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string_view>
#include <utility>

namespace smithproxy::gui {
namespace {

struct RequestState final : lmh::ConnectionState {
    explicit RequestState(lmh::Controller& controller) : ConnectionState(controller) {}
};

struct Response {
    unsigned status{200};
    std::string content_type{"application/json; charset=utf-8"};
    std::string body;
    std::string cache_control{"no-store"};
};

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
        : config_(config), monitor_(monitor), started_at_(std::chrono::steady_clock::now()) {}

    bool validPath(const char*, const char*) override { return true; }
    lmh::ConnectionState* create_state() override { return new RequestState(*this); }

    int handleRequest(MHD_Connection* connection, const char* url, const char* method,
                      const char*, std::size_t* upload_data_size, void** ptr) override {
        if (*ptr == nullptr) {
            *ptr = create_state();
            return MHD_YES;
        }
        auto& state = *static_cast<RequestState*>(*ptr);
        if (*upload_data_size > 0U) {
            *upload_data_size = 0U;
            return MHD_YES;
        }
        if (state.response_sent) return MHD_YES;

        const bool head = std::string_view(method) == "HEAD";
        Response response;
        if (std::string_view(method) != "GET" && !head) {
            response = {405, "application/json; charset=utf-8", "{\"error\":\"method not allowed\"}"};
        } else {
            response = route(url);
        }
        return send(connection, state, std::move(response), head);
    }

private:
    Response route(const std::string_view url) const {
        if (url == "/healthz") return health();
        const auto relative = path_below_base(url, config_.base_path);
        if (!relative) return {404, "application/json; charset=utf-8", "{\"error\":\"not found\"}"};
        if (*relative == "/healthz") return health();
        if (*relative == "/api/v1/status") return status();
        if (*relative == "/api/v1/capabilities") return capabilities();
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

    Response capabilities() const {
        const auto status = monitor_.status();
        return {200, "application/json; charset=utf-8",
                "{\"service\":\"smithproxy-gui\",\"api_version\":\"v1\",\"base_path\":" +
                    json_string(config_.base_path) + ",\"smithproxy_state\":" + json_string(status.state) +
                    ",\"features\":{\"config_read\":false,\"config_write\":false,"
                    "\"jobs\":false,\"events\":false}}"};
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
        MHD_add_response_header(output, "Content-Security-Policy",
                                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                                "object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
        const auto queued = MHD_queue_response(connection, response.status, output);
        MHD_destroy_response(output);
        if (queued == MHD_YES) state.response_sent = true;
        return queued;
    }

    const AppConfig& config_;
    SmithproxyMonitor& monitor_;
    const std::chrono::steady_clock::time_point started_at_;
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
