#include "cli_console.hpp"

#include "websocket.hpp"

#include <lmhttpd.hpp>
#include <microhttpd.h>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

namespace smithproxy::gui {
namespace {

constexpr std::string_view console_protocol = "smithproxy-cli-v1";
constexpr std::size_t maximum_sessions = 4U;
constexpr std::size_t maximum_frame_payload = 64U * 1024U;
constexpr std::size_t maximum_pending_bytes = 256U * 1024U;
constexpr auto connect_timeout = std::chrono::seconds{3};
constexpr auto idle_timeout = std::chrono::minutes{30};

struct SessionCounter {
    explicit SessionCounter(std::shared_ptr<std::atomic_bool> stop)
        : stop_requested(std::move(stop)) {}
    std::atomic_size_t active{};
    std::shared_ptr<std::atomic_bool> stop_requested;
};

struct UpgradeContext {
    int broker{-1};
    std::shared_ptr<SessionCounter> sessions;
};

struct ConsoleRequestState final : lmh::ConnectionState {
    ConsoleRequestState(lmh::Controller& controller, std::shared_ptr<SessionCounter> counter)
        : ConnectionState(controller), sessions(std::move(counter)) {}

    ~ConsoleRequestState() {
        if (broker >= 0) ::close(broker);
        if (reserved) sessions->active.fetch_sub(1U, std::memory_order_relaxed);
    }

    int broker{-1};
    bool reserved{};
    std::shared_ptr<SessionCounter> sessions;
};

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

bool header_is(const char* value, const std::string_view expected) {
    if (value == nullptr || std::strlen(value) != expected.size()) return false;
    return std::equal(expected.begin(), expected.end(), value, [](const char left, const char right) {
        return std::tolower(static_cast<unsigned char>(left)) ==
               std::tolower(static_cast<unsigned char>(right));
    });
}

bool header_contains_token(const char* value, const std::string_view expected) {
    if (value == nullptr) return false;
    std::string_view remaining(value);
    while (!remaining.empty()) {
        const auto comma = remaining.find(',');
        auto token = remaining.substr(0U, comma);
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) {
            token.remove_prefix(1U);
        }
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back()))) {
            token.remove_suffix(1U);
        }
        if (token.size() == expected.size() &&
            std::equal(expected.begin(), expected.end(), token.begin(), [](const char left, const char right) {
                return std::tolower(static_cast<unsigned char>(left)) ==
                       std::tolower(static_cast<unsigned char>(right));
            })) {
            return true;
        }
        if (comma == std::string_view::npos) break;
        remaining.remove_prefix(comma + 1U);
    }
    return false;
}

bool gateway_authenticated(MHD_Connection* connection, const AppConfig& config) {
    if (!config.gateway_secret) return true;
    const auto* supplied = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, "X-Smithproxy-GUI-Gateway");
    if (supplied == nullptr) return false;
    return constant_time_equal(supplied, *config.gateway_secret) ||
           (config.previous_gateway_secret &&
            constant_time_equal(supplied, *config.previous_gateway_secret));
}

bool same_origin(MHD_Connection* connection) {
    const auto* origin = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin");
    const auto* host = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Host");
    const auto* fetch_site = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, "Sec-Fetch-Site");
    if (origin == nullptr || host == nullptr) return false;
    if (fetch_site != nullptr && std::string_view(fetch_site) != "same-origin") return false;
    const std::string http = "http://" + std::string(host);
    const std::string https = "https://" + std::string(host);
    return constant_time_equal(origin, http) || constant_time_equal(origin, https);
}

int set_nonblocking(const int socket) {
    const auto flags = ::fcntl(socket, F_GETFL, 0);
    return flags < 0 ? -1 : ::fcntl(socket, F_SETFL, flags | O_NONBLOCK);
}

// Resolve and connect before accepting the browser upgrade. A failed broker
// therefore remains an ordinary HTTP 503 instead of a blank terminal.
int connect_broker(const SmithproxyCliConfig& endpoint) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses{};
    const auto service = std::to_string(endpoint.port);
    if (::getaddrinfo(endpoint.host.c_str(), service.c_str(), &hints, &addresses) != 0) return -1;
    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> owned(addresses, ::freeaddrinfo);

    for (auto* address = addresses; address != nullptr; address = address->ai_next) {
        const int socket = ::socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (socket < 0) continue;
        if (set_nonblocking(socket) != 0) {
            ::close(socket);
            continue;
        }
        if (::connect(socket, address->ai_addr, address->ai_addrlen) == 0) return socket;
        if (errno != EINPROGRESS) {
            ::close(socket);
            continue;
        }
        pollfd descriptor{socket, POLLOUT, 0};
        if (::poll(&descriptor, 1, static_cast<int>(connect_timeout.count() * 1000)) > 0) {
            int error{};
            socklen_t size = sizeof(error);
            if (::getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0) {
                return socket;
            }
        }
        ::close(socket);
    }
    return -1;
}

bool append_bounded(std::string& destination, const std::string_view bytes) {
    if (bytes.size() > maximum_pending_bytes - destination.size()) return false;
    destination.append(bytes);
    return true;
}

bool flush_socket(const int socket, std::string& pending) {
    if (pending.empty()) return true;
    const auto written = ::send(socket, pending.data(), pending.size(), MSG_NOSIGNAL);
    if (written > 0) {
        pending.erase(0U, static_cast<std::size_t>(written));
        return true;
    }
    return written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR);
}

// Move bytes in both directions without interpreting CLI commands. WebSocket
// control frames terminate or maintain the transport; only data frames reach libcli2.
void bridge_session(UpgradeContext context, const MHD_socket browser,
                    MHD_UpgradeResponseHandle* upgrade, std::string initial) {
    std::string browser_input = std::move(initial);
    std::string browser_output;
    std::string broker_output;
    auto last_activity = std::chrono::steady_clock::now();
    std::array<char, 16U * 1024U> buffer{};
    bool running = initial.size() <= maximum_pending_bytes && set_nonblocking(browser) == 0;

    while (running && !context.sessions->stop_requested->load(std::memory_order_relaxed) &&
           std::chrono::steady_clock::now() - last_activity < idle_timeout) {
        while (!browser_input.empty()) {
            auto decoded = decode_websocket_client_frame(browser_input, maximum_frame_payload);
            if (decoded.state == WebSocketDecodeState::Incomplete) break;
            if (decoded.state == WebSocketDecodeState::ProtocolError) {
                running = false;
                break;
            }
            browser_input.erase(0U, decoded.frame.consumed);
            if (decoded.frame.opcode == WebSocketOpcode::Close) {
                running = false;
            } else if (decoded.frame.opcode == WebSocketOpcode::Ping) {
                running = append_bounded(
                    browser_output,
                    encode_websocket_server_frame(WebSocketOpcode::Pong, decoded.frame.payload));
            } else if (decoded.frame.opcode == WebSocketOpcode::Text ||
                       decoded.frame.opcode == WebSocketOpcode::Binary) {
                running = append_bounded(broker_output, decoded.frame.payload);
            }
        }
        if (!running) break;

        pollfd descriptors[2] = {
            {browser, static_cast<short>(POLLIN | (browser_output.empty() ? 0 : POLLOUT)), 0},
            {context.broker, static_cast<short>(POLLIN | (broker_output.empty() ? 0 : POLLOUT)), 0},
        };
        const auto ready = ::poll(descriptors, 2, 1000);
        if (ready < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if ((descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 ||
            (descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) break;
        if ((descriptors[0].revents & POLLIN) != 0) {
            const auto size = ::recv(browser, buffer.data(), buffer.size(), 0);
            if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                continue;
            }
            if (size <= 0 || !append_bounded(
                    browser_input, {buffer.data(), static_cast<std::size_t>(size)})) break;
            last_activity = std::chrono::steady_clock::now();
        }
        if ((descriptors[1].revents & POLLIN) != 0) {
            const auto size = ::recv(context.broker, buffer.data(), buffer.size(), 0);
            if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
                continue;
            }
            if (size <= 0 || !append_bounded(
                    browser_output,
                    encode_websocket_server_frame(
                        WebSocketOpcode::Binary,
                        {buffer.data(), static_cast<std::size_t>(size)}))) break;
            last_activity = std::chrono::steady_clock::now();
        }
        if ((descriptors[0].revents & POLLOUT) != 0 &&
            !flush_socket(browser, browser_output)) break;
        if ((descriptors[1].revents & POLLOUT) != 0 &&
            !flush_socket(context.broker, broker_output)) break;
    }

    ::close(context.broker);
    MHD_upgrade_action(upgrade, MHD_UPGRADE_ACTION_CLOSE);
    context.sessions->active.fetch_sub(1U, std::memory_order_relaxed);
}

void upgraded(void*, MHD_Connection*, void* request_state, const char* extra, const std::size_t extra_size,
              const MHD_socket socket, MHD_UpgradeResponseHandle* upgrade) {
    auto* state = static_cast<ConsoleRequestState*>(request_state);
    UpgradeContext context{state->broker, state->sessions};
    state->broker = -1;
    state->reserved = false;
    std::string initial(extra, extra_size);
    std::thread(bridge_session, std::move(context), socket, upgrade, std::move(initial)).detach();
}

class CliConsoleController final : public lmh::Controller {
public:
    CliConsoleController(const AppConfig& config, std::shared_ptr<std::atomic_bool> stop_requested)
        : config_(config), path_(config.base_path == "/"
              ? "/api/v1/console"
              : config.base_path + "/api/v1/console"),
          sessions_(std::make_shared<SessionCounter>(std::move(stop_requested))) {}

    bool validPath(const char* path, const char* method) override {
        return config_.smithproxy_cli && path != nullptr && method != nullptr &&
               std::string_view(path) == path_ && std::string_view(method) == "GET";
    }

    lmh::ConnectionState* create_state() override {
        return new ConsoleRequestState(*this, sessions_);
    }

    int handleComplete(MHD_Connection*, MHD_RequestTerminationCode,
                       lmh::ConnectionState* state) override {
        delete static_cast<ConsoleRequestState*>(state);
        return MHD_YES;
    }

    int handleRequest(MHD_Connection* connection, const char*, const char*, const char*,
                      std::size_t*, void** request_state) override {
        if (*request_state == nullptr) {
            *request_state = create_state();
            return MHD_YES;
        }
        auto* state = static_cast<ConsoleRequestState*>(*request_state);
        if (state->response_sent) return MHD_YES;
        if (!gateway_authenticated(connection, config_) || !same_origin(connection)) {
            return send_error(connection, *state, MHD_HTTP_UNAUTHORIZED);
        }
        const auto* upgrade = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_UPGRADE);
        const auto* connection_header = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONNECTION);
        const auto* version = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "Sec-WebSocket-Version");
        const auto* protocol = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "Sec-WebSocket-Protocol");
        const auto* key = MHD_lookup_connection_value(
            connection, MHD_HEADER_KIND, "Sec-WebSocket-Key");
        const auto accept = key == nullptr ? std::string{} : websocket_accept(key);
        if (!header_is(upgrade, "websocket") || !header_contains_token(connection_header, "upgrade") ||
            !constant_time_equal(version == nullptr ? "" : version, "13") ||
            !constant_time_equal(protocol == nullptr ? "" : protocol, console_protocol) || accept.empty()) {
            return send_error(connection, *state, MHD_HTTP_BAD_REQUEST);
        }

        auto active = sessions_->active.load(std::memory_order_relaxed);
        while (active < maximum_sessions &&
               !sessions_->active.compare_exchange_weak(active, active + 1U)) {}
        if (active >= maximum_sessions) return send_error(connection, *state, MHD_HTTP_TOO_MANY_REQUESTS);
        state->reserved = true;
        const int broker = connect_broker(*config_.smithproxy_cli);
        if (broker < 0) {
            sessions_->active.fetch_sub(1U, std::memory_order_relaxed);
            state->reserved = false;
            return send_error(connection, *state, MHD_HTTP_SERVICE_UNAVAILABLE);
        }
        state->broker = broker;

        auto* response = MHD_create_response_for_upgrade(upgraded, nullptr);
        if (response == nullptr) {
            return MHD_NO;
        }
        MHD_add_response_header(response, MHD_HTTP_HEADER_UPGRADE, "websocket");
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONNECTION, "Upgrade");
        MHD_add_response_header(response, "Sec-WebSocket-Accept", accept.c_str());
        MHD_add_response_header(response, "Sec-WebSocket-Protocol", console_protocol.data());
        const auto queued = MHD_queue_response(connection, MHD_HTTP_SWITCHING_PROTOCOLS, response);
        MHD_destroy_response(response);
        if (queued == MHD_YES) state->response_sent = true;
        return queued;
    }

private:
    int send_error(MHD_Connection* connection, lmh::ConnectionState& state, const unsigned status) {
        auto* response = MHD_create_response_from_buffer(0U, nullptr, MHD_RESPMEM_PERSISTENT);
        const auto queued = MHD_queue_response(connection, status, response);
        MHD_destroy_response(response);
        if (queued == MHD_YES) state.response_sent = true;
        return queued;
    }

    const AppConfig& config_;
    const std::string path_;
    std::shared_ptr<SessionCounter> sessions_;
};

} // namespace

std::shared_ptr<lmh::Controller> make_cli_console_controller(
    const AppConfig& config, std::shared_ptr<std::atomic_bool> stop_requested) {
    return std::make_shared<CliConsoleController>(config, std::move(stop_requested));
}

} // namespace smithproxy::gui
