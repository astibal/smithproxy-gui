#include "smithproxy_client.hpp"

#include <curl/curl.h>

#include <condition_variable>
#include <future>
#include <limits>
#include <memory>
#include <string_view>

namespace smithproxy::gui {
namespace {

struct CurlCleanup {
    void operator()(CURL* handle) const { curl_easy_cleanup(handle); }
};

struct HeaderCleanup {
    void operator()(curl_slist* headers) const { curl_slist_free_all(headers); }
};

std::size_t discard_body(char*, const std::size_t size, const std::size_t count, void*) {
    return size * count;
}

struct ResponseBuffer {
    std::size_t limit{256U * 1024U};
    std::string body;
    bool exceeded{};
};

std::size_t collect_body(char* data, const std::size_t size, const std::size_t count, void* context) {
    auto& response = *static_cast<ResponseBuffer*>(context);
    if (count != 0U && size > std::numeric_limits<std::size_t>::max() / count) {
        response.exceeded = true;
        return 0U;
    }
    const auto bytes = size * count;
    if (response.body.size() > response.limit || bytes > response.limit - response.body.size()) {
        response.exceeded = true;
        return 0U;
    }
    response.body.append(data, bytes);
    return bytes;
}

void configure_request(CURL* curl, const SmithproxyConfig& config, const std::string& endpoint,
                       curl_slist* headers) {
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_CAINFO, config.ca_cert.c_str());
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,
                     config.api_url.starts_with("https://") ? "https" : "http");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 2500L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
}

SmithproxyStatus probe_result(const std::string& state, std::string detail,
                              const std::chrono::steady_clock::time_point started_at) {
    const auto latency = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_at).count();
    SmithproxyStatus result;
    result.state = state;
    result.detail = std::move(detail);
    result.checked_at = std::chrono::system_clock::now();
    result.latency_ms = latency > 0 ? static_cast<std::uint64_t>(latency) : 0U;
    return result;
}

} // namespace

SmithproxyMonitor::SmithproxyMonitor(std::optional<SmithproxyConfig> config, const bool config_enabled)
    : config_(std::move(config)), config_enabled_(config_enabled) {
    if (config_) {
        status_.state = "starting";
        status_.detail = "Waiting for the first Smithproxy probe";
        status_.runtime_metrics.state = "starting";
        status_.runtime_metrics.detail = "Waiting for the first Smithproxy metrics sample";
        status_.tls_cache_metrics.state = "starting";
        status_.tls_cache_metrics.detail = "Waiting for the first Smithproxy TLS cache sample";
        status_.live_sessions.state = "starting";
        status_.live_sessions.detail = "Waiting for the first Smithproxy session activity sample";
        if (config_enabled_) {
            status_.config_snapshot.state = "starting";
            status_.config_snapshot.detail = "Waiting for the first Smithproxy configuration sample";
        }
    }
}

SmithproxyMonitor::~SmithproxyMonitor() { stop(); }

void SmithproxyMonitor::start() {
    if (!config_ || worker_.joinable()) return;
    worker_ = std::jthread([this](const std::stop_token token) { run(token); });
}

void SmithproxyMonitor::stop() {
    if (!worker_.joinable()) return;
    worker_.request_stop();
    worker_.join();
}

SmithproxyStatus SmithproxyMonitor::status() const {
    std::scoped_lock lock(mutex_);
    return status_;
}

void SmithproxyMonitor::run(const std::stop_token stop_token) {
    std::mutex wait_mutex;
    std::condition_variable_any wakeup;
    auto next_session_sample = std::chrono::steady_clock::time_point{};
    auto next_config_sample = std::chrono::steady_clock::time_point{};
    while (!stop_token.stop_requested()) {
        auto latest = ping();
        std::optional<RuntimeMetrics> sampled_metrics;
        std::optional<TlsCacheMetrics> sampled_tls_cache;
        std::optional<LiveSessions> sampled_sessions;
        std::optional<ConfigSnapshot> sampled_config;
        if (latest.state == "ready") {
            const auto now = std::chrono::steady_clock::now();
            const bool sample_sessions = now >= next_session_sample;
            const bool sample_config = config_enabled_ && now >= next_config_sample;
            auto metrics_future = std::async(
                std::launch::async, [this] { return fetch_runtime_metrics(); });
            auto tls_cache_future = std::async(
                std::launch::async, [this] { return fetch_tls_cache_metrics(); });
            std::optional<std::future<ConfigSnapshot>> config_future;
            if (sample_config) {
                config_future.emplace(std::async(
                    std::launch::async, [this] { return fetch_config_snapshot(); }));
            }
            if (sample_sessions) sampled_sessions = fetch_live_sessions();
            sampled_metrics = metrics_future.get();
            sampled_tls_cache = tls_cache_future.get();
            if (config_future) sampled_config = config_future->get();
            if (sample_sessions) {
                next_session_sample = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            }
            if (sample_config) {
                next_config_sample = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            }
        }
        {
            std::scoped_lock lock(mutex_);
            latest.total_probes = status_.total_probes + 1U;
            latest.last_success_at = status_.last_success_at;
            latest.consecutive_failures = status_.consecutive_failures + 1U;
            latest.history = std::move(status_.history);
            auto previous_metrics = std::move(status_.runtime_metrics);
            auto previous_tls_cache = std::move(status_.tls_cache_metrics);
            auto previous_sessions = std::move(status_.live_sessions);
            auto previous_config = std::move(status_.config_snapshot);
            if (latest.state == "ready") {
                latest.last_success_at = latest.checked_at;
                latest.consecutive_failures = 0U;
                auto metrics = std::move(*sampled_metrics);
                metrics.last_success_at = previous_metrics.last_success_at;
                if (metrics.state == "ready") {
                    metrics.last_success_at = metrics.checked_at;
                } else {
                    metrics.workers = previous_metrics.workers;
                    metrics.sessions_total = previous_metrics.sessions_total;
                    metrics.sessions_active = previous_metrics.sessions_active;
                    metrics.bytes_up = previous_metrics.bytes_up;
                    metrics.bytes_down = previous_metrics.bytes_down;
                    metrics.listeners = std::move(previous_metrics.listeners);
                }
                latest.runtime_metrics = std::move(metrics);

                auto tls_cache = std::move(*sampled_tls_cache);
                tls_cache.last_success_at = previous_tls_cache.last_success_at;
                if (tls_cache.state == "ready") {
                    tls_cache.last_success_at = tls_cache.checked_at;
                } else {
                    tls_cache.size = previous_tls_cache.size;
                    tls_cache.capacity = previous_tls_cache.capacity;
                }
                latest.tls_cache_metrics = std::move(tls_cache);

                if (sampled_sessions) {
                    auto sessions = std::move(*sampled_sessions);
                    sessions.last_success_at = previous_sessions.last_success_at;
                    if (sessions.state == "ready") {
                        sessions.last_success_at = sessions.checked_at;
                    } else {
                        sessions.total = previous_sessions.total;
                        sessions.speed_up = previous_sessions.speed_up;
                        sessions.speed_down = previous_sessions.speed_down;
                        sessions.protocols = std::move(previous_sessions.protocols);
                    }
                    latest.live_sessions = std::move(sessions);
                } else {
                    latest.live_sessions = std::move(previous_sessions);
                }
                if (sampled_config) {
                    auto config = std::move(*sampled_config);
                    config.last_success_at = previous_config.last_success_at;
                    if (config.state == "ready") {
                        config.last_success_at = config.checked_at;
                    } else {
                        config.policies = std::move(previous_config.policies);
                        config.addresses = std::move(previous_config.addresses);
                        config.ports = std::move(previous_config.ports);
                        config.protocols = std::move(previous_config.protocols);
                    }
                    latest.config_snapshot = std::move(config);
                } else {
                    latest.config_snapshot = std::move(previous_config);
                }
            } else {
                previous_metrics.state = "unavailable";
                previous_metrics.detail = "Smithproxy runtime metrics are unavailable while the API probe is not ready";
                previous_metrics.checked_at = latest.checked_at;
                latest.runtime_metrics = std::move(previous_metrics);
                previous_tls_cache.state = "unavailable";
                previous_tls_cache.detail = "Smithproxy TLS cache is unavailable while the API probe is not ready";
                previous_tls_cache.checked_at = latest.checked_at;
                latest.tls_cache_metrics = std::move(previous_tls_cache);
                previous_sessions.state = "unavailable";
                previous_sessions.detail = "Smithproxy session activity is unavailable while the API probe is not ready";
                previous_sessions.checked_at = latest.checked_at;
                latest.live_sessions = std::move(previous_sessions);
                if (config_enabled_) {
                    previous_config.state = "unavailable";
                    previous_config.detail = "Smithproxy configuration is unavailable while the API probe is not ready";
                    previous_config.checked_at = latest.checked_at;
                }
                latest.config_snapshot = std::move(previous_config);
            }
            latest.history.push_back({latest.state, latest.checked_at, latest.latency_ms});
            if (latest.history.size() > 60U) latest.history.erase(latest.history.begin());
            status_ = std::move(latest);
        }
        std::unique_lock lock(wait_mutex);
        wakeup.wait_for(lock, stop_token, std::chrono::seconds(5), [] { return false; });
    }
}

SmithproxyStatus SmithproxyMonitor::ping() const {
    const auto started_at = std::chrono::steady_clock::now();
    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) return probe_result("error", "Cannot initialize the Smithproxy HTTP client", started_at);

    const std::string endpoint = config_->api_url + "/api/status/ping";
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) return probe_result("error", "Cannot prepare Smithproxy authentication", started_at);

    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, discard_body);

    const auto result = curl_easy_perform(curl.get());
    if (result != CURLE_OK) {
        return probe_result("unreachable", curl_easy_strerror(result), started_at);
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code == 200L) {
        return probe_result("ready", "Smithproxy API accepted the bootstrap credential", started_at);
    }
    if (status_code == 401L || status_code == 403L) {
        return probe_result("unauthorized", "Smithproxy API rejected the bootstrap credential", started_at);
    }
    return probe_result("error", "Smithproxy API returned HTTP " + std::to_string(status_code), started_at);
}

RuntimeMetrics SmithproxyMonitor::fetch_runtime_metrics() const {
    RuntimeMetrics metrics;
    metrics.state = "unavailable";
    metrics.checked_at = std::chrono::system_clock::now();

    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) {
        metrics.detail = "Cannot initialize the Smithproxy metrics client";
        return metrics;
    }
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) {
        metrics.detail = "Cannot prepare Smithproxy metrics authentication";
        return metrics;
    }

    const std::string endpoint = config_->api_url + "/api/diag/proxy/listener/stats";
    ResponseBuffer response;
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    metrics.checked_at = std::chrono::system_clock::now();
    if (response.exceeded) {
        metrics.detail = "Smithproxy listener metrics exceeded the response limit";
        return metrics;
    }
    if (result != CURLE_OK) {
        metrics.detail = std::string("Cannot retrieve Smithproxy listener metrics: ") + curl_easy_strerror(result);
        return metrics;
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 200L) {
        metrics.detail = "Smithproxy listener metrics returned HTTP " + std::to_string(status_code);
        return metrics;
    }
    auto parsed = parse_listener_metrics(response.body);
    if (!parsed.metrics) {
        metrics.detail = std::move(parsed.error);
        return metrics;
    }
    parsed.metrics->checked_at = metrics.checked_at;
    return std::move(*parsed.metrics);
}

TlsCacheMetrics SmithproxyMonitor::fetch_tls_cache_metrics() const {
    TlsCacheMetrics metrics;
    metrics.state = "unavailable";
    metrics.checked_at = std::chrono::system_clock::now();

    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) {
        metrics.detail = "Cannot initialize the Smithproxy TLS cache client";
        return metrics;
    }
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) {
        metrics.detail = "Cannot prepare Smithproxy TLS cache authentication";
        return metrics;
    }

    const std::string endpoint = config_->api_url + "/api/diag/ssl/cache/stats";
    ResponseBuffer response;
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    metrics.checked_at = std::chrono::system_clock::now();
    if (response.exceeded) {
        metrics.detail = "Smithproxy TLS cache metrics exceeded the response limit";
        return metrics;
    }
    if (result != CURLE_OK) {
        metrics.detail = std::string("Cannot retrieve Smithproxy TLS cache metrics: ") +
                         curl_easy_strerror(result);
        return metrics;
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 200L) {
        metrics.detail = "Smithproxy TLS cache metrics returned HTTP " + std::to_string(status_code);
        return metrics;
    }
    auto parsed = parse_tls_cache_metrics(response.body);
    if (!parsed.metrics) {
        metrics.detail = std::move(parsed.error);
        return metrics;
    }
    parsed.metrics->checked_at = metrics.checked_at;
    return std::move(*parsed.metrics);
}

LiveSessions SmithproxyMonitor::fetch_live_sessions() const {
    LiveSessions sessions;
    sessions.state = "unavailable";
    sessions.checked_at = std::chrono::system_clock::now();

    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) {
        sessions.detail = "Cannot initialize the Smithproxy session activity client";
        return sessions;
    }
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) {
        sessions.detail = "Cannot prepare Smithproxy session activity authentication";
        return sessions;
    }

    const std::string endpoint = config_->api_url + "/api/diag/proxy/session/list";
    ResponseBuffer response;
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    sessions.checked_at = std::chrono::system_clock::now();
    if (response.exceeded) {
        sessions.detail = "Smithproxy session activity exceeded the response limit";
        return sessions;
    }
    if (result != CURLE_OK) {
        sessions.detail = std::string("Cannot retrieve Smithproxy session activity: ") +
                          curl_easy_strerror(result);
        return sessions;
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 200L) {
        sessions.detail = "Smithproxy session activity returned HTTP " + std::to_string(status_code);
        return sessions;
    }
    auto parsed = parse_live_sessions(response.body);
    if (!parsed.snapshot) {
        sessions.detail = std::move(parsed.error);
        return sessions;
    }
    parsed.snapshot->checked_at = sessions.checked_at;
    return std::move(*parsed.snapshot);
}

ConfigSnapshot SmithproxyMonitor::fetch_config_snapshot() const {
    ConfigSnapshot snapshot;
    snapshot.state = "unavailable";
    snapshot.checked_at = std::chrono::system_clock::now();

    struct SectionResponse {
        std::optional<std::string> body;
        std::string error;
    };
    const auto fetch_section = [this](const std::string& section) -> SectionResponse {
        std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
        if (!curl) return {std::nullopt, "Cannot initialize the Smithproxy configuration client"};

        auto* raw_headers = curl_slist_append(
            nullptr, ("X-API-Key: " + config_->api_key).c_str());
        if (!raw_headers) return {std::nullopt, "Cannot prepare Smithproxy configuration authentication"};
        auto* updated_headers = curl_slist_append(raw_headers, "Content-Type: application/json");
        if (!updated_headers) {
            curl_slist_free_all(raw_headers);
            return {std::nullopt, "Cannot prepare Smithproxy configuration headers"};
        }
        std::unique_ptr<curl_slist, HeaderCleanup> headers(updated_headers);

        const std::string endpoint = config_->api_url + "/api/config/uni/get";
        const std::string request = "{\"params\":{\"section\":\"" + section + "\",\"name\":\"\"}}";
        ResponseBuffer response{
            .limit = 2U * 1024U * 1024U,
            .body = {},
            .exceeded = false,
        };
        configure_request(curl.get(), *config_, endpoint, headers.get());
        curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, request.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, static_cast<long>(request.size()));
        curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
        curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
        const auto result = curl_easy_perform(curl.get());
        if (response.exceeded) {
            return {std::nullopt, "Smithproxy configuration exceeded the response limit"};
        }
        if (result != CURLE_OK) {
            return {std::nullopt, std::string("Cannot retrieve Smithproxy configuration: ") +
                                      curl_easy_strerror(result)};
        }
        long status_code{};
        curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
        if (status_code != 200L) {
            return {std::nullopt, "Smithproxy configuration returned HTTP " +
                                      std::to_string(status_code)};
        }
        return {std::move(response.body), {}};
    };

    auto policies_future = std::async(std::launch::async, fetch_section, "policy");
    auto addresses_future = std::async(std::launch::async, fetch_section, "address_objects");
    auto ports_future = std::async(std::launch::async, fetch_section, "port_objects");
    auto protocols_future = std::async(std::launch::async, fetch_section, "proto_objects");
    auto policies = policies_future.get();
    auto addresses = addresses_future.get();
    auto ports = ports_future.get();
    auto protocols = protocols_future.get();
    snapshot.checked_at = std::chrono::system_clock::now();

    for (const auto* response : {&policies, &addresses, &ports, &protocols}) {
        if (!response->body) {
            snapshot.detail = response->error;
            return snapshot;
        }
    }
    auto parsed = parse_config_snapshot(
        *policies.body, *addresses.body, *ports.body, *protocols.body);
    if (!parsed.snapshot) {
        snapshot.detail = std::move(parsed.error);
        return snapshot;
    }
    parsed.snapshot->checked_at = snapshot.checked_at;
    return std::move(*parsed.snapshot);
}

} // namespace smithproxy::gui
