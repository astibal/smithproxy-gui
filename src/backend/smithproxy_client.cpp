#include "smithproxy_client.hpp"

#include <curl/curl.h>

#include <array>
#include <condition_variable>
#include <future>
#include <iterator>
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

constexpr std::size_t transaction_response_limit = 1024U * 1024U;

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

TransactionResponse transaction_failure(std::string state) {
    return {
        .state = std::move(state),
        .revision = std::nullopt,
        .previous_revision = std::nullopt,
        .validated_operations = 0U,
        .warning_count = 0U,
        .restart = "unknown",
    };
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
        status_.neighbor_metrics.state = "starting";
        status_.neighbor_metrics.detail = "Waiting for the first Smithproxy neighborhood sample";
        if (config_enabled_) {
            status_.config_snapshot.state = "starting";
            status_.config_snapshot.detail = "Waiting for the first Smithproxy configuration sample";
            status_.transaction_capabilities.state = "starting";
            status_.transaction_capabilities.detail =
                "Waiting for Smithproxy transaction capability discovery";
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

TransactionResponse SmithproxyMonitor::validate_transaction(const DraftSnapshot& draft) const {
    if (!config_ || !config_enabled_) return transaction_failure("unavailable");
    if (!draft.base_revision) return transaction_failure("unavailable");
    const auto capabilities = status().transaction_capabilities;
    const auto idempotency_key = generate_transaction_idempotency_key();
    if (!idempotency_key) return transaction_failure("unavailable");
    const auto envelope = build_transaction_envelope(
        draft, TransactionMode::Validate, *idempotency_key, capabilities);
    if (!envelope.body) {
        return transaction_failure(
            envelope.error_code == "transaction.request_too_large" ||
                    envelope.error_code == "transaction.invalid_draft"
            ? "rejected"
            : "unavailable");
    }

    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) return transaction_failure("unavailable");
    curl_slist* raw_headers = nullptr;
    for (const auto& header : {
             "X-API-Key: " + config_->api_key,
             std::string{"Content-Type: application/json"},
             std::string{"Accept: application/json"},
             std::string{"Expect:"},
         }) {
        auto* updated = curl_slist_append(raw_headers, header.c_str());
        if (!updated) {
            curl_slist_free_all(raw_headers);
            return transaction_failure("unavailable");
        }
        raw_headers = updated;
    }
    std::unique_ptr<curl_slist, HeaderCleanup> headers(raw_headers);

    const std::string endpoint = config_->api_url + "/api/config/v2/transaction";
    ResponseBuffer response{
        .limit = transaction_response_limit,
        .body = {},
        .exceeded = false,
    };
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, envelope.body->data());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE,
                     static_cast<curl_off_t>(envelope.body->size()));
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    if (response.exceeded) return transaction_failure("invalid-response");
    if (result != CURLE_OK) return transaction_failure("unavailable");

    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    return parse_transaction_response(
        status_code, response.body, TransactionMode::Validate, *draft.base_revision,
        draft.changes.size());
}

void SmithproxyMonitor::run(const std::stop_token stop_token) {
    std::mutex wait_mutex;
    std::condition_variable_any wakeup;
    auto next_session_sample = std::chrono::steady_clock::time_point{};
    auto next_neighbor_sample = std::chrono::steady_clock::time_point{};
    auto next_config_sample = std::chrono::steady_clock::time_point{};
    while (!stop_token.stop_requested()) {
        auto latest = ping();
        std::optional<RuntimeMetrics> sampled_metrics;
        std::optional<TlsCacheMetrics> sampled_tls_cache;
        std::optional<LiveSessions> sampled_sessions;
        std::optional<NeighborMetrics> sampled_neighbors;
        std::optional<ConfigSnapshot> sampled_config;
        std::optional<TransactionCapabilities> sampled_transaction_capabilities;
        if (latest.state == "ready") {
            const auto now = std::chrono::steady_clock::now();
            const bool sample_sessions = now >= next_session_sample;
            const bool sample_neighbors = now >= next_neighbor_sample;
            const bool sample_config = config_enabled_ && now >= next_config_sample;
            auto metrics_future = std::async(
                std::launch::async, [this] { return fetch_runtime_metrics(); });
            auto tls_cache_future = std::async(
                std::launch::async, [this] { return fetch_tls_cache_metrics(); });
            std::optional<std::future<ConfigSnapshot>> config_future;
            std::optional<std::future<TransactionCapabilities>> transaction_capabilities_future;
            std::optional<std::future<NeighborMetrics>> neighbor_future;
            if (sample_config) {
                config_future.emplace(std::async(
                    std::launch::async, [this] { return fetch_config_snapshot(); }));
                transaction_capabilities_future.emplace(std::async(
                    std::launch::async, [this] { return fetch_transaction_capabilities(); }));
            }
            if (sample_neighbors) {
                neighbor_future.emplace(std::async(
                    std::launch::async, [this] { return fetch_neighbor_metrics(); }));
            }
            if (sample_sessions) sampled_sessions = fetch_live_sessions();
            sampled_metrics = metrics_future.get();
            sampled_tls_cache = tls_cache_future.get();
            if (neighbor_future) sampled_neighbors = neighbor_future->get();
            if (config_future) sampled_config = config_future->get();
            if (transaction_capabilities_future) {
                sampled_transaction_capabilities = transaction_capabilities_future->get();
            }
            if (sample_sessions) {
                next_session_sample = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            }
            if (sample_neighbors) {
                next_neighbor_sample = std::chrono::steady_clock::now() + std::chrono::seconds(30);
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
            auto previous_neighbors = std::move(status_.neighbor_metrics);
            auto previous_config = std::move(status_.config_snapshot);
            auto previous_transaction_capabilities = std::move(status_.transaction_capabilities);
            if (latest.state == "ready") {
                latest.last_success_at = latest.checked_at;
                latest.consecutive_failures = 0U;
                auto metrics = std::move(*sampled_metrics);
                metrics.last_success_at = previous_metrics.last_success_at;
                metrics.history = std::move(previous_metrics.history);
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
                metrics.history.push_back({metrics.state, metrics.checked_at, metrics.sessions_active,
                                           metrics.bytes_up, metrics.bytes_down});
                if (metrics.history.size() > 60U) metrics.history.erase(metrics.history.begin());
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
                if (sampled_neighbors) {
                    auto neighbors = std::move(*sampled_neighbors);
                    neighbors.last_success_at = previous_neighbors.last_success_at;
                    if (neighbors.state == "ready") {
                        neighbors.last_success_at = neighbors.checked_at;
                    } else {
                        neighbors.hosts_total = previous_neighbors.hosts_total;
                        neighbors.active_today = previous_neighbors.active_today;
                        neighbors.active_week = previous_neighbors.active_week;
                        neighbors.tagged_hosts = previous_neighbors.tagged_hosts;
                        neighbors.observations = previous_neighbors.observations;
                        neighbors.bytes_up = previous_neighbors.bytes_up;
                        neighbors.bytes_down = previous_neighbors.bytes_down;
                    }
                    latest.neighbor_metrics = std::move(neighbors);
                } else {
                    latest.neighbor_metrics = std::move(previous_neighbors);
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
                        config.profiles = std::move(previous_config.profiles);
                        config.settings = std::move(previous_config.settings);
                        config.captures = std::move(previous_config.captures);
                        config.security_assets = std::move(previous_config.security_assets);
                    }
                    latest.config_snapshot = std::move(config);
                } else {
                    latest.config_snapshot = std::move(previous_config);
                }
                if (sampled_transaction_capabilities) {
                    latest.transaction_capabilities = std::move(*sampled_transaction_capabilities);
                } else {
                    latest.transaction_capabilities = std::move(previous_transaction_capabilities);
                }
            } else {
                previous_metrics.state = "unavailable";
                previous_metrics.detail = "Smithproxy runtime metrics are unavailable while the API probe is not ready";
                previous_metrics.checked_at = latest.checked_at;
                previous_metrics.history.push_back({
                    previous_metrics.state, previous_metrics.checked_at,
                    previous_metrics.sessions_active, previous_metrics.bytes_up, previous_metrics.bytes_down,
                });
                if (previous_metrics.history.size() > 60U) previous_metrics.history.erase(previous_metrics.history.begin());
                latest.runtime_metrics = std::move(previous_metrics);
                previous_tls_cache.state = "unavailable";
                previous_tls_cache.detail = "Smithproxy TLS cache is unavailable while the API probe is not ready";
                previous_tls_cache.checked_at = latest.checked_at;
                latest.tls_cache_metrics = std::move(previous_tls_cache);
                previous_sessions.state = "unavailable";
                previous_sessions.detail = "Smithproxy session activity is unavailable while the API probe is not ready";
                previous_sessions.checked_at = latest.checked_at;
                latest.live_sessions = std::move(previous_sessions);
                previous_neighbors.state = "unavailable";
                previous_neighbors.detail = "Smithproxy neighborhood is unavailable while the API probe is not ready";
                previous_neighbors.checked_at = latest.checked_at;
                latest.neighbor_metrics = std::move(previous_neighbors);
                if (config_enabled_) {
                    previous_config.state = "unavailable";
                    previous_config.detail = "Smithproxy configuration is unavailable while the API probe is not ready";
                    previous_config.checked_at = latest.checked_at;
                }
                latest.config_snapshot = std::move(previous_config);
                if (config_enabled_) {
                    previous_transaction_capabilities.state = "unavailable";
                    previous_transaction_capabilities.detail =
                        "Transaction discovery is unavailable while the Smithproxy API is not ready";
                    previous_transaction_capabilities.checked_at = latest.checked_at;
                }
                latest.transaction_capabilities = std::move(previous_transaction_capabilities);
            }
            latest.history.push_back({
                latest.state, latest.checked_at, latest.latency_ms, latest.total_probes,
            });
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

NeighborMetrics SmithproxyMonitor::fetch_neighbor_metrics() const {
    NeighborMetrics metrics;
    metrics.state = "unavailable";
    metrics.checked_at = std::chrono::system_clock::now();

    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) {
        metrics.detail = "Cannot initialize the Smithproxy neighborhood client";
        return metrics;
    }
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) {
        metrics.detail = "Cannot prepare Smithproxy neighborhood authentication";
        return metrics;
    }

    const std::string endpoint = config_->api_url + "/api/diag/proxy/neighbor/list?max_days=30";
    ResponseBuffer response{
        .limit = 2U * 1024U * 1024U,
        .body = {},
        .exceeded = false,
    };
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    metrics.checked_at = std::chrono::system_clock::now();
    if (response.exceeded) {
        metrics.detail = "Smithproxy neighborhood exceeded the response limit";
        return metrics;
    }
    if (result != CURLE_OK) {
        metrics.detail = std::string("Cannot retrieve Smithproxy neighborhood: ") +
                         curl_easy_strerror(result);
        return metrics;
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code != 200L) {
        metrics.detail = "Smithproxy neighborhood returned HTTP " + std::to_string(status_code);
        return metrics;
    }
    auto parsed = parse_neighbor_metrics(response.body);
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

TransactionCapabilities SmithproxyMonitor::fetch_transaction_capabilities() const {
    TransactionCapabilities capabilities{
        .state = "unavailable",
        .detail = "Smithproxy transaction capability discovery is unavailable",
        .checked_at = std::chrono::system_clock::now(),
        .maximum_operations = 0U,
        .maximum_request_bytes = 0U,
        .operations = {},
        .collections = {},
    };
    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) return capabilities;

    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) return capabilities;

    const std::string endpoint = config_->api_url + "/api/config/v2/capabilities";
    ResponseBuffer response;
    configure_request(curl.get(), *config_, endpoint, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, collect_body);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    const auto result = curl_easy_perform(curl.get());
    capabilities.checked_at = std::chrono::system_clock::now();
    if (response.exceeded) {
        capabilities.state = "incompatible";
        capabilities.detail = "Smithproxy transaction capabilities exceeded the response limit";
        return capabilities;
    }
    if (result != CURLE_OK) return capabilities;

    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code == 404L) {
        capabilities.state = "not-advertised";
        capabilities.detail = "Smithproxy does not advertise atomic configuration transactions";
        return capabilities;
    }
    if (status_code != 200L) return capabilities;

    return parse_transaction_capabilities(response.body, reviewed_transaction_schemas());
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

    const std::array profile_categories{
        std::pair{"detection_profiles", "detection"},
        std::pair{"content_profiles", "content"},
        std::pair{"tls_profiles", "tls"},
        std::pair{"ssh_profiles", "ssh"},
        std::pair{"alg_dns_profiles", "dns"},
        std::pair{"script_profiles", "script"},
        std::pair{"auth_profiles", "authentication"},
        std::pair{"routing", "routing"},
    };
    constexpr std::array section_names{
        "policy", "address_objects", "port_objects", "proto_objects", "settings", "debug",
        "captures", "tls_ca", "starttls_signatures", "detection_signatures",
        "detection_profiles", "content_profiles", "tls_profiles", "ssh_profiles",
        "alg_dns_profiles", "script_profiles", "auth_profiles", "routing",
    };
    constexpr std::size_t maximum_parallel_requests = 4U;
    std::array<SectionResponse, section_names.size()> responses;
    std::array<std::future<void>, maximum_parallel_requests> workers;
    for (std::size_t worker = 0; worker < workers.size(); ++worker) {
        workers[worker] = std::async(std::launch::async, [&, worker] {
            for (std::size_t index = worker; index < section_names.size(); index += workers.size()) {
                responses[index] = fetch_section(section_names[index]);
            }
        });
    }
    for (auto& worker : workers) worker.get();
    snapshot.checked_at = std::chrono::system_clock::now();

    for (const auto& response : responses) {
        if (!response.body) {
            snapshot.detail = response.error;
            return snapshot;
        }
    }
    const auto& policies = responses[0];
    const auto& addresses = responses[1];
    const auto& ports = responses[2];
    const auto& protocols = responses[3];
    const auto& settings = responses[4];
    const auto& debug = responses[5];
    const auto& captures = responses[6];
    const auto& authorities = responses[7];
    const auto& starttls = responses[8];
    const auto& detection_signatures = responses[9];
    auto parsed = parse_config_snapshot(
        *policies.body, *addresses.body, *ports.body, *protocols.body);
    if (!parsed.snapshot) {
        snapshot.detail = std::move(parsed.error);
        return snapshot;
    }
    auto parsed_settings = parse_config_settings(*settings.body);
    if (!parsed_settings.settings) {
        snapshot.detail = std::move(parsed_settings.error);
        return snapshot;
    }
    parsed.snapshot->settings = std::move(parsed_settings.settings);
    auto parsed_debug = parse_config_debug(*debug.body);
    if (!parsed_debug.debug) {
        snapshot.detail = std::move(parsed_debug.error);
        return snapshot;
    }
    parsed.snapshot->debug = std::move(parsed_debug.debug);
    auto parsed_captures = parse_config_captures(*captures.body);
    if (!parsed_captures.captures) {
        snapshot.detail = std::move(parsed_captures.error);
        return snapshot;
    }
    parsed.snapshot->captures = std::move(parsed_captures.captures);
    auto parsed_security_assets = parse_config_security_assets(
        *authorities.body, *starttls.body, *detection_signatures.body);
    if (!parsed_security_assets.security_assets) {
        snapshot.detail = std::move(parsed_security_assets.error);
        return snapshot;
    }
    parsed.snapshot->security_assets = std::move(parsed_security_assets.security_assets);
    for (std::size_t index = 0; index < profile_categories.size(); ++index) {
        const auto& response = responses[index + 10U];
        const auto& [section, type] = profile_categories[index];
        auto profiles = parse_config_profiles(*response.body, section, type);
        if (!profiles.profiles) {
            snapshot.detail = std::move(profiles.error);
            return snapshot;
        }
        parsed.snapshot->profiles.insert(
            parsed.snapshot->profiles.end(),
            std::make_move_iterator(profiles.profiles->begin()),
            std::make_move_iterator(profiles.profiles->end()));
    }
    parsed.snapshot->checked_at = snapshot.checked_at;
    return std::move(*parsed.snapshot);
}

} // namespace smithproxy::gui
