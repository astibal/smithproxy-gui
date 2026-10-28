#include "smithproxy_client.hpp"

#include <curl/curl.h>

#include <condition_variable>
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
    static constexpr std::size_t limit = 256U * 1024U;
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
    if (bytes > ResponseBuffer::limit - response.body.size()) {
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

SmithproxyMonitor::SmithproxyMonitor(std::optional<SmithproxyConfig> config)
    : config_(std::move(config)) {
    if (config_) {
        status_.state = "starting";
        status_.detail = "Waiting for the first Smithproxy probe";
        status_.runtime_metrics.state = "starting";
        status_.runtime_metrics.detail = "Waiting for the first Smithproxy metrics sample";
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
    while (!stop_token.stop_requested()) {
        auto latest = ping();
        std::optional<RuntimeMetrics> sampled_metrics;
        if (latest.state == "ready") sampled_metrics = fetch_runtime_metrics();
        {
            std::scoped_lock lock(mutex_);
            latest.total_probes = status_.total_probes + 1U;
            latest.last_success_at = status_.last_success_at;
            latest.consecutive_failures = status_.consecutive_failures + 1U;
            latest.history = std::move(status_.history);
            auto previous_metrics = std::move(status_.runtime_metrics);
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
            } else {
                previous_metrics.state = "unavailable";
                previous_metrics.detail = "Smithproxy runtime metrics are unavailable while the API probe is not ready";
                previous_metrics.checked_at = latest.checked_at;
                latest.runtime_metrics = std::move(previous_metrics);
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

} // namespace smithproxy::gui
