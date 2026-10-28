#include "smithproxy_client.hpp"

#include <curl/curl.h>

#include <condition_variable>
#include <memory>

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
        {
            std::scoped_lock lock(mutex_);
            latest.total_probes = status_.total_probes + 1U;
            latest.last_success_at = status_.last_success_at;
            latest.consecutive_failures = status_.consecutive_failures + 1U;
            latest.history = std::move(status_.history);
            if (latest.state == "ready") {
                latest.last_success_at = latest.checked_at;
                latest.consecutive_failures = 0U;
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

    curl_easy_setopt(curl.get(), CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers.get());
    curl_easy_setopt(curl.get(), CURLOPT_CAINFO, config_->ca_cert.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl.get(), CURLOPT_PROXY, "");
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, 1500L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, 2500L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
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

} // namespace smithproxy::gui
