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

} // namespace

SmithproxyMonitor::SmithproxyMonitor(std::optional<SmithproxyConfig> config)
    : config_(std::move(config)) {
    if (config_) status_ = {"starting", "Waiting for the first Smithproxy probe", {}};
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
            status_ = std::move(latest);
        }
        std::unique_lock lock(wait_mutex);
        wakeup.wait_for(lock, stop_token, std::chrono::seconds(5), [] { return false; });
    }
}

SmithproxyStatus SmithproxyMonitor::ping() const {
    std::unique_ptr<CURL, CurlCleanup> curl(curl_easy_init());
    if (!curl) return {"error", "Cannot initialize the Smithproxy HTTP client", std::chrono::system_clock::now()};

    const std::string endpoint = config_->api_url + "/api/status/ping";
    std::unique_ptr<curl_slist, HeaderCleanup> headers;
    headers.reset(curl_slist_append(nullptr, ("X-API-Key: " + config_->api_key).c_str()));
    if (!headers) return {"error", "Cannot prepare Smithproxy authentication", std::chrono::system_clock::now()};

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
        return {"unreachable", curl_easy_strerror(result), std::chrono::system_clock::now()};
    }
    long status_code{};
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (status_code == 200L) return {"ready", "Smithproxy API accepted the bootstrap credential", std::chrono::system_clock::now()};
    if (status_code == 401L || status_code == 403L) {
        return {"unauthorized", "Smithproxy API rejected the bootstrap credential", std::chrono::system_clock::now()};
    }
    return {"error", "Smithproxy API returned HTTP " + std::to_string(status_code), std::chrono::system_clock::now()};
}

} // namespace smithproxy::gui
