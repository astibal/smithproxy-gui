#pragma once

#include "config.hpp"
#include "runtime_metrics.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace smithproxy::gui {

struct ProbeSample {
    std::string state;
    std::chrono::system_clock::time_point checked_at{};
    std::optional<std::uint64_t> latency_ms;
};

struct SmithproxyStatus {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy environment is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::optional<std::uint64_t> latency_ms;
    std::uint64_t total_probes{};
    std::uint64_t consecutive_failures{};
    std::vector<ProbeSample> history;
    RuntimeMetrics runtime_metrics;
};

class SmithproxyMonitor {
public:
    explicit SmithproxyMonitor(std::optional<SmithproxyConfig> config);
    ~SmithproxyMonitor();

    SmithproxyMonitor(const SmithproxyMonitor&) = delete;
    SmithproxyMonitor& operator=(const SmithproxyMonitor&) = delete;

    void start();
    void stop();
    [[nodiscard]] SmithproxyStatus status() const;
    [[nodiscard]] bool configured() const noexcept { return config_.has_value(); }

private:
    void run(std::stop_token stop_token);
    SmithproxyStatus ping() const;
    RuntimeMetrics fetch_runtime_metrics() const;

    std::optional<SmithproxyConfig> config_;
    mutable std::mutex mutex_;
    SmithproxyStatus status_;
    std::jthread worker_;
};

} // namespace smithproxy::gui
