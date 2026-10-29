#pragma once

#include "config.hpp"
#include "config_snapshot.hpp"
#include "interface_metrics.hpp"
#include "live_sessions.hpp"
#include "neighbor_metrics.hpp"
#include "runtime_metrics.hpp"
#include "tls_metrics.hpp"
#include "transaction_capabilities.hpp"
#include "transaction_envelope.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace smithproxy::gui {

struct ProbeSample {
    std::string state;
    std::chrono::system_clock::time_point checked_at{};
    std::optional<std::uint64_t> latency_ms;
    std::uint64_t sequence{};
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
    TlsCacheMetrics tls_cache_metrics;
    LiveSessions live_sessions;
    NeighborMetrics neighbor_metrics;
    InterfaceMetrics interface_metrics;
    ConfigSnapshot config_snapshot;
    TransactionCapabilities transaction_capabilities;
};

class SmithproxyMonitor {
public:
    explicit SmithproxyMonitor(std::optional<SmithproxyConfig> config, bool config_enabled = false);
    ~SmithproxyMonitor();

    SmithproxyMonitor(const SmithproxyMonitor&) = delete;
    SmithproxyMonitor& operator=(const SmithproxyMonitor&) = delete;

    void start();
    void stop();
    [[nodiscard]] SmithproxyStatus status() const;
    [[nodiscard]] TransactionResponse validate_transaction(const DraftSnapshot& draft) const;
    [[nodiscard]] TransactionResponse commit_transaction(
        const DraftSnapshot& draft, std::string_view idempotency_key) const;
    [[nodiscard]] bool note_config_committed(std::string_view committed_revision);
    [[nodiscard]] bool configured() const noexcept { return config_.has_value(); }
    [[nodiscard]] bool config_enabled() const noexcept { return config_enabled_; }

private:
    void run(std::stop_token stop_token);
    SmithproxyStatus ping() const;
    RuntimeMetrics fetch_runtime_metrics() const;
    TlsCacheMetrics fetch_tls_cache_metrics() const;
    LiveSessions fetch_live_sessions() const;
    NeighborMetrics fetch_neighbor_metrics() const;
    InterfaceMetrics fetch_interface_metrics() const;
    ConfigSnapshot fetch_config_snapshot() const;
    TransactionCapabilities fetch_transaction_capabilities() const;
    TransactionResponse execute_transaction(
        const DraftSnapshot& draft, TransactionMode mode,
        std::string_view idempotency_key) const;

    std::optional<SmithproxyConfig> config_;
    bool config_enabled_{};
    mutable std::mutex mutex_;
    SmithproxyStatus status_;
    std::atomic_bool config_refresh_requested_{};
    std::chrono::steady_clock::time_point minimum_config_observation_{};
    mutable std::mutex wakeup_mutex_;
    std::condition_variable_any wakeup_;
    std::jthread worker_;
};

} // namespace smithproxy::gui
