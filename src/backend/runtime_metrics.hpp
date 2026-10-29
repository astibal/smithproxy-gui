#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct ListenerMetrics {
    std::string name;
    std::uint64_t workers{};
    std::uint64_t sessions_total{};
    std::uint64_t sessions_active{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
};

struct RuntimeMetricsSample {
    std::string state;
    std::chrono::system_clock::time_point checked_at{};
    std::uint64_t sessions_active{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
};

struct RuntimeMetrics {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy runtime metrics are not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::uint64_t workers{};
    std::uint64_t sessions_total{};
    std::uint64_t sessions_active{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
    std::vector<ListenerMetrics> listeners;
    std::vector<RuntimeMetricsSample> history;
};

struct ListenerMetricsParseResult {
    std::optional<RuntimeMetrics> metrics;
    std::string error;
};

ListenerMetricsParseResult parse_listener_metrics(std::string_view payload);

} // namespace smithproxy::gui
