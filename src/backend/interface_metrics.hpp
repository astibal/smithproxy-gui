#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

struct InterfaceMetrics {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy interface monitoring is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::chrono::system_clock::time_point sampled_at{};
    std::uint64_t generation{};
    bool synchronization_running{};
    std::uint64_t synchronization_attempts{};
    std::uint64_t synchronization_successes{};
    std::uint64_t synchronization_errors{};
    std::uint64_t event_datagrams{};
    std::uint64_t changed_event_datagrams{};
    std::uint64_t interfaces{};
    std::uint64_t addresses{};
    std::uint64_t ipv4_addresses{};
    std::uint64_t ipv6_addresses{};
    std::optional<std::string> last_error;
};

struct InterfaceMetricsParseResult {
    std::optional<InterfaceMetrics> metrics;
    std::string error;
};

InterfaceMetricsParseResult parse_interface_metrics(std::string_view payload);

} // namespace smithproxy::gui
