#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct InterfaceAddressMetrics {
    std::string family;
    std::string address;
    std::uint64_t prefix_length{};
    std::uint64_t scope{};
    std::uint64_t flags{};
};

struct InterfaceInventoryMetrics {
    std::uint64_t index{};
    std::string name;
    std::string role;
    std::uint64_t flags{};
    bool uplink{};
    std::vector<InterfaceAddressMetrics> addresses;
};

struct InterfaceMetrics {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy interface monitoring is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::chrono::system_clock::time_point sampled_at{};
    std::uint64_t generation{};
    bool snapshot_valid{};
    bool roles_valid{};
    std::uint64_t route_generation{};
    std::uint64_t role_generation{};
    std::optional<std::string> route_changed_at;
    std::optional<std::string> role_changed_at;
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
    std::vector<InterfaceInventoryMetrics> inventory;
    std::optional<std::string> last_error;
    std::optional<std::string> last_error_detail;
};

struct InterfaceMetricsParseResult {
    std::optional<InterfaceMetrics> metrics;
    std::string error;
};

InterfaceMetricsParseResult parse_interface_metrics(std::string_view payload);

} // namespace smithproxy::gui
