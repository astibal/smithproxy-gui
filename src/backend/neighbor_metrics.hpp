#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct NeighborSample {
    std::uint64_t relative_days{};
    std::uint64_t observations{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
    std::vector<std::string> labels;
};

struct NeighborEntry {
    std::string hostname;
    std::string tags;
    std::uint64_t last_seen{};
    std::vector<NeighborSample> samples;
};

struct NeighborMetrics {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy neighborhood metrics are not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::uint64_t hosts_total{};
    std::uint64_t active_today{};
    std::uint64_t active_week{};
    std::uint64_t tagged_hosts{};
    std::uint64_t observations{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
    std::vector<NeighborEntry> entries;
};

struct NeighborMetricsParseResult {
    std::optional<NeighborMetrics> metrics;
    std::string error;
};

NeighborMetricsParseResult parse_neighbor_metrics(std::string_view payload);

} // namespace smithproxy::gui
