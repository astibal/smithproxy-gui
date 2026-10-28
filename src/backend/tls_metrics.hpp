#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

struct TlsCacheMetrics {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy TLS cache metrics are not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::uint64_t size{};
    std::uint64_t capacity{};
};

struct TlsCacheMetricsParseResult {
    std::optional<TlsCacheMetrics> metrics;
    std::string error;
};

TlsCacheMetricsParseResult parse_tls_cache_metrics(std::string_view payload);

} // namespace smithproxy::gui
