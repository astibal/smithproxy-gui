#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct SessionActivityBucket {
    std::string protocol;
    std::uint64_t sessions{};
    std::uint64_t speed_up{};
    std::uint64_t speed_down{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
};

struct LiveSessions {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy session activity is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::uint64_t total{};
    std::uint64_t speed_up{};
    std::uint64_t speed_down{};
    std::vector<SessionActivityBucket> protocols;
};

struct LiveSessionsParseResult {
    std::optional<LiveSessions> snapshot;
    std::string error;
};

LiveSessionsParseResult parse_live_sessions(std::string_view payload);

} // namespace smithproxy::gui
