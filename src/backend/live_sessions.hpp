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

// One administrator-facing connection snapshot. The GUI core deliberately
// keeps this model smaller than Smithproxy's diagnostic payload so internal
// worker names and protocol implementation details never cross the API.
struct LiveSessionEntry {
    std::string id;
    std::string source_address;
    std::string source_port;
    std::string destination_address;
    std::string destination_port;
    std::string protocol;
    std::string policy;
    std::uint64_t speed_up{};
    std::uint64_t speed_down{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
    bool active{true};
    std::chrono::system_clock::time_point first_seen_at{};
    std::chrono::system_clock::time_point last_seen_at{};
    std::optional<std::chrono::system_clock::time_point> closed_at;
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
    std::vector<LiveSessionEntry> entries;
};

struct LiveSessionsParseResult {
    std::optional<LiveSessions> snapshot;
    std::string error;
};

LiveSessionsParseResult parse_live_sessions(std::string_view payload);

// Preserve first-seen timestamps and retain recently closed connections long
// enough for an administrator to notice short sessions between GUI refreshes.
void reconcile_live_sessions(
    LiveSessions& current, const LiveSessions& previous,
    std::chrono::system_clock::time_point observed_at);

} // namespace smithproxy::gui
