#include "live_sessions.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>
#include <unordered_map>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_upstream_sessions = 2048U;
constexpr std::size_t maximum_protocols = 32U;

std::optional<std::uint64_t> counter(const nlohmann::json& object, const char* name) {
    const auto iterator = object.find(name);
    if (iterator == object.end()) return std::nullopt;
    if (iterator->is_number_unsigned()) return iterator->get<std::uint64_t>();
    if (iterator->is_number_integer()) {
        const auto value = iterator->get<std::int64_t>();
        if (value >= 0) return static_cast<std::uint64_t>(value);
    }
    return std::nullopt;
}

std::optional<std::string> protocol(const nlohmann::json& session) {
    for (const auto* side : {"left", "right"}) {
        const auto collection = session.find(side);
        if (collection == session.end() || !collection->is_array() || collection->empty() ||
            !collection->front().is_object()) {
            continue;
        }
        const auto value = collection->front().find("com");
        if (value == collection->front().end() || !value->is_string()) continue;
        auto result = value->get<std::string>();
        if (result.empty() || result.size() > 32U) return std::nullopt;
        if (result != "none" && result != "unknown") return result;
    }
    return std::string{"unknown"};
}

void saturating_add(std::uint64_t& target, const std::uint64_t value) {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    target = value > maximum - target ? maximum : target + value;
}

} // namespace

LiveSessionsParseResult parse_live_sessions(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_array() ||
        document.size() > maximum_upstream_sessions) {
        return {std::nullopt, "Smithproxy returned an invalid session activity collection"};
    }

    LiveSessions result;
    result.state = "ready";
    result.detail = "Smithproxy session activity is current";
    result.total = static_cast<std::uint64_t>(document.size());
    std::unordered_map<std::string, std::size_t> buckets;

    for (const auto& item : document) {
        if (!item.is_object()) {
            return {std::nullopt, "Smithproxy returned an invalid session activity entry"};
        }
        const auto transport = protocol(item);
        const auto stats = item.find("stats");
        if (!transport || stats == item.end() || !stats->is_object()) {
            return {std::nullopt, "Smithproxy session activity is invalid"};
        }
        const auto speed = stats->find("speed");
        const auto counters = stats->find("counters");
        if (speed == stats->end() || !speed->is_object() || counters == stats->end() ||
            !counters->is_object()) {
            return {std::nullopt, "Smithproxy session activity statistics are invalid"};
        }
        const auto speed_up = counter(*speed, "up");
        const auto speed_down = counter(*speed, "down");
        const auto bytes_up = counter(*counters, "bytes_up");
        const auto bytes_down = counter(*counters, "bytes_down");
        if (!speed_up || !speed_down || !bytes_up || !bytes_down) {
            return {std::nullopt, "Smithproxy session activity counters are invalid"};
        }

        auto [iterator, inserted] = buckets.emplace(*transport, result.protocols.size());
        if (inserted) {
            if (result.protocols.size() >= maximum_protocols) {
                return {std::nullopt, "Smithproxy returned too many session protocols"};
            }
            result.protocols.push_back({*transport});
        }
        auto& bucket = result.protocols[iterator->second];
        saturating_add(bucket.sessions, 1U);
        saturating_add(bucket.speed_up, *speed_up);
        saturating_add(bucket.speed_down, *speed_down);
        saturating_add(bucket.bytes_up, *bytes_up);
        saturating_add(bucket.bytes_down, *bytes_down);
        saturating_add(result.speed_up, *speed_up);
        saturating_add(result.speed_down, *speed_down);
    }

    std::ranges::sort(result.protocols, {}, &SessionActivityBucket::protocol);
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
