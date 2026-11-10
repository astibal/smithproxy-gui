#include "live_sessions.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_upstream_sessions = 2048U;
constexpr std::size_t maximum_protocols = 32U;
constexpr std::size_t maximum_classifications = 16U;
constexpr std::size_t maximum_retained_sessions = 512U;
constexpr auto closed_session_retention = std::chrono::minutes(5);

std::optional<std::string> bounded_text(
    const nlohmann::json& object, const char* name, const std::size_t maximum_length,
    const bool allow_empty = false) {
    const auto iterator = object.find(name);
    if (iterator == object.end() || !iterator->is_string()) return std::nullopt;
    auto value = iterator->get<std::string>();
    if ((!allow_empty && value.empty()) || value.size() > maximum_length ||
        std::ranges::any_of(value, [](const unsigned char character) {
            return std::iscntrl(character) != 0;
        })) {
        return std::nullopt;
    }
    return value;
}

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

struct Endpoint {
    std::string address;
    std::string port;
};

std::optional<Endpoint> endpoint(const nlohmann::json& session, const char* side) {
    const auto collection = session.find(side);
    if (collection == session.end() || !collection->is_array() || collection->empty() ||
        !collection->front().is_object()) {
        return std::nullopt;
    }
    const auto address = bounded_text(collection->front(), "host", 255U);
    const auto port = bounded_text(collection->front(), "port", 16U);
    if (!address || !port) return std::nullopt;
    return Endpoint{*address, *port};
}

std::optional<std::string> policy(const nlohmann::json& session) {
    const auto iterator = session.find("policy");
    if (iterator == session.end()) return std::string{"Unmatched"};
    if (iterator->is_string()) {
        auto value = iterator->get<std::string>();
        if (value.empty()) return std::string{"Unmatched"};
        if (value.size() > 128U || std::ranges::any_of(value, [](const unsigned char character) {
                return std::iscntrl(character) != 0;
            })) {
            return std::nullopt;
        }
        return value;
    }
    if (iterator->is_number_unsigned()) return std::to_string(iterator->get<std::uint64_t>());
    if (iterator->is_number_integer()) return std::to_string(iterator->get<std::int64_t>());
    return std::nullopt;
}

struct SessionClassifications {
    std::vector<std::string> sift;
    std::vector<std::string> lored;
    std::string lored_status;
};

// Smithproxy classification output is useful to administrators, but remains
// untrusted diagnostic data. Accept only small printable string collections
// and never forward the rest of the upstream classification object.
std::optional<SessionClassifications> classifications(const nlohmann::json& session) {
    const auto classification = session.find("classification");
    if (classification == session.end()) return SessionClassifications{};
    if (!classification->is_object()) return std::nullopt;

    const auto read_list = [&](const char* name) -> std::optional<std::vector<std::string>> {
        const auto values = classification->find(name);
        if (values == classification->end()) return std::vector<std::string>{};
        if (!values->is_array() || values->size() > maximum_classifications) return std::nullopt;
        std::vector<std::string> result;
        result.reserve(values->size());
        std::unordered_set<std::string> unique;
        for (const auto& value : *values) {
            if (!value.is_string()) return std::nullopt;
            const auto text = value.get<std::string>();
            if (text.empty() || text.size() > 128U ||
                std::ranges::any_of(text, [](const unsigned char character) {
                    return std::iscntrl(character) != 0;
                }) || !unique.insert(text).second) {
                return std::nullopt;
            }
            result.push_back(text);
        }
        return result;
    };

    auto sift = read_list("sift");
    auto lored = read_list("lored");
    if (!sift || !lored) return std::nullopt;
    std::string status;
    if (classification->contains("lored_status")) {
        auto parsed = bounded_text(*classification, "lored_status", 128U, true);
        if (!parsed) return std::nullopt;
        status = std::move(*parsed);
    }
    return SessionClassifications{std::move(*sift), std::move(*lored), std::move(status)};
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
    std::unordered_set<std::string> identifiers;

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
        const auto id = bounded_text(item, "oid", 128U);
        const auto source = endpoint(item, "left");
        const auto destination = endpoint(item, "right");
        const auto matched_policy = policy(item);
        const auto classified = classifications(item);
        if (!speed_up || !speed_down || !bytes_up || !bytes_down || !id || !source ||
            !destination || !matched_policy || !classified) {
            return {std::nullopt, "Smithproxy session activity entry is invalid"};
        }
        if (!identifiers.insert(*id).second) {
            return {std::nullopt, "Smithproxy returned a duplicate session identifier"};
        }

        result.entries.push_back({
            .id = *id,
            .source_address = source->address,
            .source_port = source->port,
            .destination_address = destination->address,
            .destination_port = destination->port,
            .protocol = *transport,
            .policy = *matched_policy,
            .sift_classifications = classified->sift,
            .lored_classifications = classified->lored,
            .lored_status = classified->lored_status,
            .speed_up = *speed_up,
            .speed_down = *speed_down,
            .bytes_up = *bytes_up,
            .bytes_down = *bytes_down,
            .active = true,
            .first_seen_at = {},
            .last_seen_at = {},
            .closed_at = std::nullopt,
        });

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
    std::ranges::sort(result.entries, {}, &LiveSessionEntry::id);
    return {std::move(result), {}};
}

void reconcile_live_sessions(
    LiveSessions& current, const LiveSessions& previous,
    const std::chrono::system_clock::time_point observed_at) {
    std::unordered_map<std::string, const LiveSessionEntry*> previous_by_id;
    previous_by_id.reserve(previous.entries.size());
    for (const auto& entry : previous.entries) previous_by_id.emplace(entry.id, &entry);

    std::unordered_set<std::string> active_ids;
    active_ids.reserve(current.entries.size());
    for (auto& entry : current.entries) {
        active_ids.insert(entry.id);
        entry.active = true;
        entry.last_seen_at = observed_at;
        entry.closed_at.reset();
        const auto previous_entry = previous_by_id.find(entry.id);
        entry.first_seen_at = previous_entry == previous_by_id.end()
            ? observed_at : previous_entry->second->first_seen_at;
    }

    // A session missing from a successful poll has closed. Keep its last known
    // counters for a short bounded window; failed polls never call this helper.
    for (const auto& entry : previous.entries) {
        if (active_ids.contains(entry.id)) continue;
        auto retained = entry;
        retained.active = false;
        if (!retained.closed_at) retained.closed_at = observed_at;
        if (*retained.closed_at <= observed_at &&
            observed_at - *retained.closed_at <= closed_session_retention) {
            current.entries.push_back(std::move(retained));
        }
    }

    std::ranges::sort(current.entries, [](const auto& left, const auto& right) {
        if (left.active != right.active) return left.active > right.active;
        return left.last_seen_at > right.last_seen_at;
    });
    if (current.entries.size() > maximum_retained_sessions) {
        current.entries.resize(maximum_retained_sessions);
    }
}

} // namespace smithproxy::gui
