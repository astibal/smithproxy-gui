#include "neighbor_metrics.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <unordered_set>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_neighbors = 4096U;
constexpr std::size_t maximum_days = 30U;
constexpr std::size_t maximum_hostname_length = 253U;
constexpr std::size_t maximum_tags_length = 2048U;

std::optional<std::uint64_t> counter(const nlohmann::json& object, const char* name) {
    const auto value = object.find(name);
    if (value == object.end()) return std::nullopt;
    if (value->is_number_unsigned()) return value->get<std::uint64_t>();
    if (value->is_number_integer()) {
        const auto signed_value = value->get<std::int64_t>();
        if (signed_value >= 0) return static_cast<std::uint64_t>(signed_value);
    }
    return std::nullopt;
}

void saturating_add(std::uint64_t& target, const std::uint64_t value) {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    target = value > maximum - target ? maximum : target + value;
}

bool safe_text(const std::string& value, const std::size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    for (const unsigned char character : value) {
        if (character < 0x20U || character == 0x7fU) return false;
    }
    return true;
}

} // namespace

NeighborMetricsParseResult parse_neighbor_metrics(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_array() || document.size() > maximum_neighbors) {
        return {std::nullopt, "Smithproxy returned an invalid neighborhood collection"};
    }

    NeighborMetrics result;
    result.state = "ready";
    result.detail = "Smithproxy neighborhood aggregates are current";
    std::unordered_set<std::string> hostnames;
    hostnames.reserve(document.size());
    for (const auto& neighbor : document) {
        if (!neighbor.is_object()) {
            return {std::nullopt, "Smithproxy returned an invalid neighborhood entry"};
        }
        const auto hostname = neighbor.find("hostname");
        const auto tags = neighbor.find("tags");
        const auto stats = neighbor.find("stats");
        const auto last_seen = counter(neighbor, "last_seen");
        if (hostname == neighbor.end() || !hostname->is_string() ||
            tags == neighbor.end() || !tags->is_string() ||
            stats == neighbor.end() || !stats->is_array() || stats->size() > maximum_days ||
            !last_seen) {
            return {std::nullopt, "Smithproxy neighborhood fields are invalid"};
        }
        const auto hostname_value = hostname->get<std::string>();
        const auto tags_value = tags->get<std::string>();
        if (!safe_text(hostname_value, maximum_hostname_length) ||
            tags_value.size() > maximum_tags_length ||
            (!tags_value.empty() && !safe_text(tags_value, maximum_tags_length)) ||
            !hostnames.insert(hostname_value).second) {
            return {std::nullopt, "Smithproxy neighborhood identity is invalid"};
        }

        bool active_today = false;
        bool active_week = false;
        for (const auto& sample : *stats) {
            if (!sample.is_object()) {
                return {std::nullopt, "Smithproxy neighborhood sample is invalid"};
            }
            const auto relative_days = counter(sample, "relative_days");
            const auto observations = counter(sample, "counter");
            const auto bytes_up = counter(sample, "bytes_up");
            const auto bytes_down = counter(sample, "bytes_down");
            if (!relative_days || *relative_days > maximum_days || !observations ||
                !bytes_up || !bytes_down) {
                return {std::nullopt, "Smithproxy neighborhood counters are invalid"};
            }
            active_today = active_today || *relative_days == 0U;
            active_week = active_week || *relative_days <= 6U;
            saturating_add(result.observations, *observations);
            saturating_add(result.bytes_up, *bytes_up);
            saturating_add(result.bytes_down, *bytes_down);
        }
        result.hosts_total += 1U;
        if (active_today) result.active_today += 1U;
        if (active_week) result.active_week += 1U;
        if (!tags_value.empty()) result.tagged_hosts += 1U;
    }
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
