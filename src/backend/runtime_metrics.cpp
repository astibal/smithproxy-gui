#include "runtime_metrics.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <unordered_set>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_listeners = 32U;
constexpr std::size_t maximum_name_length = 64U;

bool valid_counter(const nlohmann::json& value) {
    return value.is_number_unsigned() ||
           (value.is_number_integer() && value.get<std::int64_t>() >= 0);
}

std::optional<std::uint64_t> counter(const nlohmann::json& object, const char* name) {
    const auto iterator = object.find(name);
    if (iterator == object.end() || !valid_counter(*iterator)) return std::nullopt;
    return iterator->get<std::uint64_t>();
}

void saturating_add(std::uint64_t& target, const std::uint64_t value) {
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    target = value > maximum - target ? maximum : target + value;
}

} // namespace

ListenerMetricsParseResult parse_listener_metrics(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) {
        return {std::nullopt, "Smithproxy returned malformed listener metrics"};
    }
    const auto iterator = document.find("listeners");
    if (iterator == document.end() || !iterator->is_array() || iterator->size() > maximum_listeners) {
        return {std::nullopt, "Smithproxy returned an invalid listener collection"};
    }

    RuntimeMetrics result;
    result.state = "ready";
    result.detail = "Smithproxy listener metrics are current";
    result.listeners.reserve(iterator->size());
    std::unordered_set<std::string> names;
    for (const auto& item : *iterator) {
        if (!item.is_object()) return {std::nullopt, "Smithproxy returned an invalid listener entry"};
        const auto name = item.find("name");
        if (name == item.end() || !name->is_string()) {
            return {std::nullopt, "Smithproxy listener name is missing"};
        }
        const auto name_value = name->get<std::string>();
        if (name_value.empty() || name_value.size() > maximum_name_length) {
            return {std::nullopt, "Smithproxy listener name is invalid"};
        }
        if (!names.insert(name_value).second) {
            return {std::nullopt, "Smithproxy listener names are not unique"};
        }
        const auto workers = counter(item, "workers");
        const auto sessions_total = counter(item, "sessions_total");
        const auto sessions_active = counter(item, "sessions_active");
        const auto bytes_up = counter(item, "bytes_up");
        const auto bytes_down = counter(item, "bytes_down");
        if (!workers || !sessions_total || !sessions_active || !bytes_up || !bytes_down ||
            *sessions_active > *sessions_total) {
            return {std::nullopt, "Smithproxy listener counters are invalid"};
        }
        ListenerMetrics listener{name_value, *workers, *sessions_total, *sessions_active,
                                 *bytes_up, *bytes_down};
        saturating_add(result.workers, listener.workers);
        saturating_add(result.sessions_total, listener.sessions_total);
        saturating_add(result.sessions_active, listener.sessions_active);
        saturating_add(result.bytes_up, listener.bytes_up);
        saturating_add(result.bytes_down, listener.bytes_down);
        result.listeners.push_back(std::move(listener));
    }
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
