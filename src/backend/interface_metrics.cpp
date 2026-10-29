#include "interface_metrics.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>

namespace smithproxy::gui {
namespace {

constexpr std::uint64_t maximum_json_integer = 9'007'199'254'740'991ULL;
constexpr std::size_t maximum_error_code_length = 64U;

std::optional<std::uint64_t> counter(const nlohmann::json& object, const char* name) {
    const auto value = object.find(name);
    if (value == object.end()) return std::nullopt;
    std::uint64_t result{};
    if (value->is_number_unsigned()) {
        result = value->get<std::uint64_t>();
    } else if (value->is_number_integer()) {
        const auto signed_value = value->get<std::int64_t>();
        if (signed_value < 0) return std::nullopt;
        result = static_cast<std::uint64_t>(signed_value);
    } else {
        return std::nullopt;
    }
    return result <= maximum_json_integer ? std::optional{result} : std::nullopt;
}

bool stable_error_code(const std::string& value) {
    if (value.empty() || value.size() > maximum_error_code_length ||
        value.front() < 'a' || value.front() > 'z') {
        return false;
    }
    for (const unsigned char character : value) {
        const bool accepted = (character >= 'a' && character <= 'z') ||
                              (character >= '0' && character <= '9') ||
                              character == '.' || character == '_' || character == '-';
        if (!accepted) return false;
    }
    return true;
}

} // namespace

InterfaceMetricsParseResult parse_interface_metrics(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object() || document.size() != 7U) {
        return {std::nullopt, "Smithproxy returned an invalid interface summary"};
    }
    const auto schema_version = counter(document, "schema_version");
    if (!schema_version || *schema_version != 1U || !document.contains("state") ||
        !document["state"].is_string() || !document.contains("synchronization") ||
        !document["synchronization"].is_object() || !document.contains("totals") ||
        !document["totals"].is_object() || !document.contains("last_error")) {
        return {std::nullopt, "Smithproxy returned an invalid interface summary"};
    }
    const auto state = document["state"].get<std::string>();
    constexpr std::array states{"starting", "ready", "degraded", "unavailable"};
    if (std::find(states.begin(), states.end(), state) == states.end()) {
        return {std::nullopt, "Smithproxy returned an invalid interface state"};
    }
    const auto generation = counter(document, "generation");
    const auto sampled_at = counter(document, "sampled_at_unix_ms");
    const auto& synchronization = document["synchronization"];
    const auto& totals = document["totals"];
    if (synchronization.size() != 6U || totals.size() != 4U ||
        !synchronization.contains("running") || !synchronization["running"].is_boolean()) {
        return {std::nullopt, "Smithproxy returned invalid interface counters"};
    }
    const auto attempts = counter(synchronization, "attempts");
    const auto successes = counter(synchronization, "successes");
    const auto errors = counter(synchronization, "errors");
    const auto event_datagrams = counter(synchronization, "event_datagrams");
    const auto changed_datagrams = counter(synchronization, "changed_event_datagrams");
    const auto interfaces = counter(totals, "interfaces");
    const auto addresses = counter(totals, "addresses");
    const auto ipv4 = counter(totals, "ipv4_addresses");
    const auto ipv6 = counter(totals, "ipv6_addresses");
    const auto maximum_time_milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::duration::max()).count();
    if (!generation || !sampled_at ||
        *sampled_at > static_cast<std::uint64_t>(maximum_time_milliseconds) ||
        !attempts || !successes || !errors ||
        !event_datagrams || !changed_datagrams || !interfaces || !addresses || !ipv4 || !ipv6 ||
        *successes > *attempts || *errors > *attempts || *successes + *errors > *attempts ||
        *changed_datagrams > *event_datagrams ||
        *ipv4 > *addresses || *ipv6 > *addresses || *ipv4 + *ipv6 != *addresses) {
        return {std::nullopt, "Smithproxy returned incoherent interface counters"};
    }
    std::optional<std::string> last_error;
    if (!document["last_error"].is_null()) {
        if (!document["last_error"].is_string()) {
            return {std::nullopt, "Smithproxy returned an invalid interface error code"};
        }
        last_error = document["last_error"].get<std::string>();
        if (!stable_error_code(*last_error)) {
            return {std::nullopt, "Smithproxy returned an invalid interface error code"};
        }
    }
    if (state == "ready" && last_error) {
        return {std::nullopt, "Smithproxy returned an incoherent interface state"};
    }

    InterfaceMetrics result;
    result.state = state;
    result.detail = state == "ready"
        ? "Smithproxy interface synchronization is current"
        : state == "degraded" ? "Smithproxy interface synchronization is degraded"
        : state == "starting" ? "Smithproxy interface synchronization is starting"
        : "Smithproxy interface synchronization is unavailable";
    result.sampled_at = std::chrono::system_clock::time_point{
        std::chrono::milliseconds{*sampled_at}};
    result.generation = *generation;
    result.synchronization_running = synchronization["running"].get<bool>();
    result.synchronization_attempts = *attempts;
    result.synchronization_successes = *successes;
    result.synchronization_errors = *errors;
    result.event_datagrams = *event_datagrams;
    result.changed_event_datagrams = *changed_datagrams;
    result.interfaces = *interfaces;
    result.addresses = *addresses;
    result.ipv4_addresses = *ipv4;
    result.ipv6_addresses = *ipv6;
    result.last_error = std::move(last_error);
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
