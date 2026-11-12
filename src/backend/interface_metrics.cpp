#include "interface_metrics.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <set>

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

bool bounded_text(const nlohmann::json& value, const std::size_t maximum,
                  const bool allow_empty = false) {
    if (!value.is_string()) return false;
    const auto& text = value.get_ref<const std::string&>();
    return (allow_empty || !text.empty()) && text.size() <= maximum &&
           std::none_of(text.begin(), text.end(), [](const unsigned char character) {
               return character < 0x20U || character == 0x7fU;
           });
}

} // namespace

InterfaceMetricsParseResult parse_interface_metrics(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) {
        return {std::nullopt, "Smithproxy returned an invalid interface summary"};
    }
    const auto schema_version = counter(document, "schema_version");
    if (!schema_version || *schema_version != 1U || !document.contains("state") ||
        !document["state"].is_string() || !document.contains("synchronization") ||
        !document["synchronization"].is_object() || !document.contains("totals") ||
        !document["totals"].is_object() || !document.contains("last_error_code")) {
        return {std::nullopt, "Smithproxy returned an invalid interface summary"};
    }
    const auto state = document["state"].get<std::string>();
    constexpr std::array states{"starting", "ready", "degraded", "unavailable"};
    if (std::find(states.begin(), states.end(), state) == states.end()) {
        return {std::nullopt, "Smithproxy returned an invalid interface state"};
    }
    const auto generation = counter(document, "generation");
    const auto route_generation = counter(document, "route_generation");
    const auto role_generation = counter(document, "role_generation");
    const auto sampled_at = counter(document, "sampled_at_unix_ms");
    const auto& synchronization = document["synchronization"];
    const auto& totals = document["totals"];
    if (!synchronization.contains("running") || !synchronization["running"].is_boolean() ||
        !document.contains("interfaces") || !document["interfaces"].is_array() ||
        document["interfaces"].size() > 4096U) {
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
    if (!generation || !route_generation || !role_generation || !sampled_at ||
        *sampled_at > static_cast<std::uint64_t>(maximum_time_milliseconds) ||
        !attempts || !successes || !errors ||
        !event_datagrams || !changed_datagrams || !interfaces || !addresses || !ipv4 || !ipv6 ||
        *successes > *attempts ||
        *changed_datagrams > *event_datagrams ||
        *ipv4 > *addresses || *ipv6 > *addresses || *ipv4 + *ipv6 != *addresses) {
        return {std::nullopt, "Smithproxy returned incoherent interface counters"};
    }
    if (!document.contains("snapshot_valid") || !document["snapshot_valid"].is_boolean() ||
        !document.contains("roles_valid") || !document["roles_valid"].is_boolean() ||
        !document.contains("route_changed_at") || !document.contains("role_changed_at") ||
        !document.contains("last_error") || !document["last_error"].is_string() ||
        !bounded_text(document["last_error"], 1024U, true)) {
        return {std::nullopt, "Smithproxy returned invalid interface diagnostics"};
    }
    const auto optional_time = [&document](const char* name) -> std::optional<std::string> {
        if (document[name].is_null()) return std::string{};
        if (!bounded_text(document[name], 32U)) return std::nullopt;
        return document[name].get<std::string>();
    };
    const auto route_changed_at = optional_time("route_changed_at");
    const auto role_changed_at = optional_time("role_changed_at");
    if (!route_changed_at || !role_changed_at) {
        return {std::nullopt, "Smithproxy returned invalid interface change timestamps"};
    }
    std::optional<std::string> last_error;
    if (!document["last_error_code"].is_null()) {
        if (!document["last_error_code"].is_string()) {
            return {std::nullopt, "Smithproxy returned an invalid interface error code"};
        }
        last_error = document["last_error_code"].get<std::string>();
        if (!stable_error_code(*last_error)) {
            return {std::nullopt, "Smithproxy returned an invalid interface error code"};
        }
    }
    if (state == "ready" && last_error) {
        return {std::nullopt, "Smithproxy returned an incoherent interface state"};
    }

    std::vector<InterfaceInventoryMetrics> inventory;
    inventory.reserve(document["interfaces"].size());
    std::set<std::uint64_t> indexes;
    std::uint64_t inventory_addresses = 0;
    for (const auto& interface : document["interfaces"]) {
        if (!interface.is_object() || !interface.contains("ifindex") ||
            !bounded_text(interface.value("name", nlohmann::json{}), 64U) ||
            !bounded_text(interface.value("role", nlohmann::json{}), 64U, true) ||
            !interface.contains("uplink") || !interface["uplink"].is_boolean() ||
            !interface.contains("addresses") || !interface["addresses"].is_array() ||
            interface["addresses"].size() > 1024U) {
            return {std::nullopt, "Smithproxy returned an invalid interface inventory"};
        }
        const auto index = counter(interface, "ifindex");
        const auto flags = counter(interface, "flags");
        if (!index || *index == 0U || !flags || *flags > 0xffffffffULL ||
            !indexes.insert(*index).second) {
            return {std::nullopt, "Smithproxy returned an invalid interface inventory"};
        }
        InterfaceInventoryMetrics parsed_interface;
        parsed_interface.index = *index;
        parsed_interface.name = interface["name"].get<std::string>();
        parsed_interface.role = interface["role"].get<std::string>();
        parsed_interface.flags = *flags;
        parsed_interface.uplink = interface["uplink"].get<bool>();
        for (const auto& address : interface["addresses"]) {
            if (!address.is_object() || !bounded_text(address.value("family", nlohmann::json{}), 8U) ||
                !bounded_text(address.value("address", nlohmann::json{}), 128U)) {
                return {std::nullopt, "Smithproxy returned an invalid interface address"};
            }
            const auto family = address["family"].get<std::string>();
            const auto prefix = counter(address, "prefix_length");
            const auto scope = counter(address, "scope");
            const auto address_flags = counter(address, "flags");
            const auto maximum_prefix = family == "IPv4" ? 32U : family == "IPv6" ? 128U : 255U;
            if ((family != "IPv4" && family != "IPv6" && family != "other") || !prefix ||
                *prefix > maximum_prefix || !scope || *scope > 255U || !address_flags ||
                *address_flags > 0xffffffffULL) {
                return {std::nullopt, "Smithproxy returned an invalid interface address"};
            }
            parsed_interface.addresses.push_back({
                family, address["address"].get<std::string>(), *prefix, *scope, *address_flags});
            ++inventory_addresses;
        }
        inventory.push_back(std::move(parsed_interface));
    }
    if (inventory.size() != *interfaces || inventory_addresses != *addresses) {
        return {std::nullopt, "Smithproxy returned an incoherent interface inventory"};
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
    result.snapshot_valid = document["snapshot_valid"].get<bool>();
    result.roles_valid = document["roles_valid"].get<bool>();
    result.route_generation = *route_generation;
    result.role_generation = *role_generation;
    if (!route_changed_at->empty()) result.route_changed_at = *route_changed_at;
    if (!role_changed_at->empty()) result.role_changed_at = *role_changed_at;
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
    result.inventory = std::move(inventory);
    result.last_error = std::move(last_error);
    const auto raw_error = document["last_error"].get<std::string>();
    if (!raw_error.empty()) result.last_error_detail = raw_error;
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
