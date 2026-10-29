#include "draft_operation_json.hpp"

#include "draft_operation.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace smithproxy::gui {
namespace {

bool exact_keys(const nlohmann::json& value,
                const std::initializer_list<std::string_view> required,
                const std::initializer_list<std::string_view> optional = {}) {
    if (!value.is_object() || value.size() < required.size() ||
        value.size() > required.size() + optional.size()) {
        return false;
    }
    for (const auto key : required) {
        if (!value.contains(key)) return false;
    }
    for (const auto& [key, unused] : value.items()) {
        (void)unused;
        const auto recognized = std::find(required.begin(), required.end(), key) != required.end() ||
                                std::find(optional.begin(), optional.end(), key) != optional.end();
        if (!recognized) return false;
    }
    return true;
}

std::optional<DraftPosition> parse_position(const nlohmann::json& value) {
    if (!value.is_object() || value.size() != 1U) return std::nullopt;
    if (value.contains("first") && value["first"] == true) {
        return DraftPosition{DraftPositionKind::First, std::nullopt};
    }
    if (value.contains("last") && value["last"] == true) {
        return DraftPosition{DraftPositionKind::Last, std::nullopt};
    }
    if (value.contains("before") && value["before"].is_string()) {
        return DraftPosition{DraftPositionKind::Before, value["before"].get<std::string>()};
    }
    if (value.contains("after") && value["after"].is_string()) {
        return DraftPosition{DraftPositionKind::After, value["after"].get<std::string>()};
    }
    return std::nullopt;
}

std::optional<DraftAuthIdentities> parse_auth_identities(const nlohmann::json& value) {
    if (!value.is_array() || value.empty() || value.size() > 256U) return std::nullopt;
    DraftAuthIdentities identities;
    identities.reserve(value.size());
    for (const auto& item : value) {
        if (!exact_keys(item, {"name"}, {"detection_profile", "content_profile", "tls_profile",
                                         "alg_dns_profile"}) ||
            !item["name"].is_string()) {
            return std::nullopt;
        }
        DraftAuthIdentity identity{
            .name = item["name"].get<std::string>(),
            .detection_profile = {},
            .content_profile = {},
            .tls_profile = {},
            .alg_dns_profile = {},
        };
        const auto profile = [&](const std::string_view field, std::string& output) {
            if (!item.contains(field)) return true;
            if (!item[field].is_string()) return false;
            output = item[field].get<std::string>();
            return true;
        };
        if (!profile("detection_profile", identity.detection_profile) ||
            !profile("content_profile", identity.content_profile) ||
            !profile("tls_profile", identity.tls_profile) ||
            !profile("alg_dns_profile", identity.alg_dns_profile)) {
            return std::nullopt;
        }
        identities.push_back(std::move(identity));
    }
    return identities;
}

} // namespace

std::optional<DraftScalar> parse_draft_scalar(const nlohmann::json& value) {
    if (value.is_boolean()) return DraftScalar{value.get<bool>()};
    if (value.is_number_unsigned()) {
        const auto number = value.get<std::uint64_t>();
        if (number > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::nullopt;
        }
        return DraftScalar{static_cast<std::int64_t>(number)};
    }
    if (value.is_number_integer()) return DraftScalar{value.get<std::int64_t>()};
    if (value.is_number_float()) return DraftScalar{value.get<double>()};
    if (value.is_string()) return DraftScalar{value.get<std::string>()};
    if (!value.is_array()) return std::nullopt;
    if (value.empty()) return DraftScalar{std::vector<std::string>{}};
    if (value.front().is_object()) {
        auto identities = parse_auth_identities(value);
        return identities
            ? std::optional<DraftScalar>{DraftScalar{std::move(*identities)}} : std::nullopt;
    }
    if (value.front().is_number_integer() || value.front().is_number_unsigned()) {
        std::vector<std::int64_t> values;
        values.reserve(value.size());
        for (const auto& item : value) {
            if (!item.is_number_integer() && !item.is_number_unsigned()) return std::nullopt;
            if (item.is_number_unsigned() &&
                item.get<std::uint64_t>() >
                    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
                return std::nullopt;
            }
            values.push_back(item.get<std::int64_t>());
        }
        return DraftScalar{std::move(values)};
    }
    std::vector<std::string> values;
    values.reserve(value.size());
    for (const auto& item : value) {
        if (!item.is_string()) return std::nullopt;
        values.push_back(item.get<std::string>());
    }
    return DraftScalar{std::move(values)};
}

std::optional<DraftStructuralOperation> parse_draft_structural_operation(
    const nlohmann::json& value) {
    if (!value.is_object() || !value.contains("op") || !value["op"].is_string() ||
        !value.contains("local_id") || !value["local_id"].is_string() ||
        !value.contains("collection") || !value["collection"].is_string()) {
        return std::nullopt;
    }
    const auto operation = value["op"].get<std::string>();
    const auto local_id = value["local_id"].get<std::string>();
    const auto collection = value["collection"].get<std::string>();
    if (operation == "create") {
        if (!exact_keys(value, {"op", "local_id", "collection", "client_id", "position", "fields"},
                        {"parent_id"}) ||
            !value["client_id"].is_string() || !value["fields"].is_object() ||
            value["fields"].empty()) {
            return std::nullopt;
        }
        const auto position = parse_position(value["position"]);
        if (!position) return std::nullopt;
        std::optional<std::string> parent_id;
        if (value.contains("parent_id")) {
            if (!value["parent_id"].is_string()) return std::nullopt;
            parent_id = value["parent_id"].get<std::string>();
        }
        std::map<std::string, DraftScalar, std::less<>> fields;
        for (const auto& [name, raw] : value["fields"].items()) {
            auto parsed = parse_draft_scalar(raw);
            if (!parsed) return std::nullopt;
            fields.emplace(name, std::move(*parsed));
        }
        DraftStructuralOperation parsed = DraftCreateOperation{
            .local_id = local_id,
            .collection = collection,
            .client_id = value["client_id"].get<std::string>(),
            .parent_id = std::move(parent_id),
            .position = *position,
            .fields = std::move(fields),
        };
        return valid_draft_structural_operation(parsed)
                   ? std::optional<DraftStructuralOperation>{std::move(parsed)} : std::nullopt;
    }
    if (operation == "delete") {
        if (!exact_keys(value, {"op", "local_id", "collection", "entity_id"}) ||
            !value["entity_id"].is_string()) {
            return std::nullopt;
        }
        DraftStructuralOperation parsed = DraftDeleteOperation{
            .local_id = local_id,
            .collection = collection,
            .entity_id = value["entity_id"].get<std::string>(),
        };
        return valid_draft_structural_operation(parsed)
                   ? std::optional<DraftStructuralOperation>{std::move(parsed)} : std::nullopt;
    }
    if (operation == "move") {
        if (!exact_keys(value, {"op", "local_id", "collection", "entity_id", "position"}) ||
            !value["entity_id"].is_string()) {
            return std::nullopt;
        }
        const auto position = parse_position(value["position"]);
        if (!position) return std::nullopt;
        DraftStructuralOperation parsed = DraftMoveOperation{
            .local_id = local_id,
            .collection = collection,
            .entity_id = value["entity_id"].get<std::string>(),
            .position = *position,
        };
        return valid_draft_structural_operation(parsed)
                   ? std::optional<DraftStructuralOperation>{std::move(parsed)} : std::nullopt;
    }
    return std::nullopt;
}

} // namespace smithproxy::gui
