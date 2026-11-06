#include "transaction_envelope.hpp"

#include "draft_operation.hpp"
#include "draft_schema.hpp"
#include "revision.hpp"

#include <nlohmann/json.hpp>

#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cctype>
#include <set>
#include <type_traits>
#include <utility>

namespace smithproxy::gui {
namespace {

constexpr std::size_t hard_maximum_operations = 4096U;
constexpr std::size_t hard_maximum_request_bytes = 1024U * 1024U;
constexpr std::size_t maximum_warnings = 64U;
constexpr std::size_t maximum_warning_bytes = 256U;

bool valid_idempotency_key(const std::string_view value) {
    constexpr std::array<std::size_t, 4U> separators{8U, 13U, 18U, 23U};
    if (value.size() != 36U) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (std::find(separators.begin(), separators.end(), index) != separators.end()) {
            if (value[index] != '-') return false;
        } else if (!std::isdigit(static_cast<unsigned char>(value[index])) &&
                   !(value[index] >= 'a' && value[index] <= 'f')) {
            return false;
        }
    }
    return true;
}

bool valid_error_code(const std::string_view value) {
    if (value.empty() || value.size() > 64U) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= 'a' && character <= 'z') ||
               std::isdigit(static_cast<unsigned char>(character)) || character == '_' ||
               character == '-' || character == '.';
    });
}

nlohmann::json scalar_json(const DraftScalar& value) {
    return std::visit([](const auto& item) -> nlohmann::json {
        return item;
    }, value);
}

nlohmann::json explicit_scalar_json(const DraftScalar& value) {
    return std::visit([](const auto& item) -> nlohmann::json {
        using Value = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Value, bool>) {
            return {{"type", "bool"}, {"data", item}};
        } else if constexpr (std::is_same_v<Value, std::int64_t>) {
            return {{"type", "int"}, {"data", item}};
        } else if constexpr (std::is_same_v<Value, double>) {
            return {{"type", "double"}, {"data", item}};
        } else if constexpr (std::is_same_v<Value, std::string>) {
            return {{"type", "string"}, {"data", item}};
        } else if constexpr (std::is_same_v<Value, std::vector<std::int64_t>>) {
            return {{"type", "int_array"}, {"data", item}};
        } else if constexpr (std::is_same_v<Value, std::vector<std::string>>) {
            return {{"type", "string_array"}, {"data", item}};
        } else {
            return nullptr;
        }
    }, value);
}

std::optional<std::string> transaction_config_path(
    const std::string_view logical_path, const ConfigSnapshot& snapshot) {
    const auto marker = logical_path.find(".[");
    if (marker == std::string_view::npos) return std::string(logical_path);
    const auto close = logical_path.find(']', marker + 2U);
    if (close == std::string_view::npos || close + 2U > logical_path.size() ||
        logical_path[close + 1U] != '.') {
        return std::nullopt;
    }
    std::size_t index{};
    const auto index_text = logical_path.substr(marker + 2U, close - marker - 2U);
    const auto [end, error] = std::from_chars(
        index_text.data(), index_text.data() + index_text.size(), index);
    if (index_text.empty() || error != std::errc{} ||
        end != index_text.data() + index_text.size()) {
        return std::nullopt;
    }

    const auto root = logical_path.substr(0U, marker);
    auto suffix = logical_path.substr(close + 2U);
    std::optional<std::string> name;
    if (root == "address_objects" && index < snapshot.addresses.size()) {
        name = snapshot.addresses[index].name;
        if (suffix == "name" || suffix == "type") return std::nullopt;
        if (suffix == "value") suffix = snapshot.addresses[index].type;
    } else if (root == "port_objects" && index < snapshot.ports.size()) {
        name = snapshot.ports[index].name;
        if (suffix == "name") return std::nullopt;
    } else if (root == "proto_objects" && index < snapshot.protocols.size()) {
        name = snapshot.protocols[index].name;
        if (suffix == "name") return std::nullopt;
    } else if (root == "tls_ca" && snapshot.security_assets &&
               index < snapshot.security_assets->certificate_authorities.size()) {
        name = snapshot.security_assets->certificate_authorities[index].name;
        if (suffix == "name") return std::nullopt;
    } else {
        const auto profile_name = [&](const auto& matches) -> std::optional<std::string> {
            std::size_t current{};
            for (const auto& profile : snapshot.profiles) {
                if (!matches(profile)) continue;
                if (current++ == index) return profile.name;
            }
            return std::nullopt;
        };
        if (root == "routing") {
            name = profile_name([](const auto& item) { return item.routing.has_value(); });
        } else if (root == "tls_profiles") {
            name = profile_name([](const auto& item) { return item.tls.has_value(); });
        } else if (root == "ssh_profiles") {
            name = profile_name([](const auto& item) { return item.ssh.has_value(); });
        } else if (root == "detection_profiles") {
            name = profile_name([](const auto& item) { return item.detection.has_value(); });
        } else if (root == "content_profiles") {
            name = profile_name([](const auto& item) { return item.content.has_value(); });
        } else if (root == "alg_dns_profiles") {
            name = profile_name([](const auto& item) { return item.dns.has_value(); });
        } else if (root == "script_profiles") {
            name = profile_name([](const auto& item) { return item.script.has_value(); });
        } else if (root == "auth_profiles") {
            name = profile_name([](const auto& item) { return item.authentication.has_value(); });
        } else {
            return std::string(logical_path); // Ordered collections retain numeric paths.
        }
        if (suffix == "name") return std::nullopt;
    }
    if (!name) return std::nullopt;
    return std::string(root) + "." + *name + "." + std::string(suffix);
}

std::optional<std::string> named_object_name(
    const std::string_view collection, const std::string_view entity_id,
    const ConfigSnapshot& snapshot) {
    const auto find_name = [entity_id](const auto& objects) -> std::optional<std::string> {
        const auto found = std::find_if(objects.begin(), objects.end(), [entity_id](const auto& item) {
            return item.id == entity_id;
        });
        if (found == objects.end()) return std::nullopt;
        return found->name;
    };
    if (collection == "address_objects") return find_name(snapshot.addresses);
    if (collection == "port_objects") return find_name(snapshot.ports);
    if (collection == "proto_objects") return find_name(snapshot.protocols);
    if (collection == "tls_ca" && snapshot.security_assets) {
        return find_name(snapshot.security_assets->certificate_authorities);
    }
    const auto found = std::find_if(snapshot.profiles.begin(), snapshot.profiles.end(),
        [collection, entity_id](const auto& profile) {
            if (profile.id != entity_id) return false;
            if (collection == "routing") return profile.routing.has_value();
            if (collection == "tls_profiles") return profile.tls.has_value();
            if (collection == "content_profiles") return profile.content.has_value();
            if (collection == "ssh_profiles") return profile.ssh.has_value();
            if (collection == "script_profiles") return profile.script.has_value();
            if (collection == "auth_profiles") return profile.authentication.has_value();
            if (collection == "detection_profiles") return profile.detection.has_value();
            if (collection == "alg_dns_profiles") return profile.dns.has_value();
            return false;
        });
    if (found != snapshot.profiles.end()) return found->name;
    return std::nullopt;
}

bool named_collection(const std::string_view collection) {
    constexpr std::array collections{
        "address_objects", "port_objects", "proto_objects", "routing", "tls_profiles",
        "content_profiles", "ssh_profiles", "script_profiles", "auth_profiles",
        "detection_profiles", "alg_dns_profiles", "tls_ca",
    };
    return std::find(collections.begin(), collections.end(), collection) != collections.end();
}

bool valid_config_group_name(const std::string_view name) {
    if (name.empty() ||
        !(std::isalpha(static_cast<unsigned char>(name.front())) || name.front() == '_')) {
        return false;
    }
    return std::all_of(name.begin() + 1, name.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == '_' || character == '-';
    });
}

bool append_named_create(
    nlohmann::json& operations, const DraftCreateOperation& create) {
    if (!named_collection(create.collection) || create.parent_id ||
        create.position.kind != DraftPositionKind::Last) {
        return false;
    }
    const auto name = create.fields.find("name");
    if (name == create.fields.end() || !std::holds_alternative<std::string>(name->second)) {
        return false;
    }
    const auto& object_name = std::get<std::string>(name->second);
    if (!valid_config_group_name(object_name)) return false;
    operations.push_back({
        {"op", "add"}, {"path", create.collection}, {"name", object_name},
    });
    for (const auto& [field, scalar] : create.fields) {
        if (field == "name") continue;
        auto value = explicit_scalar_json(scalar);
        if (value.is_null()) return false;
        operations.push_back({
            {"op", "set"},
            {"path", create.collection + "." + object_name + "." + field},
            {"value", std::move(value)},
        });
    }
    return true;
}

std::optional<std::size_t> row_index(
    const std::vector<std::string>& rows, const std::string_view id) {
    const auto found = std::find(rows.begin(), rows.end(), id);
    if (found == rows.end()) return std::nullopt;
    return static_cast<std::size_t>(std::distance(rows.begin(), found));
}

bool append_ordered_move(
    nlohmann::json& operations, const std::string_view path, std::vector<std::string>& rows,
    const std::string_view entity_id, const DraftPosition& position) {
    const auto source = row_index(rows, entity_id);
    if (!source || rows.empty()) return false;

    std::size_t target{};
    std::string wire_position{"before"};
    if (position.kind == DraftPositionKind::First) {
        target = 0U;
    } else if (position.kind == DraftPositionKind::Last) {
        target = rows.size() - 1U;
        wire_position = "after";
    } else {
        if (!position.reference) return false;
        const auto reference = row_index(rows, *position.reference);
        if (!reference || *reference == *source) return false;
        target = *reference;
        wire_position = position.kind == DraftPositionKind::After ? "after" : "before";
    }

    operations.push_back({
        {"op", "move"}, {"path", path}, {"source", *source},
        {"target", target}, {"position", wire_position},
    });
    if (*source == target) return true;

    const auto moved = rows[*source];
    rows.erase(rows.begin() + static_cast<std::ptrdiff_t>(*source));
    auto insertion = row_index(rows, rows[target > *source ? target - 1U : target]);
    if (!insertion) return false;
    if (wire_position == "after") ++*insertion;
    rows.insert(rows.begin() + static_cast<std::ptrdiff_t>(*insertion), moved);
    return true;
}

bool append_policy_operation(
    nlohmann::json& operations, std::vector<std::string>& rows,
    const DraftStructuralOperation& operation) {
    return std::visit([&](const auto& item) {
        using Operation = std::decay_t<decltype(item)>;
        if (item.collection != "policy") return false;
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (item.parent_id || item.fields.empty()) return false;
            operations.push_back({{"op", "add"}, {"path", "policy"}, {"name", ""}});
            const auto index = rows.size();
            for (const auto& [field, scalar] : item.fields) {
                auto value = explicit_scalar_json(scalar);
                if (value.is_null()) return false;
                operations.push_back({
                    {"op", "set"},
                    {"path", "policy.[" + std::to_string(index) + "]." + field},
                    {"value", std::move(value)},
                });
            }
            const auto row_id = "client:" + item.client_id;
            rows.push_back(row_id);
            if (item.position.kind == DraftPositionKind::Last) return true;
            return append_ordered_move(operations, "policy", rows, row_id, item.position);
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            const auto index = row_index(rows, item.entity_id);
            if (!index) return false;
            operations.push_back({
                {"op", "remove"}, {"path", "policy"},
                {"entries", nlohmann::json::array({std::to_string(*index)})},
            });
            rows.erase(rows.begin() + static_cast<std::ptrdiff_t>(*index));
            return true;
        } else {
            return append_ordered_move(operations, "policy", rows, item.entity_id, item.position);
        }
    }, operation);
}

struct ContentRuleRows {
    std::string profile_id;
    std::string path;
    std::vector<std::string> rows;
};

std::vector<ContentRuleRows> content_rule_rows(const ConfigSnapshot& snapshot) {
    std::vector<ContentRuleRows> result;
    for (const auto& profile : snapshot.profiles) {
        if (!profile.content) continue;
        ContentRuleRows context{
            .profile_id = profile.id,
            .path = "content_profiles." + profile.name + ".content_rules",
            .rows = {},
        };
        context.rows.reserve(profile.content->rules.size());
        for (const auto& rule : profile.content->rules) context.rows.push_back(rule.id);
        result.push_back(std::move(context));
    }
    return result;
}

bool append_content_rule_operation(
    nlohmann::json& operations, std::vector<ContentRuleRows>& contexts,
    const DraftStructuralOperation& operation) {
    return std::visit([&](const auto& item) {
        using Operation = std::decay_t<decltype(item)>;
        if (item.collection != "content_profiles.content_rules") return false;
        auto context = contexts.end();
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (!item.parent_id) return false;
            context = std::find_if(contexts.begin(), contexts.end(), [&](const auto& candidate) {
                return candidate.profile_id == *item.parent_id;
            });
        } else {
            context = std::find_if(contexts.begin(), contexts.end(), [&](const auto& candidate) {
                return row_index(candidate.rows, item.entity_id).has_value();
            });
        }
        if (context == contexts.end()) return false;

        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            operations.push_back({{"op", "add"}, {"path", context->path}, {"name", ""}});
            const auto index = context->rows.size();
            for (const auto& [field, scalar] : item.fields) {
                auto value = explicit_scalar_json(scalar);
                if (value.is_null()) return false;
                operations.push_back({
                    {"op", "set"},
                    {"path", context->path + ".[" + std::to_string(index) + "]." + field},
                    {"value", std::move(value)},
                });
            }
            const auto row_id = "client:" + item.client_id;
            context->rows.push_back(row_id);
            if (item.position.kind == DraftPositionKind::Last) return true;
            return append_ordered_move(
                operations, context->path, context->rows, row_id, item.position);
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            const auto index = row_index(context->rows, item.entity_id);
            if (!index) return false;
            operations.push_back({
                {"op", "remove"}, {"path", context->path},
                {"entries", nlohmann::json::array({std::to_string(*index)})},
            });
            context->rows.erase(context->rows.begin() + static_cast<std::ptrdiff_t>(*index));
            return true;
        } else {
            return append_ordered_move(
                operations, context->path, context->rows, item.entity_id, item.position);
        }
    }, operation);
}

struct SignatureRow {
    std::string id;
    std::vector<std::string> flow;
};

struct SignatureRows {
    std::string collection;
    std::vector<SignatureRow> rows;
};

// Smithproxy addresses signatures and flow steps by their current list index.
// Keep a lightweight mirror of both levels so every later operation is bound
// after earlier creates, moves, and removals have shifted those indices.
std::vector<SignatureRows> signature_rows(const ConfigSnapshot& snapshot) {
    std::vector<SignatureRows> result{
        {.collection = "starttls_signatures", .rows = {}},
        {.collection = "detection_signatures", .rows = {}},
    };
    if (!snapshot.security_assets) return result;
    for (const auto& signature : snapshot.security_assets->signatures) {
        auto context = std::find_if(result.begin(), result.end(), [&](const auto& candidate) {
            return candidate.collection == signature.kind + "_signatures";
        });
        if (context == result.end()) continue;
        SignatureRow row{.id = signature.id, .flow = {}};
        row.flow.reserve(signature.flow.size());
        for (const auto& step : signature.flow) row.flow.push_back(step.id);
        context->rows.push_back(std::move(row));
    }
    return result;
}

std::optional<std::size_t> signature_index(
    const SignatureRows& context, const std::string_view entity_id) {
    const auto found = std::find_if(context.rows.begin(), context.rows.end(), [&](const auto& row) {
        return row.id == entity_id;
    });
    if (found == context.rows.end()) return std::nullopt;
    return static_cast<std::size_t>(std::distance(context.rows.begin(), found));
}

bool append_signature_operation(
    nlohmann::json& operations, std::vector<SignatureRows>& contexts,
    const DraftStructuralOperation& operation) {
    return std::visit([&](const auto& item) {
        using Operation = std::decay_t<decltype(item)>;
        const bool nested = item.collection.ends_with("_signatures.flow");
        const auto root = nested
            ? item.collection.substr(0U, item.collection.size() - std::string_view{".flow"}.size())
            : item.collection;
        if (root != "starttls_signatures" && root != "detection_signatures") return false;
        auto context = std::find_if(contexts.begin(), contexts.end(), [&](const auto& candidate) {
            return candidate.collection == root;
        });
        if (context == contexts.end()) return false;

        if (!nested) {
            if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
                if (item.parent_id || item.fields.empty()) return false;
                const auto name = item.fields.find("name");
                if (name == item.fields.end() || !std::holds_alternative<std::string>(name->second)) {
                    return false;
                }
                const auto index = context->rows.size();
                operations.push_back({
                    {"op", "add"}, {"path", context->collection},
                    {"name", std::get<std::string>(name->second)},
                });
                for (const auto& [field, scalar] : item.fields) {
                    auto value = explicit_scalar_json(scalar);
                    if (value.is_null()) return false;
                    operations.push_back({
                        {"op", "set"},
                        {"path", context->collection + ".[" + std::to_string(index) + "]." + field},
                        {"value", std::move(value)},
                    });
                }
                // Nested creates name their pending parent by client_id, so keep
                // that exact identifier until the transaction has been emitted.
                context->rows.push_back({.id = item.client_id, .flow = {}});
                return item.position.kind == DraftPositionKind::Last;
            } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
                const auto index = signature_index(*context, item.entity_id);
                if (!index) return false;
                operations.push_back({
                    {"op", "remove"}, {"path", context->collection},
                    {"entries", nlohmann::json::array({std::to_string(*index)})},
                });
                context->rows.erase(context->rows.begin() + static_cast<std::ptrdiff_t>(*index));
                return true;
            } else {
                return false;
            }
        }

        // A create carries its parent explicitly. Existing flow operations can
        // instead locate their unique parent through the stable flow-step ID.
        std::optional<std::size_t> parent_index;
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (!item.parent_id) return false;
            parent_index = signature_index(*context, *item.parent_id);
        } else {
            for (std::size_t index = 0U; index < context->rows.size(); ++index) {
                if (row_index(context->rows[index].flow, item.entity_id)) {
                    parent_index = index;
                    break;
                }
            }
        }
        if (!parent_index) return false;
        auto& flow = context->rows[*parent_index].flow;
        const auto path = context->collection + ".[" + std::to_string(*parent_index) + "].flow";
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            operations.push_back({{"op", "add"}, {"path", path}, {"name", ""}});
            const auto index = flow.size();
            for (const auto& [field, scalar] : item.fields) {
                auto value = explicit_scalar_json(scalar);
                if (value.is_null()) return false;
                operations.push_back({
                    {"op", "set"},
                    {"path", path + ".[" + std::to_string(index) + "]." + field},
                    {"value", std::move(value)},
                });
            }
            const auto row_id = "client:" + item.client_id;
            flow.push_back(row_id);
            if (item.position.kind == DraftPositionKind::Last) return true;
            return append_ordered_move(operations, path, flow, row_id, item.position);
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            const auto index = row_index(flow, item.entity_id);
            if (!index) return false;
            operations.push_back({
                {"op", "remove"}, {"path", path},
                {"entries", nlohmann::json::array({std::to_string(*index)})},
            });
            flow.erase(flow.begin() + static_cast<std::ptrdiff_t>(*index));
            return true;
        } else {
            return append_ordered_move(operations, path, flow, item.entity_id, item.position);
        }
    }, operation);
}

nlohmann::json position_json(const DraftPosition& position) {
    switch (position.kind) {
        case DraftPositionKind::First: return {{"first", true}};
        case DraftPositionKind::Last: return {{"last", true}};
        case DraftPositionKind::Before: return {{"before", *position.reference}};
        case DraftPositionKind::After: return {{"after", *position.reference}};
    }
    return nlohmann::json::object();
}

bool supports_operation(const TransactionCapabilities& capabilities, const std::string_view operation) {
    return std::find(capabilities.operations.begin(), capabilities.operations.end(), operation) !=
           capabilities.operations.end();
}

const TransactionCollectionCapability* collection_capability(
    const TransactionCapabilities& capabilities, const std::string_view collection) {
    const auto found = std::find_if(
        capabilities.collections.begin(), capabilities.collections.end(),
        [collection](const auto& item) { return item.id == collection; });
    return found == capabilities.collections.end() ? nullptr : &*found;
}

TransactionResponse invalid_response() {
    return {};
}

TransactionResponse terminal_response(std::string state) {
    return {
        .state = std::move(state),
        .revision = std::nullopt,
        .previous_revision = std::nullopt,
        .validated_operations = 0U,
        .warning_count = 0U,
        .restart = "unknown",
        .issue_code = std::nullopt,
        .issue_path = std::nullopt,
        .issue_detail = std::nullopt,
        .issue_operation = std::nullopt,
    };
}

} // namespace

std::optional<std::string> generate_transaction_idempotency_key() noexcept {
    std::array<unsigned char, 16U> bytes{};
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto received = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        if (received == 0) return std::nullopt;
        offset += static_cast<std::size_t>(received);
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);

    constexpr std::array<char, 16U> hexadecimal{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    std::string result;
    result.reserve(36U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index == 4U || index == 6U || index == 8U || index == 10U) result.push_back('-');
        result.push_back(hexadecimal[(bytes[index] >> 4U) & 0x0fU]);
        result.push_back(hexadecimal[bytes[index] & 0x0fU]);
    }
    return result;
}

TransactionEnvelope build_transaction_envelope(
    const DraftSnapshot& draft, const TransactionMode mode, const std::string_view idempotency_key,
    const TransactionCapabilities& capabilities) {
    const auto operation_count = draft.operation_count();
    if (capabilities.state != "ready" || !draft.base_revision ||
        !is_config_revision(*draft.base_revision) || !valid_idempotency_key(idempotency_key) ||
        draft.empty() || operation_count > hard_maximum_operations ||
        capabilities.maximum_operations == 0U ||
        operation_count > capabilities.maximum_operations ||
        capabilities.maximum_request_bytes == 0U ||
        capabilities.maximum_request_bytes > hard_maximum_request_bytes ||
        (!draft.changes.empty() && !supports_operation(capabilities, "set"))) {
        return {std::nullopt, "transaction.unavailable"};
    }

    nlohmann::json prerequisite_creates = nlohmann::json::array();
    nlohmann::json remaining_structural = nlohmann::json::array();
    std::set<std::string, std::less<>> local_ids;
    std::set<std::string, std::less<>> client_ids;
    std::set<std::pair<std::string, std::string>> structural_targets;
    for (const auto& operation : draft.structural_operations) {
        if (!valid_draft_structural_operation(operation) ||
            !local_ids.emplace(draft_structural_local_id(operation)).second) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        const auto* collection = collection_capability(
            capabilities, draft_structural_collection(operation));
        if (collection == nullptr) return {std::nullopt, "transaction.invalid_draft"};
        const auto serialized = std::visit([&](const auto& item) -> std::optional<nlohmann::json> {
            using Operation = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
                if (!supports_operation(capabilities, "create") ||
                    collection->nested != item.parent_id.has_value() ||
                    !client_ids.emplace(item.client_id).second) {
                    return std::nullopt;
                }
                nlohmann::json fields = nlohmann::json::object();
                for (const auto& [name, value] : item.fields) fields[name] = scalar_json(value);
                nlohmann::json result{
                    {"op", "create"}, {"collection", item.collection},
                    {"client_id", item.client_id}, {"position", position_json(item.position)},
                    {"fields", std::move(fields)},
                };
                if (item.parent_id) result["parent_id"] = *item.parent_id;
                return std::optional<nlohmann::json>{std::move(result)};
            } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
                if (!supports_operation(capabilities, "delete") ||
                    !structural_targets.emplace(item.collection, item.entity_id).second) {
                    return std::nullopt;
                }
                nlohmann::json result{
                    {"op", "delete"}, {"collection", item.collection},
                    {"entity_id", item.entity_id}, {"if_referenced", "reject"},
                };
                return std::optional<nlohmann::json>{std::move(result)};
            } else {
                if (!supports_operation(capabilities, "move") || !collection->ordered ||
                    !structural_targets.emplace(item.collection, item.entity_id).second) {
                    return std::nullopt;
                }
                nlohmann::json result{
                    {"op", "move"}, {"collection", item.collection},
                    {"entity_id", item.entity_id}, {"position", position_json(item.position)},
                };
                return std::optional<nlohmann::json>{std::move(result)};
            }
        }, operation);
        if (!serialized) return {std::nullopt, "transaction.invalid_draft"};
        const auto* create = std::get_if<DraftCreateOperation>(&operation);
        if (create != nullptr && !collection->ordered && !collection->nested) {
            prerequisite_creates.push_back(std::move(*serialized));
        } else {
            remaining_structural.push_back(std::move(*serialized));
        }
    }

    nlohmann::json operations = std::move(prerequisite_creates);
    std::set<std::string, std::less<>> paths;
    for (const auto& change : draft.changes) {
        if (!paths.emplace(change.path).second ||
            validate_draft_schema(change) != DraftSchemaResult::Valid) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        if (const auto* number = std::get_if<double>(&change.value);
            number != nullptr && !std::isfinite(*number)) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        operations.push_back({
            {"op", "set"},
            {"path", change.path},
            {"value", scalar_json(change.value)},
        });
    }
    for (auto& operation : remaining_structural) {
        operations.push_back(std::move(operation));
    }
    const nlohmann::json document{
        {"mode", mode == TransactionMode::Validate ? "validate" : "commit"},
        {"base_revision", *draft.base_revision},
        {"idempotency_key", idempotency_key},
        {"operations", std::move(operations)},
    };
    auto body = document.dump();
    if (body.size() > capabilities.maximum_request_bytes ||
        body.size() > hard_maximum_request_bytes) {
        return {std::nullopt, "transaction.request_too_large"};
    }
    return {std::move(body), {}};
}

TransactionEnvelope build_transaction_v2_operations(
    const DraftSnapshot& draft, const ConfigSnapshot& snapshot) {
    if (!draft.base_revision || !snapshot.revision ||
        *draft.base_revision != *snapshot.revision || draft.empty() ||
        draft.operation_count() > hard_maximum_operations) {
        return {std::nullopt, "transaction.unavailable"};
    }

    nlohmann::json operations = nlohmann::json::array();
    std::set<std::string, std::less<>> local_ids;
    for (const auto& operation : draft.structural_operations) {
        if (!valid_draft_structural_operation(operation) ||
            !local_ids.emplace(draft_structural_local_id(operation)).second) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        const auto* create = std::get_if<DraftCreateOperation>(&operation);
        if (create && named_collection(create->collection) &&
            !append_named_create(operations, *create)) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
    }

    // Scalar paths are bound to the base snapshot. Apply them after named
    // prerequisites exist, but before ordered collections can shift indices.
    std::set<std::string, std::less<>> paths;
    for (const auto& change : draft.changes) {
        if (!paths.emplace(change.path).second ||
            validate_draft_schema(change) != DraftSchemaResult::Valid) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        auto path = transaction_config_path(change.path, snapshot);
        auto value = explicit_scalar_json(change.value);
        if (!path || value.is_null()) return {std::nullopt, "transaction.invalid_draft"};
        operations.push_back({
            {"op", "set"},
            {"path", std::move(*path)},
            {"value", std::move(value)},
        });
    }

    std::vector<std::string> policy_rows;
    policy_rows.reserve(snapshot.policies.size() + draft.structural_operations.size());
    for (const auto& policy : snapshot.policies) policy_rows.push_back(policy.id);
    auto content_rows = content_rule_rows(snapshot);
    auto signatures = signature_rows(snapshot);
    for (const auto& operation : draft.structural_operations) {
        const auto collection = draft_structural_collection(operation);
        if (collection == "policy") {
            if (!append_policy_operation(operations, policy_rows, operation)) {
                return {std::nullopt, "transaction.invalid_draft"};
            }
            continue;
        }
        if (collection == "content_profiles.content_rules") {
            if (!append_content_rule_operation(operations, content_rows, operation)) {
                return {std::nullopt, "transaction.invalid_draft"};
            }
            continue;
        }
        if (collection == "starttls_signatures" || collection == "detection_signatures" ||
            collection == "starttls_signatures.flow" || collection == "detection_signatures.flow") {
            if (!append_signature_operation(operations, signatures, operation)) {
                return {std::nullopt, "transaction.invalid_draft"};
            }
            continue;
        }
        if (!named_collection(collection)) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        if (std::holds_alternative<DraftCreateOperation>(operation)) continue;
        const auto* remove = std::get_if<DraftDeleteOperation>(&operation);
        if (!remove) return {std::nullopt, "transaction.invalid_draft"};
        const auto name = named_object_name(remove->collection, remove->entity_id, snapshot);
        if (!name) return {std::nullopt, "transaction.invalid_draft"};
        operations.push_back({
            {"op", "remove"},
            {"path", remove->collection},
            {"entries", nlohmann::json::array({*name})},
        });
    }
    if (operations.size() > hard_maximum_operations) {
        return {std::nullopt, "transaction.request_too_large"};
    }
    auto body = operations.dump();
    if (body.size() > hard_maximum_request_bytes) {
        return {std::nullopt, "transaction.request_too_large"};
    }
    return {std::move(body), {}};
}

TransactionResponse parse_transaction_response(
    const long status_code, const std::string_view payload, const TransactionMode mode,
    const std::string_view expected_base_revision, const std::size_t expected_operations) {
    if (payload.size() > hard_maximum_request_bytes || expected_operations > hard_maximum_operations) {
        return invalid_response();
    }
    if (!is_config_revision(expected_base_revision)) return invalid_response();
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) return invalid_response();

    if (status_code == 200L) {
        if (!document.contains("success") || !document["success"].is_object()) {
            return invalid_response();
        }
        const auto& success = document["success"];
        if (!success.contains("revision") || !success["revision"].is_string() ||
            !success.contains("previous_revision") || !success["previous_revision"].is_string() ||
            !success.contains("validated_operations") ||
            !success["validated_operations"].is_number_unsigned() ||
            !success.contains("restart") || !success["restart"].is_string() ||
            !success.contains("warnings") || !success["warnings"].is_array() ||
            success["warnings"].size() > maximum_warnings) {
            return invalid_response();
        }
        const auto revision = success["revision"].get<std::string>();
        const auto previous_revision = success["previous_revision"].get<std::string>();
        const auto validated = success["validated_operations"].get<std::size_t>();
        const auto restart = success["restart"].get<std::string>();
        const bool revisions_match_mode = mode == TransactionMode::Validate
            ? revision == expected_base_revision && previous_revision == expected_base_revision
            : revision != expected_base_revision && previous_revision == expected_base_revision;
        if (!is_config_revision(revision) || !is_config_revision(previous_revision) ||
            !revisions_match_mode || validated != expected_operations ||
            (restart != "not-required" && restart != "required" && restart != "scheduled")) {
            return invalid_response();
        }
        for (const auto& warning : success["warnings"]) {
            if (!warning.is_string() || warning.get_ref<const std::string&>().size() > maximum_warning_bytes) {
                return invalid_response();
            }
        }
        return {
            .state = "succeeded",
            .revision = std::move(revision),
            .previous_revision = std::move(previous_revision),
            .validated_operations = validated,
            .warning_count = success["warnings"].size(),
            .restart = restart,
            .issue_code = std::nullopt,
            .issue_path = std::nullopt,
            .issue_detail = std::nullopt,
            .issue_operation = std::nullopt,
        };
    }

    if (!document.contains("error") || !document["error"].is_object() ||
        !document["error"].contains("code") || !document["error"]["code"].is_string()) {
        return invalid_response();
    }
    if (!valid_error_code(document["error"]["code"].get_ref<const std::string&>())) {
        return invalid_response();
    }
    switch (status_code) {
        case 400L:
        case 413L:
        case 422L:
            return terminal_response("rejected");
        case 401L:
        case 403L:
            return terminal_response("authorization-failed");
        case 409L:
            return terminal_response("conflict");
        case 500L:
            return terminal_response("failed");
        default:
            return invalid_response();
    }
}

} // namespace smithproxy::gui
