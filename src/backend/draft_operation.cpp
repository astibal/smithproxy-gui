#include "draft_operation.hpp"

#include "draft_schema.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <type_traits>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_fields = 256U;
constexpr std::size_t maximum_string_length = 65536U;
constexpr std::size_t maximum_array_items = 256U;

struct CollectionSchema {
    std::string_view id;
    std::string_view indexed_path;
    std::string_view required_field;
};

constexpr std::array collection_schemas{
    CollectionSchema{"policy", "policy.[0]", "name"},
    CollectionSchema{"address_objects", "address_objects.[0]", "name"},
    CollectionSchema{"port_objects", "port_objects.[0]", "name"},
    CollectionSchema{"proto_objects", "proto_objects.[0]", "name"},
    CollectionSchema{"routing", "routing.[0]", "name"},
    CollectionSchema{"tls_profiles", "tls_profiles.[0]", "name"},
    CollectionSchema{"content_profiles", "content_profiles.[0]", "name"},
    CollectionSchema{"content_profiles.content_rules",
                     "content_profiles.[0].content_rules.[0]", "match"},
    CollectionSchema{"ssh_profiles", "ssh_profiles.[0]", "name"},
    CollectionSchema{"script_profiles", "script_profiles.[0]", "name"},
    CollectionSchema{"auth_profiles", "auth_profiles.[0]", "name"},
    CollectionSchema{"detection_profiles", "detection_profiles.[0]", "name"},
    CollectionSchema{"alg_dns_profiles", "alg_dns_profiles.[0]", "name"},
    CollectionSchema{"tls_ca", "tls_ca.[0]", "name"},
    CollectionSchema{"starttls_signatures", "starttls_signatures.[0]", "name"},
    CollectionSchema{"starttls_signatures.flow", "starttls_signatures.[0].flow.[0]", "signature"},
    CollectionSchema{"detection_signatures", "detection_signatures.[0]", "name"},
    CollectionSchema{"detection_signatures.flow", "detection_signatures.[0].flow.[0]", "signature"},
};

const CollectionSchema* collection_schema(const std::string_view id) {
    const auto found = std::find_if(collection_schemas.begin(), collection_schemas.end(),
                                    [id](const auto& item) { return item.id == id; });
    return found == collection_schemas.end() ? nullptr : &*found;
}

bool valid_local_identifier(const std::string_view value) {
    if (value.empty() || value.size() > 64U ||
        !std::isalnum(static_cast<unsigned char>(value.front()))) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == '.' || character == '_' || character == '-';
    });
}

bool valid_collection(const std::string_view value) {
    if (value.empty() || value.size() > 96U ||
        !std::islower(static_cast<unsigned char>(value.front()))) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::islower(character) || std::isdigit(character) || character == '_' || character == '.';
    });
}

bool valid_entity_identifier(const std::string_view value) {
    if (value.empty() || value.size() > 256U) return false;
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == ':' || character == '.' ||
               character == '_' || character == '-';
    });
}

bool valid_field_name(const std::string_view value) {
    if (value.empty() || value.size() > 96U ||
        !std::islower(static_cast<unsigned char>(value.front()))) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const unsigned char character) {
        return std::islower(character) || std::isdigit(character) || character == '_' || character == '-';
    });
}

bool valid_position(const DraftPosition& position) {
    if (position.kind == DraftPositionKind::First || position.kind == DraftPositionKind::Last) {
        return !position.reference.has_value();
    }
    return position.reference && valid_entity_identifier(*position.reference);
}

bool valid_scalar(const DraftScalar& value) {
    return std::visit([](const auto& item) {
        using Value = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Value, std::string>) {
            return item.size() <= maximum_string_length && item.find('\0') == std::string::npos;
        } else if constexpr (std::is_same_v<Value, std::vector<std::string>>) {
            return item.size() <= maximum_array_items &&
                   std::all_of(item.begin(), item.end(), [](const std::string& entry) {
                       return !entry.empty() && entry.size() <= maximum_string_length &&
                              entry.find('\0') == std::string::npos;
                   });
        } else if constexpr (std::is_same_v<Value, std::vector<std::int64_t>>) {
            return item.size() <= maximum_array_items;
        } else if constexpr (std::is_same_v<Value, double>) {
            return std::isfinite(item);
        } else {
            return true;
        }
    }, value);
}

} // namespace

bool valid_draft_structural_operation(const DraftStructuralOperation& operation) {
    return std::visit([](const auto& item) {
        using Operation = std::decay_t<decltype(item)>;
        const auto* schema = collection_schema(item.collection);
        if (!valid_local_identifier(item.local_id) || !valid_collection(item.collection) ||
            schema == nullptr) {
            return false;
        }
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (!valid_local_identifier(item.client_id) || !valid_position(item.position) ||
                item.fields.empty() || item.fields.size() > maximum_fields ||
                (item.parent_id && !valid_entity_identifier(*item.parent_id)) ||
                !item.fields.contains(schema->required_field)) {
                return false;
            }
            return std::all_of(item.fields.begin(), item.fields.end(), [&](const auto& field) {
                if (!valid_field_name(field.first) || !valid_scalar(field.second)) return false;
                const auto path = draft_structural_field_path(item.collection, field.first);
                return path && validate_draft_schema({*path, field.second}) == DraftSchemaResult::Valid;
            });
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            return valid_entity_identifier(item.entity_id);
        } else {
            return valid_entity_identifier(item.entity_id) && valid_position(item.position) &&
                   (!item.position.reference || *item.position.reference != item.entity_id);
        }
    }, operation);
}

bool valid_draft_structural_local_id(const std::string_view local_id) {
    return valid_local_identifier(local_id);
}

std::string_view draft_structural_local_id(const DraftStructuralOperation& operation) {
    return std::visit([](const auto& item) -> std::string_view { return item.local_id; }, operation);
}

std::string_view draft_structural_collection(const DraftStructuralOperation& operation) {
    return std::visit([](const auto& item) -> std::string_view { return item.collection; }, operation);
}

bool known_draft_structural_collection(const std::string_view collection) {
    return collection_schema(collection) != nullptr;
}

std::optional<std::string> draft_structural_field_path(
    const std::string_view collection, const std::string_view field) {
    const auto* schema = collection_schema(collection);
    if (schema == nullptr || !valid_field_name(field)) return std::nullopt;
    return std::string(schema->indexed_path) + "." + std::string(field);
}

} // namespace smithproxy::gui
