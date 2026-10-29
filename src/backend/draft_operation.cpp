#include "draft_operation.hpp"

#include <algorithm>
#include <cmath>
#include <cctype>
#include <type_traits>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_fields = 256U;
constexpr std::size_t maximum_string_length = 65536U;
constexpr std::size_t maximum_array_items = 256U;

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
        if (!valid_local_identifier(item.local_id) || !valid_collection(item.collection)) {
            return false;
        }
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (!valid_local_identifier(item.client_id) || !valid_position(item.position) ||
                item.fields.empty() || item.fields.size() > maximum_fields ||
                (item.parent_id && !valid_entity_identifier(*item.parent_id))) {
                return false;
            }
            return std::all_of(item.fields.begin(), item.fields.end(), [](const auto& field) {
                return valid_field_name(field.first) && valid_scalar(field.second);
            });
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            return valid_entity_identifier(item.entity_id);
        } else {
            return valid_entity_identifier(item.entity_id) && valid_position(item.position) &&
                   (!item.position.reference || *item.position.reference != item.entity_id);
        }
    }, operation);
}

std::string_view draft_structural_local_id(const DraftStructuralOperation& operation) {
    return std::visit([](const auto& item) -> std::string_view { return item.local_id; }, operation);
}

std::string_view draft_structural_collection(const DraftStructuralOperation& operation) {
    return std::visit([](const auto& item) -> std::string_view { return item.collection; }, operation);
}

} // namespace smithproxy::gui
