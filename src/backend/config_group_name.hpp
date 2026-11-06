#pragma once

#include <algorithm>
#include <cctype>
#include <string_view>

namespace smithproxy::gui {

// libconfig group names must be safe to address without quoting or escaping.
inline bool valid_config_group_name(const std::string_view name) {
    if (name.empty() || name.size() > 128U ||
        !(std::isalpha(static_cast<unsigned char>(name.front())) || name.front() == '_')) {
        return false;
    }
    return std::all_of(name.begin() + 1, name.end(), [](const unsigned char character) {
        return std::isalnum(character) || character == '_' || character == '-';
    });
}

}  // namespace smithproxy::gui
