#pragma once

#include "ascii.hpp"

#include <string_view>

namespace smithproxy::gui {

// libconfig group names must be safe to address without quoting or escaping.
inline bool valid_config_group_name(const std::string_view name) {
    if (name.empty() || name.size() > 128U ||
        !(ascii_letter(static_cast<unsigned char>(name.front())) || name.front() == '_')) {
        return false;
    }
    for (const char character : name.substr(1U)) {
        const auto ascii_character = static_cast<unsigned char>(character);
        if (!ascii_letter(ascii_character) && !ascii_digit(ascii_character) &&
            character != '_' && character != '-') {
            return false;
        }
    }
    return true;
}

}  // namespace smithproxy::gui
