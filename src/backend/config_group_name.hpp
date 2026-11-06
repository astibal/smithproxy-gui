#pragma once

#include <string_view>

namespace smithproxy::gui {

// libconfig group names must be safe to address without quoting or escaping.
inline bool valid_config_group_name(const std::string_view name) {
    const auto ascii_letter = [](const char character) {
        return (character >= 'A' && character <= 'Z') ||
               (character >= 'a' && character <= 'z');
    };
    if (name.empty() || name.size() > 128U ||
        !(ascii_letter(name.front()) || name.front() == '_')) {
        return false;
    }
    for (const char character : name.substr(1U)) {
        const bool digit = character >= '0' && character <= '9';
        if (!ascii_letter(character) && !digit && character != '_' && character != '-') {
            return false;
        }
    }
    return true;
}

}  // namespace smithproxy::gui
