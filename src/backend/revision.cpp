#include "revision.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>

namespace smithproxy::gui {

namespace {

bool is_lowercase_hex(const std::string_view value) noexcept {
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return std::isdigit(static_cast<unsigned char>(character)) ||
               (character >= 'a' && character <= 'f');
    });
}

} // namespace

bool is_content_hash(const std::string_view value) noexcept {
    constexpr std::string_view prefix{"sha256:"};
    if (!value.starts_with(prefix) || value.size() != prefix.size() + 64U) return false;
    return is_lowercase_hex(value.substr(prefix.size()));
}

bool is_config_revision(const std::string_view value) noexcept {
    // Current Smithproxy revisions are independent 128-bit random identifiers.
    // Accept the former content-addressed form as well so GUI upgrades remain
    // compatible with already deployed transaction-capable Smithproxy builds.
    return (value.size() == 32U && is_lowercase_hex(value)) || is_content_hash(value);
}

} // namespace smithproxy::gui
