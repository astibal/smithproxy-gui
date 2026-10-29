#include "revision.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>

namespace smithproxy::gui {

bool is_canonical_revision(const std::string_view value) noexcept {
    constexpr std::string_view prefix{"sha256:"};
    if (!value.starts_with(prefix) || value.size() != prefix.size() + 64U) return false;
    return std::all_of(value.begin() + static_cast<std::ptrdiff_t>(prefix.size()), value.end(),
                       [](const char character) {
                           return std::isdigit(static_cast<unsigned char>(character)) ||
                                  (character >= 'a' && character <= 'f');
                       });
}

} // namespace smithproxy::gui
