#pragma once

#include <string_view>

namespace smithproxy::gui {

[[nodiscard]] bool is_canonical_revision(std::string_view value) noexcept;

} // namespace smithproxy::gui
