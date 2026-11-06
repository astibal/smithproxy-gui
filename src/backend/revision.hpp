#pragma once

#include <string_view>

namespace smithproxy::gui {

[[nodiscard]] bool is_config_revision(std::string_view value) noexcept;
[[nodiscard]] bool is_content_hash(std::string_view value) noexcept;

} // namespace smithproxy::gui
