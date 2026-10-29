#pragma once

#include "draft_store.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

[[nodiscard]] bool valid_draft_structural_operation(const DraftStructuralOperation& operation);
[[nodiscard]] bool valid_draft_structural_local_id(std::string_view local_id);
[[nodiscard]] std::string_view draft_structural_local_id(const DraftStructuralOperation& operation);
[[nodiscard]] std::string_view draft_structural_collection(const DraftStructuralOperation& operation);
[[nodiscard]] bool known_draft_structural_collection(std::string_view collection);
[[nodiscard]] std::optional<std::string> draft_structural_field_path(
    std::string_view collection, std::string_view field);

} // namespace smithproxy::gui
