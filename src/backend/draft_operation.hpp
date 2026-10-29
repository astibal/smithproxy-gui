#pragma once

#include "draft_store.hpp"

#include <string_view>

namespace smithproxy::gui {

[[nodiscard]] bool valid_draft_structural_operation(const DraftStructuralOperation& operation);
[[nodiscard]] std::string_view draft_structural_local_id(const DraftStructuralOperation& operation);
[[nodiscard]] std::string_view draft_structural_collection(const DraftStructuralOperation& operation);

} // namespace smithproxy::gui
