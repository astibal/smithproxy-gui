#pragma once

#include "draft_store.hpp"

#include <nlohmann/json_fwd.hpp>

#include <optional>

namespace smithproxy::gui {

[[nodiscard]] std::optional<DraftScalar> parse_draft_scalar(const nlohmann::json& value);
[[nodiscard]] std::optional<DraftStructuralOperation> parse_draft_structural_operation(
    const nlohmann::json& value);

} // namespace smithproxy::gui
