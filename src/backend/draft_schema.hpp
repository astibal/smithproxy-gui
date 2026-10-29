#pragma once

#include "draft_store.hpp"

namespace smithproxy::gui {

enum class DraftSchemaResult {
    Valid,
    UnknownPath,
    InvalidValue,
};

[[nodiscard]] DraftSchemaResult validate_draft_schema(const DraftChange& change);

} // namespace smithproxy::gui
