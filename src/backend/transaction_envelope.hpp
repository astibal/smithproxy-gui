#pragma once

#include "draft_store.hpp"
#include "transaction_capabilities.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

enum class TransactionMode { Validate, Commit };

struct TransactionEnvelope {
    std::optional<std::string> body;
    std::string error_code;
};

struct TransactionResponse {
    std::string state{"invalid-response"};
    std::optional<std::string> revision;
    std::optional<std::string> previous_revision;
    std::size_t validated_operations{};
    std::size_t warning_count{};
    std::string restart{"unknown"};
};

[[nodiscard]] std::optional<std::string> generate_transaction_idempotency_key() noexcept;

[[nodiscard]] TransactionEnvelope build_transaction_envelope(
    const DraftSnapshot& draft, TransactionMode mode, std::string_view idempotency_key,
    const TransactionCapabilities& capabilities);

[[nodiscard]] TransactionResponse parse_transaction_response(
    long status_code, std::string_view payload, TransactionMode mode,
    std::string_view expected_base_revision, std::size_t expected_operations);

} // namespace smithproxy::gui
