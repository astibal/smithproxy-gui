#pragma once

#include <chrono>
#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct TransactionCollectionCapability {
    std::string id;
    bool ordered{};
    bool nested{};
    std::string schema_revision;
};

struct TransactionCapabilities {
    std::string state{"not-advertised"};
    std::string detail{"Smithproxy does not advertise atomic configuration transactions"};
    std::chrono::system_clock::time_point checked_at{};
    std::size_t maximum_operations{};
    std::size_t maximum_request_bytes{};
    std::vector<std::string> operations;
    std::vector<TransactionCollectionCapability> collections;
    // True only when Smithproxy explicitly advertises the reviewed save endpoint.
    bool explicit_save{};
    // 1 is the legacy single-request contract; 2 is begin/prepare/commit.
    unsigned wire_version{1U};
};

using ReviewedTransactionSchemas = std::map<std::string, std::string, std::less<>>;

[[nodiscard]] TransactionCapabilities parse_transaction_capabilities(
    std::string_view payload, const ReviewedTransactionSchemas& reviewed_schemas);

[[nodiscard]] const ReviewedTransactionSchemas& reviewed_transaction_schemas();

} // namespace smithproxy::gui
