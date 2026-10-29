#include "transaction_capabilities.hpp"

#include "revision.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <set>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_operations_bound = 4096U;
constexpr std::size_t maximum_request_bytes_bound = 1024U * 1024U;
constexpr std::size_t maximum_collections = 64U;
constexpr std::size_t maximum_collection_id = 96U;
constexpr std::array<std::string_view, 4U> required_operations{"set", "create", "delete", "move"};

TransactionCapabilities incompatible() {
    return {
        .state = "incompatible",
        .detail = "Smithproxy advertised an incompatible transaction contract",
        .checked_at = std::chrono::system_clock::now(),
        .maximum_operations = 0U,
        .maximum_request_bytes = 0U,
        .operations = {},
        .collections = {},
    };
}

bool bounded_positive_size(const nlohmann::json& value, const std::size_t hard_maximum,
                           std::size_t& output) {
    if (!value.is_number_unsigned()) return false;
    const auto parsed = value.get<std::uint64_t>();
    if (parsed == 0U || parsed > std::numeric_limits<std::size_t>::max()) return false;
    output = std::min(static_cast<std::size_t>(parsed), hard_maximum);
    return true;
}

bool valid_collection_id(const std::string_view value) {
    if (value.empty() || value.size() > maximum_collection_id ||
        !std::islower(static_cast<unsigned char>(value.front()))) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](const char character) {
        const auto code = static_cast<unsigned char>(character);
        return std::islower(code) || std::isdigit(code) || character == '_' || character == '.';
    });
}

} // namespace

TransactionCapabilities parse_transaction_capabilities(
    const std::string_view payload, const ReviewedTransactionSchemas& reviewed_schemas) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object() || !document.contains("success") ||
        !document["success"].is_object()) {
        return incompatible();
    }
    const auto& success = document["success"];
    if (!success.contains("transaction_version") || success["transaction_version"] != 1 ||
        !success.contains("operation_version") || success["operation_version"] != 1 ||
        !success.contains("stable_entity_ids") || success["stable_entity_ids"] != true ||
        !success.contains("operations") || !success["operations"].is_array() ||
        !success.contains("maximum_operations") || !success.contains("maximum_request_bytes") ||
        !success.contains("collections") || !success["collections"].is_array() ||
        success["collections"].size() > maximum_collections) {
        return incompatible();
    }

    TransactionCapabilities result;
    result.checked_at = std::chrono::system_clock::now();
    if (!bounded_positive_size(success["maximum_operations"], maximum_operations_bound,
                               result.maximum_operations) ||
        !bounded_positive_size(success["maximum_request_bytes"], maximum_request_bytes_bound,
                               result.maximum_request_bytes)) {
        return incompatible();
    }

    std::set<std::string, std::less<>> operations;
    for (const auto& operation : success["operations"]) {
        if (!operation.is_string()) return incompatible();
        const auto name = operation.get<std::string>();
        if (!operations.emplace(name).second) return incompatible();
    }
    if (operations.size() != required_operations.size() ||
        !std::all_of(required_operations.begin(), required_operations.end(),
                     [&operations](const auto operation) { return operations.contains(operation); })) {
        return incompatible();
    }
    result.operations.assign(operations.begin(), operations.end());

    std::set<std::string, std::less<>> collection_ids;
    bool requires_review = false;
    for (const auto& collection : success["collections"]) {
        if (!collection.is_object() || !collection.contains("id") ||
            !collection["id"].is_string() || !collection.contains("ordered") ||
            !collection["ordered"].is_boolean() || !collection.contains("nested") ||
            !collection["nested"].is_boolean() || !collection.contains("schema_revision") ||
            !collection["schema_revision"].is_string()) {
            return incompatible();
        }
        const auto id = collection["id"].get<std::string>();
        const auto revision = collection["schema_revision"].get<std::string>();
        if (!valid_collection_id(id) || !is_canonical_revision(revision) ||
            !collection_ids.emplace(id).second) {
            return incompatible();
        }
        const auto reviewed = reviewed_schemas.find(id);
        if (reviewed == reviewed_schemas.end() || reviewed->second != revision) requires_review = true;
        result.collections.push_back({
            .id = id,
            .ordered = collection["ordered"].get<bool>(),
            .nested = collection["nested"].get<bool>(),
            .schema_revision = revision,
        });
    }
    if (result.collections.empty()) return incompatible();

    if (requires_review || reviewed_schemas.size() != result.collections.size()) {
        result.state = "review-required";
        result.detail = "Smithproxy transaction schemas require GUI core review";
        return result;
    }
    result.state = "ready";
    result.detail = "Smithproxy advertises the reviewed atomic transaction contract";
    return result;
}

const ReviewedTransactionSchemas& reviewed_transaction_schemas() {
    static const ReviewedTransactionSchemas schemas;
    return schemas;
}

} // namespace smithproxy::gui
