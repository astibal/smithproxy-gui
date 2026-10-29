#include "transaction_envelope.hpp"

#include "draft_schema.hpp"
#include "revision.hpp"

#include <nlohmann/json.hpp>

#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cctype>
#include <set>
#include <utility>

namespace smithproxy::gui {
namespace {

constexpr std::size_t hard_maximum_operations = 4096U;
constexpr std::size_t hard_maximum_request_bytes = 1024U * 1024U;
constexpr std::size_t maximum_warnings = 64U;
constexpr std::size_t maximum_warning_bytes = 256U;

bool valid_idempotency_key(const std::string_view value) {
    constexpr std::array<std::size_t, 4U> separators{8U, 13U, 18U, 23U};
    if (value.size() != 36U) return false;
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (std::find(separators.begin(), separators.end(), index) != separators.end()) {
            if (value[index] != '-') return false;
        } else if (!std::isdigit(static_cast<unsigned char>(value[index])) &&
                   !(value[index] >= 'a' && value[index] <= 'f')) {
            return false;
        }
    }
    return true;
}

bool valid_error_code(const std::string_view value) {
    if (value.empty() || value.size() > 64U) return false;
    return std::all_of(value.begin(), value.end(), [](const char character) {
        return (character >= 'a' && character <= 'z') ||
               std::isdigit(static_cast<unsigned char>(character)) || character == '_' ||
               character == '-' || character == '.';
    });
}

nlohmann::json scalar_json(const DraftScalar& value) {
    return std::visit([](const auto& item) -> nlohmann::json {
        return item;
    }, value);
}

TransactionResponse invalid_response() {
    return {};
}

TransactionResponse terminal_response(std::string state) {
    return {
        .state = std::move(state),
        .revision = std::nullopt,
        .previous_revision = std::nullopt,
        .validated_operations = 0U,
        .warning_count = 0U,
        .restart = "unknown",
    };
}

} // namespace

std::optional<std::string> generate_transaction_idempotency_key() noexcept {
    std::array<unsigned char, 16U> bytes{};
    std::size_t offset{};
    while (offset < bytes.size()) {
        const auto received = getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return std::nullopt;
        }
        if (received == 0) return std::nullopt;
        offset += static_cast<std::size_t>(received);
    }
    bytes[6] = static_cast<unsigned char>((bytes[6] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<unsigned char>((bytes[8] & 0x3fU) | 0x80U);

    constexpr std::array<char, 16U> hexadecimal{
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    std::string result;
    result.reserve(36U);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (index == 4U || index == 6U || index == 8U || index == 10U) result.push_back('-');
        result.push_back(hexadecimal[(bytes[index] >> 4U) & 0x0fU]);
        result.push_back(hexadecimal[bytes[index] & 0x0fU]);
    }
    return result;
}

TransactionEnvelope build_transaction_envelope(
    const DraftSnapshot& draft, const TransactionMode mode, const std::string_view idempotency_key,
    const TransactionCapabilities& capabilities) {
    if (capabilities.state != "ready" || !draft.base_revision ||
        !is_canonical_revision(*draft.base_revision) || !valid_idempotency_key(idempotency_key) ||
        draft.changes.empty() || draft.changes.size() > hard_maximum_operations ||
        capabilities.maximum_operations == 0U ||
        draft.changes.size() > capabilities.maximum_operations ||
        capabilities.maximum_request_bytes == 0U ||
        capabilities.maximum_request_bytes > hard_maximum_request_bytes ||
        std::find(capabilities.operations.begin(), capabilities.operations.end(), "set") ==
            capabilities.operations.end()) {
        return {std::nullopt, "transaction.unavailable"};
    }

    nlohmann::json operations = nlohmann::json::array();
    std::set<std::string, std::less<>> paths;
    for (const auto& change : draft.changes) {
        if (!paths.emplace(change.path).second ||
            validate_draft_schema(change) != DraftSchemaResult::Valid) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        if (const auto* number = std::get_if<double>(&change.value);
            number != nullptr && !std::isfinite(*number)) {
            return {std::nullopt, "transaction.invalid_draft"};
        }
        operations.push_back({
            {"op", "set"},
            {"path", change.path},
            {"value", scalar_json(change.value)},
        });
    }
    const nlohmann::json document{
        {"mode", mode == TransactionMode::Validate ? "validate" : "commit"},
        {"base_revision", *draft.base_revision},
        {"idempotency_key", idempotency_key},
        {"operations", std::move(operations)},
    };
    auto body = document.dump();
    if (body.size() > capabilities.maximum_request_bytes ||
        body.size() > hard_maximum_request_bytes) {
        return {std::nullopt, "transaction.request_too_large"};
    }
    return {std::move(body), {}};
}

TransactionResponse parse_transaction_response(
    const long status_code, const std::string_view payload, const TransactionMode mode,
    const std::string_view expected_base_revision, const std::size_t expected_operations) {
    if (payload.size() > hard_maximum_request_bytes || expected_operations > hard_maximum_operations) {
        return invalid_response();
    }
    if (!is_canonical_revision(expected_base_revision)) return invalid_response();
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) return invalid_response();

    if (status_code == 200L) {
        if (!document.contains("success") || !document["success"].is_object()) {
            return invalid_response();
        }
        const auto& success = document["success"];
        if (!success.contains("revision") || !success["revision"].is_string() ||
            !success.contains("previous_revision") || !success["previous_revision"].is_string() ||
            !success.contains("validated_operations") ||
            !success["validated_operations"].is_number_unsigned() ||
            !success.contains("restart") || !success["restart"].is_string() ||
            !success.contains("warnings") || !success["warnings"].is_array() ||
            success["warnings"].size() > maximum_warnings) {
            return invalid_response();
        }
        const auto revision = success["revision"].get<std::string>();
        const auto previous_revision = success["previous_revision"].get<std::string>();
        const auto validated = success["validated_operations"].get<std::size_t>();
        const auto restart = success["restart"].get<std::string>();
        const bool revisions_match_mode = mode == TransactionMode::Validate
            ? revision == expected_base_revision && previous_revision == expected_base_revision
            : revision != expected_base_revision && previous_revision == expected_base_revision;
        if (!is_canonical_revision(revision) || !is_canonical_revision(previous_revision) ||
            !revisions_match_mode || validated != expected_operations ||
            (restart != "not-required" && restart != "required" && restart != "scheduled")) {
            return invalid_response();
        }
        for (const auto& warning : success["warnings"]) {
            if (!warning.is_string() || warning.get_ref<const std::string&>().size() > maximum_warning_bytes) {
                return invalid_response();
            }
        }
        return {
            .state = "succeeded",
            .revision = std::move(revision),
            .previous_revision = std::move(previous_revision),
            .validated_operations = validated,
            .warning_count = success["warnings"].size(),
            .restart = restart,
        };
    }

    if (!document.contains("error") || !document["error"].is_object() ||
        !document["error"].contains("code") || !document["error"]["code"].is_string()) {
        return invalid_response();
    }
    if (!valid_error_code(document["error"]["code"].get_ref<const std::string&>())) {
        return invalid_response();
    }
    switch (status_code) {
        case 400L:
        case 413L:
        case 422L:
            return terminal_response("rejected");
        case 401L:
        case 403L:
            return terminal_response("authorization-failed");
        case 409L:
            return terminal_response("conflict");
        case 500L:
            return terminal_response("failed");
        default:
            return invalid_response();
    }
}

} // namespace smithproxy::gui
