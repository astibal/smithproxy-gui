#include "tls_metrics.hpp"

#include <nlohmann/json.hpp>

namespace smithproxy::gui {
namespace {

std::optional<std::uint64_t> counter(const nlohmann::json& object, const char* name) {
    const auto value = object.find(name);
    if (value == object.end()) return std::nullopt;
    if (value->is_number_unsigned()) return value->get<std::uint64_t>();
    if (value->is_number_integer()) {
        const auto signed_value = value->get<std::int64_t>();
        if (signed_value >= 0) return static_cast<std::uint64_t>(signed_value);
    }
    return std::nullopt;
}

} // namespace

TlsCacheMetricsParseResult parse_tls_cache_metrics(const std::string_view payload) {
    const auto document = nlohmann::json::parse(payload, nullptr, false);
    if (document.is_discarded() || !document.is_object()) {
        return {std::nullopt, "Smithproxy returned malformed TLS cache metrics"};
    }
    const auto size = counter(document, "cache_size");
    const auto capacity = counter(document, "max_size");
    if (!size || !capacity || *size > *capacity) {
        return {std::nullopt, "Smithproxy returned invalid TLS cache counters"};
    }
    TlsCacheMetrics result;
    result.state = "ready";
    result.detail = "Smithproxy TLS cache metrics are current";
    result.size = *size;
    result.capacity = *capacity;
    return {std::move(result), {}};
}

} // namespace smithproxy::gui
