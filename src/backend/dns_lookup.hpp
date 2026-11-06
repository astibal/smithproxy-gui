#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

enum class DnsLookupState {
    Resolved,
    NotFound,
    Failed,
};

struct DnsLookupResult {
    DnsLookupState state{DnsLookupState::Failed};
    std::vector<std::string> addresses;
};

// Accept DNS host names only. IP literals and names with invalid labels are rejected.
std::optional<std::string> normalize_dns_name(std::string_view value);

// Perform a DNS-only lookup. No connection is made to any returned address.
DnsLookupResult resolve_dns_name(std::string_view normalized_name);

}  // namespace smithproxy::gui
