#include "dns_lookup.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <memory>

namespace smithproxy::gui {
namespace {

bool is_ip_literal(const std::string& value) {
    std::array<unsigned char, 16> storage{};
    return inet_pton(AF_INET, value.c_str(), storage.data()) == 1 ||
           inet_pton(AF_INET6, value.c_str(), storage.data()) == 1;
}

bool valid_label(const std::string_view label) {
    if (label.empty() || label.size() > 63U || label.front() == '-' || label.back() == '-') {
        return false;
    }
    return std::ranges::all_of(label, [](const char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '-';
    });
}

}  // namespace

std::optional<std::string> normalize_dns_name(const std::string_view value) {
    if (value.empty() || value.size() > 254U) return std::nullopt;
    std::string normalized{value};
    if (normalized.back() == '.') normalized.pop_back();
    if (normalized.empty() || normalized.size() > 253U || is_ip_literal(normalized)) {
        return std::nullopt;
    }
    std::ranges::transform(normalized, normalized.begin(), [](const char character) {
        return character >= 'A' && character <= 'Z'
            ? static_cast<char>(character - 'A' + 'a')
            : character;
    });
    std::size_t label_start = 0U;
    while (label_start <= normalized.size()) {
        const auto separator = normalized.find('.', label_start);
        const auto label_end = separator == std::string::npos ? normalized.size() : separator;
        if (!valid_label(std::string_view{normalized}.substr(label_start, label_end - label_start))) {
            return std::nullopt;
        }
        if (separator == std::string::npos) break;
        label_start = separator + 1U;
    }
    return normalized;
}

DnsLookupResult resolve_dns_name(const std::string_view normalized_name) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* raw_result = nullptr;
    const std::string name{normalized_name};
    const int error = getaddrinfo(name.c_str(), nullptr, &hints, &raw_result);
    if (error != 0) {
        return {error == EAI_NONAME ? DnsLookupState::NotFound : DnsLookupState::Failed, {}};
    }
    const std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> result{raw_result, freeaddrinfo};
    std::vector<std::string> addresses;
    for (auto* current = result.get(); current != nullptr && addresses.size() < 16U;
         current = current->ai_next) {
        std::array<char, INET6_ADDRSTRLEN> text{};
        const void* source = nullptr;
        if (current->ai_family == AF_INET) {
            source = &reinterpret_cast<const sockaddr_in*>(current->ai_addr)->sin_addr;
        } else if (current->ai_family == AF_INET6) {
            source = &reinterpret_cast<const sockaddr_in6*>(current->ai_addr)->sin6_addr;
        }
        if (source != nullptr && inet_ntop(current->ai_family, source, text.data(), text.size()) != nullptr) {
            addresses.emplace_back(text.data());
        }
    }
    std::ranges::sort(addresses);
    addresses.erase(std::ranges::unique(addresses).begin(), addresses.end());
    return {addresses.empty() ? DnsLookupState::NotFound : DnsLookupState::Resolved,
            std::move(addresses)};
}

}  // namespace smithproxy::gui
