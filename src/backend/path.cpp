#include "path.hpp"

#include <cctype>
#include <vector>

namespace smithproxy::gui {
namespace {

std::optional<unsigned char> hex_value(const char value) {
    if (value >= '0' && value <= '9') return static_cast<unsigned char>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<unsigned char>(value - 'a' + 10);
    if (value >= 'A' && value <= 'F') return static_cast<unsigned char>(value - 'A' + 10);
    return std::nullopt;
}

std::optional<std::string> percent_decode(const std::string_view input) {
    std::string decoded;
    decoded.reserve(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        if (input[i] != '%') {
            if (input[i] == '\0' || input[i] == '\\') return std::nullopt;
            decoded.push_back(input[i]);
            continue;
        }
        if (i + 2U >= input.size()) return std::nullopt;
        const auto high = hex_value(input[i + 1U]);
        const auto low = hex_value(input[i + 2U]);
        if (!high || !low) return std::nullopt;
        const auto byte = static_cast<unsigned char>((*high << 4U) | *low);
        if (byte == 0U || byte == static_cast<unsigned char>('\\') || byte == static_cast<unsigned char>('/')) {
            return std::nullopt;
        }
        decoded.push_back(static_cast<char>(byte));
        i += 2U;
    }
    return decoded;
}

} // namespace

std::optional<std::string> normalize_base_path(const std::string_view path) {
    if (path.empty() || path.front() != '/' || path.find_first_of("?#\\") != std::string_view::npos) {
        return std::nullopt;
    }
    std::string result(path);
    while (result.size() > 1U && result.back() == '/') result.pop_back();
    if (result == "/") return result;
    std::size_t start = 1U;
    while (start <= result.size()) {
        const auto end = result.find('/', start);
        const auto segment = std::string_view(result).substr(start, end - start);
        if (segment.empty() || segment == "." || segment == "..") return std::nullopt;
        if (end == std::string::npos) break;
        start = end + 1U;
    }
    return result;
}

std::optional<std::string> path_below_base(
    const std::string_view request_path, const std::string_view base_path) {
    if (request_path.empty() || request_path.front() != '/') return std::nullopt;
    if (base_path == "/") return std::string(request_path);
    if (request_path == base_path) return std::string("/");
    if (!request_path.starts_with(base_path) || request_path.size() <= base_path.size() ||
        request_path[base_path.size()] != '/') {
        return std::nullopt;
    }
    return std::string(request_path.substr(base_path.size()));
}

std::optional<std::filesystem::path> safe_asset_path(
    const std::filesystem::path& root, const std::string_view request_path) {
    if (request_path.empty() || request_path.front() != '/') return std::nullopt;
    const auto decoded = percent_decode(request_path.substr(1U));
    if (!decoded) return std::nullopt;

    std::filesystem::path relative;
    std::size_t start{};
    while (start <= decoded->size()) {
        const auto end = decoded->find('/', start);
        const auto segment = std::string_view(*decoded).substr(start, end - start);
        if (segment == "." || segment == "..") return std::nullopt;
        if (!segment.empty()) relative /= segment;
        if (end == std::string::npos) break;
        start = end + 1U;
    }
    if (relative.empty()) relative = "index.html";
    return root / relative;
}

} // namespace smithproxy::gui
