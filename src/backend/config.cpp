#include "config.hpp"

#include "path.hpp"

#include <arpa/inet.h>

#include <charconv>
#include <cstdlib>
#include <fstream>
#include <string_view>
#include <utility>

namespace smithproxy::gui {
namespace {

ParseResult failure(std::string error) {
    return {std::nullopt, std::move(error), false};
}

std::optional<std::string> environment(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::nullopt;
}

bool is_loopback_http(const std::string_view url) {
    return url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:") ||
           url.starts_with("http://[::1]:");
}

bool valid_api_url(const std::string_view url) {
    if (!(url.starts_with("https://") || is_loopback_http(url)) ||
        url.find_first_of(" \t\r\n?#@") != std::string_view::npos) {
        return false;
    }
    const auto authority = url.find("://") + 3U;
    const auto slash = url.find('/', authority);
    return slash == std::string_view::npos || slash == url.size() - 1U;
}

bool valid_header_value(const std::string_view value) {
    for (const unsigned char byte : value) {
        if (byte < 0x20U || byte == 0x7fU) return false;
    }
    return true;
}

bool valid_bind_address(const std::string& address) {
    in_addr parsed{};
    return ::inet_pton(AF_INET, address.c_str(), &parsed) == 1;
}

std::optional<std::uint16_t> parse_port(const std::string_view value) {
    unsigned port{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0 || port > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
}

} // namespace

ParseResult parse_config(const int argc, char** argv, const std::filesystem::path& default_asset_root) {
    AppConfig config;
    config.asset_root = default_asset_root;

    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help") {
            return {std::nullopt, {}, true};
        }
        if (argument == "--bind" && i + 1 < argc) {
            config.bind_address = argv[++i];
        } else if (argument == "--port" && i + 1 < argc) {
            const auto port = parse_port(argv[++i]);
            if (!port) return failure("invalid port (expected 1..65535)");
            config.port = *port;
        } else if (argument == "--base-path" && i + 1 < argc) {
            const auto normalized = normalize_base_path(argv[++i]);
            if (!normalized) return failure("invalid base path");
            config.base_path = *normalized;
        } else if (argument == "--assets" && i + 1 < argc) {
            config.asset_root = argv[++i];
        } else {
            return failure("unknown or incomplete argument: " + std::string(argument));
        }
    }

    if (!valid_bind_address(config.bind_address)) return failure("bind address must be an IPv4 literal");
    if (config.asset_root.empty()) return failure("asset root cannot be empty");

    const auto url = environment("SMITHPROXY_API_URL");
    const auto key = environment("SMITHPROXY_API_KEY");
    const auto ca = environment("SMITHPROXY_CA_CERT");
    const auto configured_values = static_cast<unsigned>(url.has_value()) +
                                   static_cast<unsigned>(key.has_value()) +
                                   static_cast<unsigned>(ca.has_value());
    if (configured_values != 0U && configured_values != 3U) {
        return failure("SMITHPROXY_API_URL, SMITHPROXY_API_KEY and SMITHPROXY_CA_CERT must be set together");
    }
    if (configured_values == 3U) {
        if (!valid_api_url(*url)) {
            return failure("Smithproxy API URL must use HTTPS (HTTP is allowed only on loopback)");
        }
        if (!valid_header_value(*key)) return failure("SMITHPROXY_API_KEY contains invalid characters");
        std::error_code error;
        if (!std::filesystem::is_regular_file(*ca, error) || error) {
            return failure("SMITHPROXY_CA_CERT is not a readable regular file");
        }
        std::ifstream certificate(*ca);
        if (!certificate) return failure("SMITHPROXY_CA_CERT is not readable");
        std::string normalized_url = *url;
        while (normalized_url.ends_with('/')) normalized_url.pop_back();
        config.smithproxy = SmithproxyConfig{std::move(normalized_url), *key, *ca};
    }
    if (auto gateway_secret = environment("SMITHPROXY_GUI_GATEWAY_SECRET")) {
        if (gateway_secret->size() < 32U || gateway_secret->size() > 256U ||
            !valid_header_value(*gateway_secret)) {
            return failure("SMITHPROXY_GUI_GATEWAY_SECRET must contain 32..256 safe header characters");
        }
        config.gateway_secret = std::move(gateway_secret);
    }
    return {std::move(config), {}, false};
}

std::string usage() {
    return "Usage: smithproxy-gui [options]\n"
           "  --bind ADDRESS    listen address (127.0.0.1)\n"
           "  --port N          listen port (18082)\n"
           "  --base-path PATH  public URL prefix (/)\n"
           "  --assets PATH     frontend asset directory (build/frontend)\n"
           "\nSmithproxy credentials are read only from SMITHPROXY_API_URL,\n"
           "SMITHPROXY_API_KEY and SMITHPROXY_CA_CERT. A trusted reverse proxy\n"
           "may authenticate sensitive browser APIs with SMITHPROXY_GUI_GATEWAY_SECRET.\n";
}

} // namespace smithproxy::gui
