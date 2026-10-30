#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace smithproxy::gui {

struct SmithproxyConfig {
    std::string api_url;
    std::string api_key;
    std::filesystem::path ca_cert;
};

struct AppConfig {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{18082};
    std::string base_path{"/"};
    std::filesystem::path asset_root;
    std::optional<SmithproxyConfig> smithproxy;
    std::optional<std::string> gateway_secret;
    std::optional<std::string> previous_gateway_secret;
};

struct ParseResult {
    std::optional<AppConfig> config;
    std::string error;
    bool show_help{};
};

ParseResult parse_config(int argc, char** argv, const std::filesystem::path& default_asset_root);
std::filesystem::path resolve_default_asset_root(
    const std::filesystem::path& executable,
    const std::filesystem::path& build_asset_root,
    const std::filesystem::path& install_asset_relative);
std::string usage();

} // namespace smithproxy::gui
