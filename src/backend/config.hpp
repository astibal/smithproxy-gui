#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct SmithproxyConfig {
    std::string api_url;
    std::string api_key;
    std::filesystem::path ca_cert;
};

// Address of the existing Smithproxy libcli2 broker. The GUI uses this
// transport for an authenticated terminal and never starts an operating-system shell.
struct SmithproxyCliConfig {
    std::string host;
    std::uint16_t port{};
};

// Persistent administrator verifier. gui.cfg never contains the original
// password; the bounded scrypt parameters are validated before use.
struct GuiAdministratorConfig {
    std::string name;
    std::string salt;
    std::string verifier;
    std::uint64_t cost{32768U};
    std::uint32_t block_size{8U};
    std::uint32_t parallelism{1U};
};

// Persistent bootstrap values stored in gui.cfg. Credential paths are visible;
// password verifiers remain sensitive archive data and never cross to browsers.
struct GuiBootstrapConfig {
    std::uint16_t schema_version{1};
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{18082};
    std::string base_path{"/"};
    std::optional<std::string> asset_root;
    std::optional<std::string> api_url;
    std::optional<std::string> ca_cert;
    std::optional<std::string> api_token_file;
    std::optional<std::string> cli_endpoint;
    std::optional<std::string> gateway_secret_file;
    std::optional<std::string> gateway_previous_secret_file;
    std::vector<GuiAdministratorConfig> administrators;
};

struct GuiBootstrapParseResult {
    std::optional<GuiBootstrapConfig> config;
    std::string error;
};

struct AppConfig {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{18082};
    std::string base_path{"/"};
    std::filesystem::path asset_root;
    std::optional<SmithproxyConfig> smithproxy;
    std::optional<SmithproxyCliConfig> smithproxy_cli;
    std::optional<std::string> gateway_secret;
    std::optional<std::string> previous_gateway_secret;
    std::optional<std::filesystem::path> gui_config_path;
    std::vector<GuiAdministratorConfig> administrators;
};

struct ParseResult {
    std::optional<AppConfig> config;
    std::string error;
    bool show_help{};
};

ParseResult parse_config(int argc, char** argv, const std::filesystem::path& default_asset_root);
// Loads the GUI-owned libconfig section exposed from the active CFtar. Secret
// values remain in protected runtime files referenced by this configuration.
ParseResult parse_gui_config_file(
    const std::filesystem::path& path, const std::filesystem::path& default_asset_root);
// Parses archive content without opening referenced credentials. The CFG API
// uses this validation before publishing a replacement gui.cfg resource.
GuiBootstrapParseResult parse_gui_bootstrap(std::string_view source);
// Emits the complete validated resource, including opaque administrator
// verifiers, for publication through Smithproxy's atomic archive API.
std::optional<std::string> serialize_gui_bootstrap(const GuiBootstrapConfig& config);
std::filesystem::path resolve_default_asset_root(
    const std::filesystem::path& executable,
    const std::filesystem::path& build_asset_root,
    const std::filesystem::path& install_asset_relative);
std::string usage();

} // namespace smithproxy::gui
