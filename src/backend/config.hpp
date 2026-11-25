#pragma once

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

class RuntimeCredentialPair {
public:
    enum class Source { Files };

    RuntimeCredentialPair(
        std::filesystem::path current_path,
        std::optional<std::filesystem::path> previous_path,
        Source source);
    RuntimeCredentialPair(
        std::string current,
        std::optional<std::string> previous = std::nullopt);
    ~RuntimeCredentialPair();

    // Polling is intentionally cheap and bounded. Authentication failures use
    // force=true so rotation convergence never waits for the normal interval.
    bool refresh(bool force = false) const;
    [[nodiscard]] std::optional<std::string> current() const;
    [[nodiscard]] bool accepts(std::string_view supplied) const;
    [[nodiscard]] bool loaded() const;
    [[nodiscard]] bool previous_loaded() const;

private:
    std::filesystem::path current_path_;
    std::optional<std::filesystem::path> previous_path_;
    mutable std::mutex mutex_;
    mutable std::optional<std::string> current_;
    mutable std::optional<std::string> previous_;
    mutable std::chrono::steady_clock::time_point checked_at_{};
    mutable std::chrono::steady_clock::time_point rejected_checked_at_{};
};

struct SmithproxyConfig {
    std::string api_url;
    std::shared_ptr<RuntimeCredentialPair> api_credential;
    std::filesystem::path ca_cert;
};

// Address of the existing Smithproxy libcli2 broker. The GUI uses this
// transport for an authenticated terminal and never starts an operating-system shell.
struct SmithproxyCliConfig {
    std::string host;
    std::uint16_t port{};
};

// Persistent bootstrap values stored in core-owned gui.cfg. Paths identify
// boot-scoped credentials; live tokens never become persistent configuration.
struct GuiBootstrapConfig {
    std::uint16_t schema_version{1};
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{18082};
    std::string base_path{"/"};
    std::optional<std::string> asset_root;
    std::optional<std::string> api_url;
    std::optional<std::string> ca_cert;
    std::optional<std::string> api_token_file;
    std::optional<std::string> previous_api_token_file;
    bool api_credential_enabled{true};
    std::uint32_t api_credential_bootstrap_freshness_seconds{300};
    std::uint32_t api_credential_rotation_seconds{86400};
    std::uint32_t api_credential_overlap_seconds{3600};
    bool administrator_auth_socket_enabled{true};
    std::string administrator_auth_socket{"/run/smithproxy/admin-auth.sock"};
    std::optional<std::string> cli_endpoint;
    std::optional<std::string> gateway_secret_file;
    std::optional<std::string> gateway_previous_secret_file;
    bool gateway_credential_enabled{true};
    std::uint32_t gateway_credential_bootstrap_freshness_seconds{300};
    std::uint32_t gateway_credential_rotation_seconds{86400};
    std::uint32_t gateway_credential_overlap_seconds{3600};
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
    std::shared_ptr<RuntimeCredentialPair> gateway_credential;
    std::optional<std::filesystem::path> gui_config_path;
    // Exact persistent bootstrap loaded for this process. Keep credential
    // references, never credential contents, so the management API can tell
    // whether the current archive has changed since this boot.
    std::optional<GuiBootstrapConfig> startup_bootstrap;
};

struct ParseResult {
    std::optional<AppConfig> config;
    std::string error;
    bool show_help{};
};

ParseResult parse_config(int argc, char** argv, const std::filesystem::path& default_asset_root);
// Loads the Smithproxy-core-owned libconfig section exposed read-only from the
// active CFtar. Secret values remain in protected runtime files referenced by
// this configuration.
ParseResult parse_gui_config_file(
    const std::filesystem::path& path, const std::filesystem::path& default_asset_root);
// Parses archive content without opening referenced credentials. The CFG API
// uses this validation before publishing a replacement gui.cfg resource.
GuiBootstrapParseResult parse_gui_bootstrap(std::string_view source);
// Emits the complete validated service bootstrap resource for publication
// through Smithproxy's atomic archive API.
std::optional<std::string> serialize_gui_bootstrap(const GuiBootstrapConfig& config);
// True when the saved bootstrap would change the next process start. A process
// started without gui.cfg has no persistent baseline, so any saved resource is
// necessarily pending activation.
bool gui_bootstrap_restart_required(
    const AppConfig& active, const std::optional<GuiBootstrapConfig>& saved);
std::filesystem::path resolve_default_asset_root(
    const std::filesystem::path& executable,
    const std::filesystem::path& build_asset_root,
    const std::filesystem::path& install_asset_relative);
std::string usage();

} // namespace smithproxy::gui
