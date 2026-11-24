#include "config.hpp"

#include "path.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <libconfig.h++>
#include <sys/stat.h>
#include <unistd.h>

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

GuiBootstrapParseResult bootstrap_failure(std::string error) {
    return {std::nullopt, std::move(error)};
}

std::optional<std::string> environment(const char* name) {
    if (const char* value = std::getenv(name); value != nullptr && *value != '\0') {
        return std::string(value);
    }
    return std::nullopt;
}

struct ProtectedFileResult {
    std::optional<std::string> value;
    std::string error;
};

bool valid_header_value(std::string_view value);

// Opens a runtime credential without following links and rejects permissions
// that would let another local account replace or read the secret.
ProtectedFileResult read_protected_file(
    const std::filesystem::path& path, const std::string_view label,
    const std::size_t maximum_size = 4096U, const bool secret = true) {
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return {std::nullopt, std::string(label) + " is not readable"};
    struct stat metadata {};
    if (::fstat(descriptor, &metadata) != 0) {
        ::close(descriptor);
        return {std::nullopt, std::string(label) + " metadata is not readable"};
    }
    const bool trusted_owner = metadata.st_uid == ::geteuid() || (!secret && metadata.st_uid == 0U);
    const bool unsafe_mode = secret ? (metadata.st_mode & 0077) != 0 : (metadata.st_mode & 0022) != 0;
    if (!S_ISREG(metadata.st_mode) || !trusted_owner || unsafe_mode ||
        metadata.st_size <= 0 || static_cast<std::uintmax_t>(metadata.st_size) > maximum_size) {
        ::close(descriptor);
        return {std::nullopt, std::string(label) +
            (secret ? " must be an owned 0600 regular file" : " must be a trusted non-writable regular file")};
    }
    std::string value(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto count = ::read(descriptor, value.data() + offset, value.size() - offset);
        if (count <= 0) {
            ::close(descriptor);
            return {std::nullopt, std::string(label) + " could not be read completely"};
        }
        offset += static_cast<std::size_t>(count);
    }
    ::close(descriptor);
    while (value.ends_with('\n') || value.ends_with('\r')) value.pop_back();
    const bool invalid_content = secret ? !valid_header_value(value) : value.find('\0') != std::string::npos;
    if (value.empty() || invalid_content) {
        return {std::nullopt, std::string(label) + " contains invalid characters"};
    }
    return {std::move(value), {}};
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

bool is_loopback_bind(const std::string& address) {
    in_addr parsed{};
    if (::inet_pton(AF_INET, address.c_str(), &parsed) != 1) return false;
    return (ntohl(parsed.s_addr) & 0xff000000U) == 0x7f000000U;
}

std::optional<std::uint16_t> parse_port(const std::string_view value) {
    unsigned port{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (error != std::errc{} || end != value.data() + value.size() || port == 0 || port > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
}

// Parse the deployment-owned CLI broker address. Brackets keep IPv6 endpoints
// unambiguous while the common host:port form remains convenient for Saslik.
std::optional<SmithproxyCliConfig> parse_cli_endpoint(const std::string_view value) {
    std::string_view host;
    std::string_view port;
    if (value.starts_with('[')) {
        const auto closing = value.find(']');
        if (closing == std::string_view::npos || closing == 1U ||
            closing + 2U >= value.size() || value[closing + 1U] != ':') {
            return std::nullopt;
        }
        host = value.substr(1U, closing - 1U);
        port = value.substr(closing + 2U);
    } else {
        const auto separator = value.rfind(':');
        if (separator == std::string_view::npos || separator == 0U ||
            separator + 1U >= value.size() || value.find(':') != separator) {
            return std::nullopt;
        }
        host = value.substr(0U, separator);
        port = value.substr(separator + 1U);
    }
    if (host.find_first_of(" \t\r\n/\\?#@[]") != std::string_view::npos) {
        return std::nullopt;
    }
    const auto parsed_port = parse_port(port);
    if (!parsed_port) return std::nullopt;
    return SmithproxyCliConfig{std::string(host), *parsed_port};
}

bool validate_final_config(const AppConfig& config, std::string& error) {
    if (!valid_bind_address(config.bind_address)) {
        error = "bind address must be an IPv4 literal";
        return false;
    }
    if (config.asset_root.empty()) {
        error = "asset root cannot be empty";
        return false;
    }
    if (!is_loopback_bind(config.bind_address) && !config.gateway_secret) {
        error = "non-loopback bind requires SMITHPROXY_GUI_GATEWAY_SECRET";
        return false;
    }
    return true;
}

} // namespace

std::filesystem::path resolve_default_asset_root(
    const std::filesystem::path& executable,
    const std::filesystem::path& build_asset_root,
    const std::filesystem::path& install_asset_relative) {
    std::error_code error;
    const auto absolute_executable = executable.is_absolute()
        ? executable
        : std::filesystem::absolute(executable, error);
    if (!error && !absolute_executable.empty()) {
        const auto installed =
            (absolute_executable.parent_path() / install_asset_relative).lexically_normal();
        if (std::filesystem::is_regular_file(installed / "index.html", error) && !error) {
            return installed;
        }
    }
    return build_asset_root;
}

ParseResult parse_config(const int argc, char** argv, const std::filesystem::path& default_asset_root) {
    AppConfig config;
    config.asset_root = default_asset_root;

    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--help") return {std::nullopt, {}, true};
    }
    bool config_path_seen = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) != "--config") continue;
        if (i + 1 >= argc) return failure("--config requires a gui.cfg path");
        if (config_path_seen) return failure("--config may be specified only once");
        config_path_seen = true;
        const auto loaded = parse_gui_config_file(argv[i + 1], default_asset_root);
        if (!loaded.config) return loaded;
        config = *loaded.config;
        ++i;
    }

    for (int i = 1; i < argc; ++i) {
        const std::string_view argument(argv[i]);
        if (argument == "--help") {
            return {std::nullopt, {}, true};
        }
        if (argument == "--config" && i + 1 < argc) {
            ++i;
        } else if (argument == "--bind" && i + 1 < argc) {
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
    if (const auto cli = environment("SMITHPROXY_CLI")) {
        config.smithproxy_cli = parse_cli_endpoint(*cli);
        if (!config.smithproxy_cli) {
            return failure("SMITHPROXY_CLI must use host:port or [IPv6]:port");
        }
    }
    if (auto gateway_secret = environment("SMITHPROXY_GUI_GATEWAY_SECRET")) {
        if (gateway_secret->size() < 32U || gateway_secret->size() > 256U ||
            !valid_header_value(*gateway_secret)) {
            return failure("SMITHPROXY_GUI_GATEWAY_SECRET must contain 32..256 safe header characters");
        }
        config.gateway_secret = std::move(gateway_secret);
    }
    if (auto previous = environment("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS")) {
        if (!config.gateway_secret) {
            return failure("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS requires the current secret");
        }
        if (previous->size() < 32U || previous->size() > 256U ||
            !valid_header_value(*previous)) {
            return failure(
                "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS must contain 32..256 safe header characters");
        }
        if (*previous == *config.gateway_secret) {
            return failure("current and previous gateway secrets must differ");
        }
        config.previous_gateway_secret = std::move(previous);
    }
    std::string validation_error;
    if (!validate_final_config(config, validation_error)) return failure(std::move(validation_error));
    return {std::move(config), {}, false};
}

ParseResult parse_gui_config_file(
    const std::filesystem::path& path, const std::filesystem::path& default_asset_root) {
    const auto source = read_protected_file(path, "GUI configuration", 1024U * 1024U, false);
    if (!source.value) return failure(source.error);
    const auto bootstrap = parse_gui_bootstrap(*source.value);
    if (!bootstrap.config) return failure(bootstrap.error);

    const auto& persistent = *bootstrap.config;
    AppConfig config;
    config.bind_address = persistent.bind_address;
    config.port = persistent.port;
    config.base_path = persistent.base_path;
    config.asset_root = default_asset_root;
    config.gui_config_path = path;

    if (persistent.api_url) {
        std::error_code filesystem_error;
        if (!std::filesystem::is_regular_file(*persistent.ca_cert, filesystem_error) ||
            filesystem_error) {
            return failure("gui.smithproxy.ca_cert is not a readable regular file");
        }
        std::ifstream certificate(*persistent.ca_cert);
        if (!certificate) return failure("gui.smithproxy.ca_cert is not readable");
        const auto token = read_protected_file(
            *persistent.api_token_file, "GUI Smithproxy API token");
        if (!token.value) return failure(token.error);
        config.smithproxy = SmithproxyConfig{
            *persistent.api_url, *token.value, *persistent.ca_cert};
        if (persistent.cli_endpoint) {
            config.smithproxy_cli = parse_cli_endpoint(*persistent.cli_endpoint);
        }
    }
    if (persistent.gateway_secret_file) {
        const auto secret = read_protected_file(
            *persistent.gateway_secret_file, "GUI gateway secret");
        if (!secret.value || secret.value->size() < 32U || secret.value->size() > 256U) {
            return failure(secret.error.empty()
                ? "GUI gateway secret must contain 32..256 characters" : secret.error);
        }
        config.gateway_secret = *secret.value;
        if (persistent.gateway_previous_secret_file) {
            const auto previous = read_protected_file(
                *persistent.gateway_previous_secret_file, "Previous GUI gateway secret");
            if (!previous.value || previous.value->size() < 32U || previous.value->size() > 256U) {
                return failure(previous.error.empty()
                    ? "previous GUI gateway secret must contain 32..256 characters"
                    : previous.error);
            }
            if (*previous.value == *config.gateway_secret) {
                return failure("current and previous GUI gateway secrets must differ");
            }
            config.previous_gateway_secret = *previous.value;
        }
    }
    std::string validation_error;
    if (!validate_final_config(config, validation_error)) return failure(std::move(validation_error));
    return {std::move(config), {}, false};
}

GuiBootstrapParseResult parse_gui_bootstrap(const std::string_view source) {
    libconfig::Config document;
    try {
        document.readString(std::string(source));
    } catch (const libconfig::ParseException& error) {
        return bootstrap_failure("invalid gui.cfg at line " + std::to_string(error.getLine()));
    }
    const auto& root = document.getRoot();
    if (!root.exists("gui") || root["gui"].getType() != libconfig::Setting::TypeGroup) {
        return bootstrap_failure("gui.cfg must contain a gui group");
    }

    const auto& gui = root["gui"];
    GuiBootstrapConfig config;
    try {
        if (gui.exists("backend")) {
            const auto& backend = gui["backend"];
            backend.lookupValue("bind_address", config.bind_address);
            int port = config.port;
            backend.lookupValue("port", port);
            if (port <= 0 || port > 65535) {
                return bootstrap_failure("gui.backend.port must use 1..65535");
            }
            config.port = static_cast<std::uint16_t>(port);
            backend.lookupValue("base_path", config.base_path);
            const auto normalized = normalize_base_path(config.base_path);
            if (!normalized) return bootstrap_failure("gui.backend.base_path is invalid");
            config.base_path = *normalized;
        }
        if (gui.exists("smithproxy")) {
            const auto& upstream = gui["smithproxy"];
            std::string api_url;
            std::string ca_cert;
            std::string api_token_file;
            if (!upstream.lookupValue("api_url", api_url) ||
                !upstream.lookupValue("ca_cert", ca_cert) ||
                !upstream.lookupValue("api_token_file", api_token_file)) {
                return bootstrap_failure(
                    "gui.smithproxy requires api_url, ca_cert, and api_token_file");
            }
            if (!valid_api_url(api_url)) {
                return bootstrap_failure(
                    "gui.smithproxy.api_url must use HTTPS or loopback HTTP");
            }
            while (api_url.ends_with('/')) api_url.pop_back();
            config.api_url = std::move(api_url);
            config.ca_cert = std::move(ca_cert);
            config.api_token_file = std::move(api_token_file);
            std::string cli_endpoint;
            if (upstream.lookupValue("cli_endpoint", cli_endpoint)) {
                if (!parse_cli_endpoint(cli_endpoint)) {
                    return bootstrap_failure("gui.smithproxy.cli_endpoint is invalid");
                }
                config.cli_endpoint = std::move(cli_endpoint);
            }
        }
        if (gui.exists("gateway")) {
            const auto& gateway = gui["gateway"];
            std::string secret_file;
            if (!gateway.lookupValue("secret_file", secret_file)) {
                return bootstrap_failure("gui.gateway requires secret_file");
            }
            config.gateway_secret_file = std::move(secret_file);
            std::string previous_file;
            if (gateway.lookupValue("previous_secret_file", previous_file)) {
                config.gateway_previous_secret_file = std::move(previous_file);
            }
        }
    } catch (const libconfig::SettingTypeException&) {
        return bootstrap_failure("gui.cfg contains a value with the wrong type");
    }
    if (!valid_bind_address(config.bind_address)) {
        return bootstrap_failure("gui.backend.bind_address must be an IPv4 literal");
    }
    return {std::move(config), {}};
}

std::string usage() {
    return "Usage: smithproxy-gui [options]\n"
           "  --bind ADDRESS    listen address (127.0.0.1)\n"
           "  --port N          listen port (18082)\n"
           "  --base-path PATH  public URL prefix (/)\n"
           "  --assets PATH     frontend asset directory (build/frontend)\n"
           "  --config FILE     GUI configuration exposed from the active CFtar\n"
           "\nSmithproxy credentials are read only from SMITHPROXY_API_URL,\n"
           "SMITHPROXY_API_KEY and SMITHPROXY_CA_CERT. A trusted reverse proxy\n"
           "must authenticate non-loopback browser APIs with SMITHPROXY_GUI_GATEWAY_SECRET.\n"
           "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS supports bounded rotation overlap.\n"
           "SMITHPROXY_CLI optionally identifies the existing libcli2 broker as host:port.\n"
           "gui.cfg may provide the same bootstrap settings while referencing protected\n"
           "boot-time credential files; it never contains the live tokens themselves.\n";
}

} // namespace smithproxy::gui
