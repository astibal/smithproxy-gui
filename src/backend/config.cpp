#include "config.hpp"

#include "path.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <libconfig.h++>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <initializer_list>
#include <set>
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

bool valid_administrator_name(const std::string_view value) {
    return !value.empty() && value.size() <= 64U &&
        std::all_of(value.begin(), value.end(), [](const unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '.' ||
                   character == '_' || character == '-' || character == '@';
        });
}

bool lowercase_hexadecimal(const std::string_view value, const std::size_t length) {
    return value.size() == length &&
        std::all_of(value.begin(), value.end(), [](const unsigned char character) {
            return (character >= '0' && character <= '9') ||
                   (character >= 'a' && character <= 'f');
        });
}

bool valid_bootstrap_path(const std::optional<std::string>& value) {
    if (!value || value->empty() || value->size() > 4096U || value->front() != '/') return false;
    return valid_header_value(*value);
}

// Rejects fields that this binary cannot preserve. An older GUI must fail
// closed instead of silently erasing configuration introduced by a newer one.
std::optional<std::string> unknown_member(
    const libconfig::Setting& group,
    const std::initializer_list<std::string_view> allowed) {
    for (int index = 0; index < group.getLength(); ++index) {
        const auto* name = group[index].getName();
        if (name == nullptr) return "unnamed value";
        bool known = false;
        for (const auto candidate : allowed) {
            if (candidate == name) {
                known = true;
                break;
            }
        }
        if (!known) return std::string(name);
    }
    return std::nullopt;
}

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
    config.asset_root = persistent.asset_root.value_or(default_asset_root.string());
    config.gui_config_path = path;
    config.administrators = persistent.administrators;

    if (persistent.api_url) {
        const auto certificate = read_protected_file(
            *persistent.ca_cert, "GUI Smithproxy CA certificate", 1024U * 1024U, false);
        if (!certificate.value) return failure(certificate.error);
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
    if (const auto member = unknown_member(root, {"gui"})) {
        return bootstrap_failure("gui.cfg contains unsupported root setting: " + *member);
    }
    if (!root.exists("gui") || root["gui"].getType() != libconfig::Setting::TypeGroup) {
        return bootstrap_failure("gui.cfg must contain a gui group");
    }

    const auto& gui = root["gui"];
    GuiBootstrapConfig config;
    try {
        if (const auto member = unknown_member(
                gui, {"schema_version", "backend", "frontend", "smithproxy", "gateway", "administrators"})) {
            return bootstrap_failure("gui.cfg contains unsupported gui setting: " + *member);
        }
        int schema_version = config.schema_version;
        gui.lookupValue("schema_version", schema_version);
        if (schema_version != 1 && schema_version != 2 && schema_version != 3) {
            return bootstrap_failure("gui.schema_version is unsupported");
        }
        config.schema_version = static_cast<std::uint16_t>(schema_version);
        if (gui.exists("backend")) {
            const auto& backend = gui["backend"];
            if (backend.getType() != libconfig::Setting::TypeGroup) {
                return bootstrap_failure("gui.backend must be a group");
            }
            if (const auto member = unknown_member(
                    backend, {"bind_address", "port", "base_path"})) {
                return bootstrap_failure("gui.backend contains unsupported setting: " + *member);
            }
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
        if (gui.exists("frontend")) {
            if(schema_version < 3) {
                return bootstrap_failure("gui.frontend requires schema_version 3");
            }
            const auto& frontend = gui["frontend"];
            if(frontend.getType() != libconfig::Setting::TypeGroup) {
                return bootstrap_failure("gui.frontend must be a group");
            }
            if(const auto member = unknown_member(frontend, {"asset_root"})) {
                return bootstrap_failure("gui.frontend contains unsupported setting: " + *member);
            }
            std::string asset_root;
            if(!frontend.lookupValue("asset_root", asset_root) ||
               !valid_bootstrap_path(std::optional<std::string>{asset_root})) {
                return bootstrap_failure("gui.frontend.asset_root must use an absolute safe path");
            }
            config.asset_root = std::move(asset_root);
        }
        if (gui.exists("smithproxy")) {
            const auto& upstream = gui["smithproxy"];
            if (upstream.getType() != libconfig::Setting::TypeGroup) {
                return bootstrap_failure("gui.smithproxy must be a group");
            }
            if (const auto member = unknown_member(
                    upstream, {"api_url", "ca_cert", "api_token_file", "cli_endpoint"})) {
                return bootstrap_failure(
                    "gui.smithproxy contains unsupported setting: " + *member);
            }
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
            if (!valid_bootstrap_path(config.ca_cert) ||
                !valid_bootstrap_path(config.api_token_file)) {
                return bootstrap_failure(
                    "gui.smithproxy credential files must use absolute safe paths");
            }
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
            if (gateway.getType() != libconfig::Setting::TypeGroup) {
                return bootstrap_failure("gui.gateway must be a group");
            }
            if (const auto member = unknown_member(
                    gateway, {"secret_file", "previous_secret_file"})) {
                return bootstrap_failure("gui.gateway contains unsupported setting: " + *member);
            }
            std::string secret_file;
            if (!gateway.lookupValue("secret_file", secret_file)) {
                return bootstrap_failure("gui.gateway requires secret_file");
            }
            config.gateway_secret_file = std::move(secret_file);
            if (!valid_bootstrap_path(config.gateway_secret_file)) {
                return bootstrap_failure("gui.gateway.secret_file must use an absolute safe path");
            }
            std::string previous_file;
            if (gateway.lookupValue("previous_secret_file", previous_file)) {
                config.gateway_previous_secret_file = std::move(previous_file);
                if (!valid_bootstrap_path(config.gateway_previous_secret_file)) {
                    return bootstrap_failure(
                        "gui.gateway.previous_secret_file must use an absolute safe path");
                }
                if (config.gateway_previous_secret_file == config.gateway_secret_file) {
                    return bootstrap_failure(
                        "gui.gateway current and previous credential files must differ");
                }
            }
        }
        if(gui.exists("administrators")) {
            if(schema_version < 2) {
                return bootstrap_failure("gui.administrators requires schema_version 2");
            }
            const auto& administrators = gui["administrators"];
            if(administrators.getType() != libconfig::Setting::TypeList ||
               administrators.getLength() > 64) {
                return bootstrap_failure("gui.administrators must be a list with at most 64 entries");
            }
            std::set<std::string> names;
            for(int index = 0; index < administrators.getLength(); ++index) {
                const auto& entry = administrators[index];
                if(entry.getType() != libconfig::Setting::TypeGroup) {
                    return bootstrap_failure("gui.administrators entries must be groups");
                }
                if(const auto member = unknown_member(
                       entry, {"name", "algorithm", "salt", "verifier", "cost", "block_size", "parallelism"})) {
                    return bootstrap_failure("gui.administrators contains unsupported setting: " + *member);
                }
                GuiAdministratorConfig administrator;
                std::string algorithm;
                long long cost = 0;
                int block_size = 0;
                int parallelism = 0;
                if(!entry.lookupValue("name", administrator.name) ||
                   !entry.lookupValue("algorithm", algorithm) ||
                   !entry.lookupValue("salt", administrator.salt) ||
                   !entry.lookupValue("verifier", administrator.verifier) ||
                   !entry.lookupValue("cost", cost) ||
                   !entry.lookupValue("block_size", block_size) ||
                   !entry.lookupValue("parallelism", parallelism)) {
                    return bootstrap_failure("gui.administrators entry is incomplete");
                }
                const bool valid_cost = cost >= 16384 && cost <= 1048576 &&
                    (static_cast<std::uint64_t>(cost) & (static_cast<std::uint64_t>(cost) - 1U)) == 0U;
                if(!valid_administrator_name(administrator.name) || algorithm != "scrypt" ||
                   !lowercase_hexadecimal(administrator.salt, 32U) ||
                   !lowercase_hexadecimal(administrator.verifier, 64U) || !valid_cost ||
                   block_size < 8 || block_size > 32 || parallelism < 1 || parallelism > 16 ||
                   !names.insert(administrator.name).second) {
                    return bootstrap_failure("gui.administrators entry is invalid");
                }
                administrator.cost = static_cast<std::uint64_t>(cost);
                administrator.block_size = static_cast<std::uint32_t>(block_size);
                administrator.parallelism = static_cast<std::uint32_t>(parallelism);
                config.administrators.push_back(std::move(administrator));
            }
        }
    } catch (const libconfig::SettingTypeException&) {
        return bootstrap_failure("gui.cfg contains a value with the wrong type");
    }
    if (!valid_bind_address(config.bind_address)) {
        return bootstrap_failure("gui.backend.bind_address must be an IPv4 literal");
    }
    if (!is_loopback_bind(config.bind_address) && !config.gateway_secret_file) {
        return bootstrap_failure(
            "gui.backend non-loopback bind requires gui.gateway.secret_file");
    }
    return {std::move(config), {}};
}

std::optional<std::string> serialize_gui_bootstrap(const GuiBootstrapConfig& config) {
    const auto quote = [](const std::string_view value) {
        std::string output{"\""};
        output.reserve(value.size() + 2U);
        for(const char character : value) {
            if(character == '\\' || character == '"') output.push_back('\\');
            output.push_back(character);
        }
        output.push_back('"');
        return output;
    };
    const auto schema_version = config.asset_root ? 3U :
        config.administrators.empty() ? std::min<std::uint16_t>(config.schema_version, 2U) : 2U;
    std::string source = "gui = {\n  schema_version = " +
        std::to_string(schema_version) + ";\n\n";
    source += "  backend = {\n    bind_address = " + quote(config.bind_address) +
        ";\n    port = " + std::to_string(config.port) +
        ";\n    base_path = " + quote(config.base_path) + ";\n  };\n";
    if(config.asset_root) {
        source += "\n  frontend = {\n    asset_root = " + quote(*config.asset_root) + ";\n  };\n";
    }
    if(config.api_url) {
        if(!config.ca_cert || !config.api_token_file) return std::nullopt;
        source += "\n  smithproxy = {\n    api_url = " + quote(*config.api_url) +
            ";\n    ca_cert = " + quote(*config.ca_cert) +
            ";\n    api_token_file = " + quote(*config.api_token_file) + ";\n";
        if(config.cli_endpoint && !config.cli_endpoint->empty())
            source += "    cli_endpoint = " + quote(*config.cli_endpoint) + ";\n";
        source += "  };\n";
    }
    if(config.gateway_secret_file) {
        source += "\n  gateway = {\n    secret_file = " + quote(*config.gateway_secret_file) + ";\n";
        if(config.gateway_previous_secret_file && !config.gateway_previous_secret_file->empty())
            source += "    previous_secret_file = " + quote(*config.gateway_previous_secret_file) + ";\n";
        source += "  };\n";
    }
    if(!config.administrators.empty()) {
        source += "\n  administrators = (\n";
        for(std::size_t index = 0U; index < config.administrators.size(); ++index) {
            const auto& administrator = config.administrators[index];
            source += "    { name = " + quote(administrator.name) +
                "; algorithm = \"scrypt\"; salt = " + quote(administrator.salt) +
                "; verifier = " + quote(administrator.verifier) +
                "; cost = " + std::to_string(administrator.cost) +
                "L; block_size = " + std::to_string(administrator.block_size) +
                "; parallelism = " + std::to_string(administrator.parallelism) + "; }";
            source += index + 1U == config.administrators.size() ? "\n" : ",\n";
        }
        source += "  );\n";
    }
    source += "};\n";
    const auto reparsed = parse_gui_bootstrap(source);
    if(!reparsed.config) return std::nullopt;
    return source;
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
