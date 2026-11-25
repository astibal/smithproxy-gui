#include "config.hpp"

#include "path.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <libconfig.h++>
#include <openssl/crypto.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <initializer_list>
#include <string_view>
#include <utility>
#include <vector>

namespace smithproxy::gui {
namespace {

constexpr std::string_view default_api_token_file = "/run/smithproxy/gui-api.key";
constexpr std::string_view default_previous_api_token_file =
    "/run/smithproxy/gui-api.previous.key";
constexpr std::string_view default_gateway_secret_file =
    "/run/smithproxy/gui-gateway.key";
constexpr std::string_view default_previous_gateway_secret_file =
    "/run/smithproxy/gui-gateway.previous.key";

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

// Secrets supplied for compatibility are consumed during bootstrap so child
// processes and later diagnostics cannot recover them from the environment.
std::optional<std::string> consume_environment_secret(const char* name) {
    auto value = environment(name);
    ::unsetenv(name);
    return value;
}

struct ProtectedFileResult {
    std::optional<std::string> value;
    std::string error;
};

bool valid_header_value(std::string_view value);

bool trusted_group(const gid_t group) {
    if(group == ::getegid()) return true;
    const int count = ::getgroups(0, nullptr);
    if(count <= 0) return false;
    std::vector<gid_t> groups(static_cast<std::size_t>(count));
    if(::getgroups(count, groups.data()) != count) return false;
    return std::find(groups.begin(), groups.end(), group) != groups.end();
}

bool valid_bootstrap_path(const std::optional<std::string>& value) {
    if (!value || value->empty() || value->size() > 4096U || value->front() != '/') return false;
    return valid_header_value(*value);
}

bool valid_credential_generation_layout(
    const std::optional<std::string>& current,
    const std::optional<std::string>& previous) {
    if(!current || !previous || current == previous) return false;
    return std::filesystem::path(*current).parent_path() ==
        std::filesystem::path(*previous).parent_path();
}

bool valid_unix_socket_path(const std::string_view value) {
    const bool absolute_path = !value.empty() && value.front() == '/';
    const bool fits_socket_address = value.size() < sizeof(sockaddr_un::sun_path);
    return absolute_path && fits_socket_address && valid_header_value(value);
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
    const bool trusted_owner = metadata.st_uid == ::geteuid() ||
        (!secret && metadata.st_uid == 0U) || (secret && trusted_group(metadata.st_gid));
    const bool unsafe_mode = secret ? (metadata.st_mode & 0027) != 0 : (metadata.st_mode & 0022) != 0;
    if (!S_ISREG(metadata.st_mode) || !trusted_owner || unsafe_mode ||
        metadata.st_size <= 0 || static_cast<std::uintmax_t>(metadata.st_size) > maximum_size) {
        ::close(descriptor);
        return {std::nullopt, std::string(label) +
            (secret ? " must be a trusted 0600/0640 regular file" : " must be a trusted non-writable regular file")};
    }
    std::string value(static_cast<std::size_t>(metadata.st_size), '\0');
    std::size_t offset = 0U;
    while (offset < value.size()) {
        const auto count = ::read(descriptor, value.data() + offset, value.size() - offset);
        const bool interrupted = count < 0 && errno == EINTR;
        if (interrupted) continue;
        const bool incomplete_read = count <= 0;
        if (incomplete_read) {
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

// Validate the small authority subset accepted by the GUI bootstrap contract.
// API endpoints never carry credentials or paths and an explicit port, when
// present, must be usable by the Smithproxy client after a service restart.
bool valid_api_authority(const std::string_view authority) {
    if(authority.empty()) return false;
    std::string_view port;
    if(authority.starts_with('[')) {
        const auto closing = authority.find(']');
        if(closing == std::string_view::npos || closing == 1U) return false;
        const auto suffix = authority.substr(closing + 1U);
        if(suffix.empty()) return true;
        if(!suffix.starts_with(':') || suffix.size() == 1U) return false;
        port = suffix.substr(1U);
    } else {
        const auto separator = authority.rfind(':');
        if(separator == std::string_view::npos) return true;
        const bool ambiguous_authority = separator == 0U ||
            authority.find(':') != separator || separator + 1U == authority.size();
        if(ambiguous_authority) return false;
        port = authority.substr(separator + 1U);
    }
    unsigned parsed_port{};
    const auto [end, error] = std::from_chars(
        port.data(), port.data() + port.size(), parsed_port);
    return error == std::errc{} && end == port.data() + port.size() &&
        parsed_port >= 1U && parsed_port <= 65535U;
}

bool valid_api_url(const std::string_view url) {
    if (!(url.starts_with("https://") || is_loopback_http(url)) ||
        url.find_first_of(" \t\r\n?#@") != std::string_view::npos) {
        return false;
    }
    const auto authority = url.find("://") + 3U;
    const auto slash = url.find('/', authority);
    const auto authority_end = slash == std::string_view::npos ? url.size() : slash;
    return valid_api_authority(url.substr(authority, authority_end - authority)) &&
        (slash == std::string_view::npos || slash == url.size() - 1U);
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
    if (!is_loopback_bind(config.bind_address) && !config.gateway_credential) {
        error = "non-loopback bind requires SMITHPROXY_GUI_GATEWAY_SECRET";
        return false;
    }
    return true;
}

} // namespace

RuntimeCredentialPair::RuntimeCredentialPair(
    std::filesystem::path current_path,
    std::optional<std::filesystem::path> previous_path,
    const Source source)
    : current_path_(std::move(current_path)), previous_path_(std::move(previous_path)) {
    (void)source;
    refresh(true);
}

RuntimeCredentialPair::RuntimeCredentialPair(
    std::string current, std::optional<std::string> previous)
    : current_(std::move(current)), previous_(std::move(previous)),
      checked_at_(std::chrono::steady_clock::now()) {}

bool RuntimeCredentialPair::refresh(const bool force) const {
    auto lock = std::scoped_lock(mutex_);
    if(current_path_.empty()) return current_.has_value();
    const auto now = std::chrono::steady_clock::now();
    if(!force && checked_at_ != std::chrono::steady_clock::time_point{} &&
       now - checked_at_ < std::chrono::seconds(5)) return current_.has_value();
    checked_at_ = now;

    const auto load_credential = [](const std::filesystem::path& path,
                                    const std::string_view label) {
        auto loaded = read_protected_file(path, label, 258U);
        const bool valid_size = loaded.value && loaded.value->size() >= 32U &&
            loaded.value->size() <= 256U;
        if(!valid_size) loaded.value.reset();
        return loaded.value;
    };
    current_ = load_credential(current_path_, "GUI Smithproxy runtime credential");
    previous_.reset();
    if(previous_path_) {
        previous_ = load_credential(
            *previous_path_, "Previous GUI Smithproxy runtime credential");
    }
    if(previous_ && current_ && *previous_ == *current_) previous_.reset();
    return current_.has_value();
}

std::optional<std::string> RuntimeCredentialPair::current() const {
    refresh();
    auto lock = std::scoped_lock(mutex_);
    return current_;
}

bool RuntimeCredentialPair::accepts(const std::string_view supplied) const {
    refresh();
    const auto matches = [supplied](const std::optional<std::string>& expected) {
        return expected && supplied.size() == expected->size() &&
            CRYPTO_memcmp(supplied.data(), expected->data(), supplied.size()) == 0;
    };
    {
        auto lock = std::scoped_lock(mutex_);
        if(matches(current_) || matches(previous_)) return true;
        const auto now = std::chrono::steady_clock::now();
        const bool recently_rechecked = rejected_checked_at_ !=
                std::chrono::steady_clock::time_point{} &&
            now - rejected_checked_at_ < std::chrono::seconds(1);
        if(recently_rechecked || current_path_.empty()) return false;
        rejected_checked_at_ = now;
    }

    // A rotation can occur between ordinary polls. Re-read once immediately
    // after rejection, rate-limited above so invalid public requests cannot
    // turn credential validation into unbounded filesystem I/O.
    refresh(true);
    auto lock = std::scoped_lock(mutex_);
    return matches(current_) || matches(previous_);
}

bool RuntimeCredentialPair::loaded() const {
    refresh();
    auto lock = std::scoped_lock(mutex_);
    return current_.has_value();
}

bool RuntimeCredentialPair::previous_loaded() const {
    refresh();
    auto lock = std::scoped_lock(mutex_);
    return previous_.has_value();
}

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
    auto api_key = consume_environment_secret("SMITHPROXY_API_KEY");
    auto gateway_secret = consume_environment_secret("SMITHPROXY_GUI_GATEWAY_SECRET");
    auto previous_gateway_secret =
        consume_environment_secret("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS");

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
    const auto ca = environment("SMITHPROXY_CA_CERT");
    const auto configured_values = static_cast<unsigned>(url.has_value()) +
                                   static_cast<unsigned>(api_key.has_value()) +
                                   static_cast<unsigned>(ca.has_value());
    if (configured_values != 0U && configured_values != 3U) {
        return failure("SMITHPROXY_API_URL, SMITHPROXY_API_KEY and SMITHPROXY_CA_CERT must be set together");
    }
    if (configured_values == 3U) {
        if (!valid_api_url(*url)) {
            return failure("Smithproxy API URL must use HTTPS (HTTP is allowed only on loopback)");
        }
        if (!valid_header_value(*api_key)) return failure("SMITHPROXY_API_KEY contains invalid characters");
        std::error_code error;
        if (!std::filesystem::is_regular_file(*ca, error) || error) {
            return failure("SMITHPROXY_CA_CERT is not a readable regular file");
        }
        std::ifstream certificate(*ca);
        if (!certificate) return failure("SMITHPROXY_CA_CERT is not readable");
        std::string normalized_url = *url;
        while (normalized_url.ends_with('/')) normalized_url.pop_back();
        config.smithproxy = SmithproxyConfig{
            std::move(normalized_url),
            std::make_shared<RuntimeCredentialPair>(*api_key),
            *ca};
    }
    if (const auto cli = environment("SMITHPROXY_CLI")) {
        config.smithproxy_cli = parse_cli_endpoint(*cli);
        if (!config.smithproxy_cli) {
            return failure("SMITHPROXY_CLI must use host:port or [IPv6]:port");
        }
    }
    if (gateway_secret) {
        if (gateway_secret->size() < 32U || gateway_secret->size() > 256U ||
            !valid_header_value(*gateway_secret)) {
            return failure("SMITHPROXY_GUI_GATEWAY_SECRET must contain 32..256 safe header characters");
        }
        if (previous_gateway_secret &&
            (previous_gateway_secret->size() < 32U ||
             previous_gateway_secret->size() > 256U ||
             !valid_header_value(*previous_gateway_secret))) {
            return failure(
                "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS must contain 32..256 safe header characters");
        }
        if(previous_gateway_secret && *previous_gateway_secret == *gateway_secret)
            return failure("current and previous gateway secrets must differ");
        config.gateway_credential = std::make_shared<RuntimeCredentialPair>(
            std::move(*gateway_secret), std::move(previous_gateway_secret));
    }
    else if(previous_gateway_secret) {
        return failure("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS requires the current secret");
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
    config.startup_bootstrap = persistent;

    if (persistent.api_url) {
        const auto certificate = read_protected_file(
            *persistent.ca_cert, "GUI Smithproxy CA certificate", 1024U * 1024U, false);
        if (!certificate.value) return failure(certificate.error);
        config.smithproxy = SmithproxyConfig{
            *persistent.api_url,
            persistent.api_credential_enabled
                ? std::make_shared<RuntimeCredentialPair>(
                    *persistent.api_token_file,
                    persistent.previous_api_token_file
                        ? std::optional<std::filesystem::path>{
                            *persistent.previous_api_token_file}
                        : std::nullopt,
                    RuntimeCredentialPair::Source::Files)
                : nullptr,
            *persistent.ca_cert};
        if (persistent.cli_endpoint) {
            config.smithproxy_cli = parse_cli_endpoint(*persistent.cli_endpoint);
        }
    }
    if (persistent.gateway_secret_file) {
        if(persistent.gateway_credential_enabled) {
            config.gateway_credential = std::make_shared<RuntimeCredentialPair>(
                *persistent.gateway_secret_file,
                persistent.gateway_previous_secret_file
                    ? std::optional<std::filesystem::path>{
                        *persistent.gateway_previous_secret_file}
                    : std::nullopt,
                RuntimeCredentialPair::Source::Files);
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
                gui, {"schema_version", "backend", "frontend", "smithproxy", "gateway"})) {
            return bootstrap_failure("gui.cfg contains unsupported gui setting: " + *member);
        }
        int schema_version = config.schema_version;
        gui.lookupValue("schema_version", schema_version);
        if (schema_version < 1 || schema_version > 5) {
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
                    upstream, {"api_url", "ca_cert", "api_token_file",
                               "previous_api_token_file", "cli_endpoint",
                               "credential_enabled",
                               "credential_bootstrap_freshness_seconds",
                               "credential_rotation_seconds",
                               "credential_overlap_seconds",
                               "administrator_auth_socket_enabled",
                               "administrator_auth_socket"})) {
                return bootstrap_failure(
                    "gui.smithproxy contains unsupported setting: " + *member);
            }
            std::string api_url;
            std::string ca_cert;
            std::string api_token_file(default_api_token_file);
            if (!upstream.lookupValue("api_url", api_url) ||
                !upstream.lookupValue("ca_cert", ca_cert)) {
                return bootstrap_failure(
                    "gui.smithproxy requires api_url and ca_cert");
            }
            const bool api_token_file_configured =
                upstream.lookupValue("api_token_file", api_token_file);
            if (!valid_api_url(api_url)) {
                return bootstrap_failure(
                    "gui.smithproxy.api_url must use HTTPS or loopback HTTP");
            }
            while (api_url.ends_with('/')) api_url.pop_back();
            config.api_url = std::move(api_url);
            config.ca_cert = std::move(ca_cert);
            config.api_token_file = std::move(api_token_file);
            std::string previous_api_token_file(default_previous_api_token_file);
            const bool previous_api_token_file_configured =
                upstream.lookupValue("previous_api_token_file", previous_api_token_file);
            if(api_token_file_configured && !previous_api_token_file_configured) {
                previous_api_token_file = *config.api_token_file + ".previous";
            }
            config.previous_api_token_file = std::move(previous_api_token_file);
            upstream.lookupValue("credential_enabled", config.api_credential_enabled);
            const auto read_seconds = [&upstream](const char* name, std::uint32_t& destination) {
                long long value = destination;
                if(upstream.lookupValue(name, value)) {
                    if(value <= 0 || value > 31536000LL)
                        throw std::out_of_range(name);
                    destination = static_cast<std::uint32_t>(value);
                }
            };
            read_seconds("credential_bootstrap_freshness_seconds",
                         config.api_credential_bootstrap_freshness_seconds);
            read_seconds("credential_rotation_seconds", config.api_credential_rotation_seconds);
            read_seconds("credential_overlap_seconds", config.api_credential_overlap_seconds);
            upstream.lookupValue(
                "administrator_auth_socket_enabled",
                config.administrator_auth_socket_enabled);
            upstream.lookupValue(
                "administrator_auth_socket",
                config.administrator_auth_socket);
            const bool auth_socket_configured =
                upstream.exists("administrator_auth_socket_enabled") ||
                upstream.exists("administrator_auth_socket");
            if(auth_socket_configured && schema_version < 5) {
                return bootstrap_failure(
                    "gui.smithproxy administrator auth socket requires schema_version 5");
            }
            if (!valid_bootstrap_path(config.ca_cert) ||
                !valid_bootstrap_path(config.api_token_file) ||
                !valid_bootstrap_path(config.previous_api_token_file)) {
                return bootstrap_failure(
                    "gui.smithproxy credential paths must be absolute and safe");
            }
            if(!valid_credential_generation_layout(
                   config.api_token_file, config.previous_api_token_file)) {
                return bootstrap_failure(
                    "gui.smithproxy credential generations must use distinct files in one directory");
            }
            if(!valid_unix_socket_path(config.administrator_auth_socket)) {
                return bootstrap_failure(
                    "gui.smithproxy administrator auth socket path is invalid");
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
                    gateway, {"secret_file", "previous_secret_file", "credential_enabled",
                              "credential_bootstrap_freshness_seconds",
                              "credential_rotation_seconds", "credential_overlap_seconds"})) {
                return bootstrap_failure("gui.gateway contains unsupported setting: " + *member);
            }
            std::string secret_file(default_gateway_secret_file);
            const bool secret_file_configured =
                gateway.lookupValue("secret_file", secret_file);
            config.gateway_secret_file = std::move(secret_file);
            gateway.lookupValue("credential_enabled", config.gateway_credential_enabled);
            if (!valid_bootstrap_path(config.gateway_secret_file)) {
                return bootstrap_failure("gui.gateway.secret_file must use an absolute safe path");
            }
            std::string previous_file(default_previous_gateway_secret_file);
            const bool previous_file_configured =
                gateway.lookupValue("previous_secret_file", previous_file);
            if(secret_file_configured && !previous_file_configured) {
                previous_file = *config.gateway_secret_file + ".previous";
            }
            config.gateway_previous_secret_file = std::move(previous_file);
            if (!valid_bootstrap_path(config.gateway_previous_secret_file)) {
                return bootstrap_failure(
                    "gui.gateway.previous_secret_file must use an absolute safe path");
            }
            if (config.gateway_previous_secret_file == config.gateway_secret_file) {
                return bootstrap_failure(
                    "gui.gateway current and previous credential files must differ");
            }
            if(!valid_credential_generation_layout(
                   config.gateway_secret_file, config.gateway_previous_secret_file)) {
                return bootstrap_failure(
                    "gui.gateway credential generations must use one directory");
            }

            const auto read_seconds = [&gateway](const char* name, std::uint32_t& destination) {
                long long value = destination;
                if(gateway.lookupValue(name, value)) {
                    if(value <= 0 || value > 31536000LL)
                        throw std::out_of_range(name);
                    destination = static_cast<std::uint32_t>(value);
                }
            };
            read_seconds("credential_bootstrap_freshness_seconds",
                         config.gateway_credential_bootstrap_freshness_seconds);
            read_seconds("credential_rotation_seconds", config.gateway_credential_rotation_seconds);
            read_seconds("credential_overlap_seconds", config.gateway_credential_overlap_seconds);
        }
    } catch (const libconfig::SettingTypeException&) {
        return bootstrap_failure("gui.cfg contains a value with the wrong type");
    } catch (const std::out_of_range&) {
        return bootstrap_failure("GUI credential timing must use 1..31536000 seconds");
    }
    if (!valid_bind_address(config.bind_address)) {
        return bootstrap_failure("gui.backend.bind_address must be an IPv4 literal");
    }
    if (!is_loopback_bind(config.bind_address) &&
        (!config.gateway_secret_file || !config.gateway_credential_enabled)) {
        return bootstrap_failure(
            "gui.backend non-loopback bind requires gui.gateway.secret_file");
    }
    if(config.api_token_file && config.gateway_secret_file &&
       (*config.api_token_file == *config.gateway_secret_file ||
        (config.previous_api_token_file &&
         *config.previous_api_token_file == *config.gateway_secret_file) ||
        (config.gateway_previous_secret_file &&
         (*config.api_token_file == *config.gateway_previous_secret_file ||
          (config.previous_api_token_file &&
           *config.previous_api_token_file == *config.gateway_previous_secret_file))))) {
        return bootstrap_failure(
            "GUI API token and gateway credentials must use separate files");
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
    const auto schema_version = 5U;
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
            ";\n    credential_enabled = " +
            std::string(config.api_credential_enabled ? "true" : "false") +
            ";\n    api_token_file = " + quote(*config.api_token_file) + ";\n";
        if(config.previous_api_token_file)
            source += "    previous_api_token_file = " +
                quote(*config.previous_api_token_file) + ";\n";
        source += "    credential_bootstrap_freshness_seconds = " +
            std::to_string(config.api_credential_bootstrap_freshness_seconds) + "L;\n";
        source += "    credential_rotation_seconds = " +
            std::to_string(config.api_credential_rotation_seconds) + "L;\n";
        source += "    credential_overlap_seconds = " +
            std::to_string(config.api_credential_overlap_seconds) + "L;\n";
        source += "    administrator_auth_socket_enabled = " +
            std::string(config.administrator_auth_socket_enabled ? "true" : "false") +
            ";\n";
        source += "    administrator_auth_socket = " +
            quote(config.administrator_auth_socket) + ";\n";
        if(config.cli_endpoint && !config.cli_endpoint->empty())
            source += "    cli_endpoint = " + quote(*config.cli_endpoint) + ";\n";
        source += "  };\n";
    }
    if(config.gateway_secret_file) {
        source += "\n  gateway = {\n    credential_enabled = " +
            std::string(config.gateway_credential_enabled ? "true" : "false") +
            ";\n    secret_file = " + quote(*config.gateway_secret_file) + ";\n";
        if(config.gateway_previous_secret_file && !config.gateway_previous_secret_file->empty())
            source += "    previous_secret_file = " + quote(*config.gateway_previous_secret_file) + ";\n";
        source += "    credential_bootstrap_freshness_seconds = " +
            std::to_string(config.gateway_credential_bootstrap_freshness_seconds) + "L;\n";
        source += "    credential_rotation_seconds = " +
            std::to_string(config.gateway_credential_rotation_seconds) + "L;\n";
        source += "    credential_overlap_seconds = " +
            std::to_string(config.gateway_credential_overlap_seconds) + "L;\n  };\n";
    }
    source += "};\n";
    const auto reparsed = parse_gui_bootstrap(source);
    if(!reparsed.config) return std::nullopt;
    return source;
}

bool gui_bootstrap_restart_required(
    const AppConfig& active, const std::optional<GuiBootstrapConfig>& saved) {
    if(!active.startup_bootstrap) return saved.has_value();
    if(!saved) return true;

    const auto& boot = *active.startup_bootstrap;
    const auto& next = *saved;
    return boot.schema_version != next.schema_version ||
        boot.bind_address != next.bind_address || boot.port != next.port ||
        boot.base_path != next.base_path || boot.asset_root != next.asset_root ||
        boot.api_url != next.api_url || boot.ca_cert != next.ca_cert ||
        boot.api_token_file != next.api_token_file ||
        boot.previous_api_token_file != next.previous_api_token_file ||
        boot.api_credential_enabled != next.api_credential_enabled ||
        boot.api_credential_bootstrap_freshness_seconds !=
            next.api_credential_bootstrap_freshness_seconds ||
        boot.api_credential_rotation_seconds != next.api_credential_rotation_seconds ||
        boot.api_credential_overlap_seconds != next.api_credential_overlap_seconds ||
        boot.administrator_auth_socket_enabled !=
            next.administrator_auth_socket_enabled ||
        boot.administrator_auth_socket != next.administrator_auth_socket ||
        boot.cli_endpoint != next.cli_endpoint ||
        boot.gateway_secret_file != next.gateway_secret_file ||
        boot.gateway_previous_secret_file != next.gateway_previous_secret_file ||
        boot.gateway_credential_enabled != next.gateway_credential_enabled ||
        boot.gateway_credential_bootstrap_freshness_seconds !=
            next.gateway_credential_bootstrap_freshness_seconds ||
        boot.gateway_credential_rotation_seconds != next.gateway_credential_rotation_seconds ||
        boot.gateway_credential_overlap_seconds != next.gateway_credential_overlap_seconds;
}

std::string usage() {
    return "Usage: smithproxy-gui [options]\n"
           "  --bind ADDRESS    listen address (127.0.0.1)\n"
           "  --port N          listen port (18082)\n"
           "  --base-path PATH  public URL prefix (/)\n"
           "  --assets PATH     frontend asset directory (build/frontend)\n"
           "  --config FILE     GUI configuration exposed from the active CFtar\n"
           "\nNative deployments use core-owned gui.cfg plus protected boot-time\n"
           "credential files. SMITHPROXY_API_URL, SMITHPROXY_API_KEY and\n"
           "SMITHPROXY_CA_CERT remain a compatibility bootstrap. A trusted reverse proxy\n"
           "must authenticate non-loopback browser APIs with SMITHPROXY_GUI_GATEWAY_SECRET.\n"
           "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS supports bounded rotation overlap.\n"
           "SMITHPROXY_CLI optionally identifies the existing libcli2 broker as host:port.\n"
           "gui.cfg may provide the same bootstrap settings while referencing protected\n"
           "boot-time credential files; it never contains the live tokens themselves.\n";
}

} // namespace smithproxy::gui
