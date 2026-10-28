#include "config.hpp"
#include "json.hpp"
#include "path.hpp"
#include "runtime_metrics.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

using namespace smithproxy::gui;

int main() {
    unsetenv("SMITHPROXY_API_URL");
    unsetenv("SMITHPROXY_API_KEY");
    unsetenv("SMITHPROXY_CA_CERT");
    assert(normalize_base_path("/") == "/");
    assert(normalize_base_path("/ws001/smithproxy-gui/") == "/ws001/smithproxy-gui");
    assert(!normalize_base_path("ws001"));
    assert(!normalize_base_path("/ws001/../gui"));
    assert(!normalize_base_path("/ws001//gui"));

    assert(path_below_base("/ws001/gui", "/ws001/gui") == "/");
    assert(path_below_base("/ws001/gui/assets/a.js", "/ws001/gui") == "/assets/a.js");
    assert(!path_below_base("/ws001/gui-evil", "/ws001/gui"));

    const std::filesystem::path root("/srv/gui");
    assert(safe_asset_path(root, "/assets/app.js") == root / "assets/app.js");
    assert(!safe_asset_path(root, "/../secret"));
    assert(!safe_asset_path(root, "/%2e%2e/secret"));
    assert(!safe_asset_path(root, "/assets%2fsecret"));
    assert(!safe_asset_path(root, "/assets\\secret"));

    assert(json_string("line\n\"quoted\"") == "\"line\\n\\\"quoted\\\"\"");

    const auto metrics = parse_listener_metrics(R"({"listeners":[
        {"name":"tcp","workers":2,"sessions_total":12,"sessions_active":3,
         "bytes_up":1024,"bytes_down":2048},
        {"name":"tls","workers":1,"sessions_total":7,"sessions_active":1,
         "bytes_up":512,"bytes_down":256}
    ]})");
    assert(metrics.metrics);
    assert(metrics.metrics->listeners.size() == 2U);
    assert(metrics.metrics->workers == 3U);
    assert(metrics.metrics->sessions_total == 19U);
    assert(metrics.metrics->sessions_active == 4U);
    assert(metrics.metrics->bytes_up == 1536U);
    assert(metrics.metrics->bytes_down == 2304U);
    assert(!parse_listener_metrics("not json").metrics);
    assert(!parse_listener_metrics(R"({"listeners":[{"name":"tcp","workers":1,
        "sessions_total":1,"sessions_active":2,"bytes_up":0,"bytes_down":0}]})").metrics);
    assert(!parse_listener_metrics(R"({"listeners":[
        {"name":"tcp","workers":1,"sessions_total":1,"sessions_active":0,"bytes_up":0,"bytes_down":0},
        {"name":"tcp","workers":1,"sessions_total":1,"sessions_active":0,"bytes_up":0,"bytes_down":0}
    ]})").metrics);

    std::vector<std::string> arguments{"smithproxy-gui", "--base-path", "/", "--port", "18082"};
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    const auto parsed = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(parsed.config);
    assert(parsed.config->base_path == "/");
    assert(parsed.config->port == 18082);
    return 0;
}
