#include "config.hpp"
#include "config_snapshot.hpp"
#include "json.hpp"
#include "live_sessions.hpp"
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
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");
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

    const auto activity = parse_live_sessions(R"([
        {"oid":"private-session","origin":"tls acceptor","policy":"internal-policy",
         "left":[{"host":"10.0.0.10","port":"43100","com":"tls"}],
         "right":[{"host":"private.example","port":"443","com":"tls"}],
         "stats":{"speed":{"up":100,"down":200},
                  "counters":{"bytes_up":1000,"bytes_down":2000}}},
        {"oid":"another-session","origin":"tls acceptor","policy":"other-policy",
         "left":[{"host":"10.0.0.11","port":"43101","com":"tls"}],
         "right":[{"host":"secret.example","port":"443","com":"tls"}],
         "stats":{"speed":{"up":50,"down":75},
                  "counters":{"bytes_up":500,"bytes_down":750}}}
    ])");
    assert(activity.snapshot);
    assert(activity.snapshot->total == 2U);
    assert(activity.snapshot->speed_up == 150U);
    assert(activity.snapshot->speed_down == 275U);
    assert(activity.snapshot->protocols.size() == 1U);
    assert(activity.snapshot->protocols.front().protocol == "tls");
    assert(activity.snapshot->protocols.front().sessions == 2U);
    assert(!parse_live_sessions("not json").snapshot);
    assert(!parse_live_sessions(R"([{"left":[{"com":"tls"}],"right":[{"com":"tls"}],
        "stats":{"speed":{"up":-1,"down":0},"counters":{"bytes_up":0,"bytes_down":0}}}])").snapshot);

    const auto configuration = parse_config_snapshot(
        R"({"success":{"policy":[{"name":"office policy","disabled":"0","proto":"tcp","src":["office"],"sport":["any"],"dst":["internet"],"dport":["https"],"action":"accept","nat":"masquerade","routing":"main","tls_profile":"inspect"}]}})",
        R"({"success":{"address_objects":{"office":{"type":"cidr","value":"10.0.0.0/24"},"internet":{"type":"fqdn","value":"example.test"}}}})",
        R"({"success":{"port_objects":{"https":{"start":"443","end":"443"}}}})",
        R"({"success":{"proto_objects":{"tcp":{"id":"6"}}}})");
    assert(configuration.snapshot);
    assert(configuration.snapshot->policies.size() == 1U);
    assert(configuration.snapshot->policies.front().name == "office policy");
    assert(configuration.snapshot->policies.front().enabled);
    assert(configuration.snapshot->policies.front().sources == std::vector<std::string>{"office"});
    assert(configuration.snapshot->addresses.size() == 2U);
    assert(configuration.snapshot->ports.front().start == 443U);
    assert(configuration.snapshot->protocols.front().number == 6U);

    const auto legacy_address = parse_config_snapshot(
        R"({"success":{"policy":[]}})",
        R"({"success":{"address_objects":{"legacy":{"type":"0","cidr":"192.0.2.1/32"}}}})",
        R"({"success":{"port_objects":{}}})",
        R"({"success":{"proto_objects":{}}})");
    assert(legacy_address.snapshot);
    assert(legacy_address.snapshot->addresses.front().type == "cidr");
    assert(!parse_config_snapshot("{}", "{}", "{}", "{}").snapshot);
    assert(!parse_config_snapshot(
        R"({"success":{"policy":[]}})", R"({"success":{"address_objects":{}}})",
        R"({"success":{"port_objects":{"bad":{"start":"2","end":"1"}}}})",
        R"({"success":{"proto_objects":{}}})").snapshot);

    std::vector<std::string> arguments{"smithproxy-gui", "--base-path", "/", "--port", "18082"};
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    const auto parsed = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(parsed.config);
    assert(parsed.config->base_path == "/");
    assert(parsed.config->port == 18082);

    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "short", 1);
    const auto invalid_secret = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(!invalid_secret.config);
    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "0123456789abcdef0123456789abcdef", 1);
    const auto authenticated = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(authenticated.config);
    assert(authenticated.config->gateway_secret == "0123456789abcdef0123456789abcdef");
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");
    return 0;
}
