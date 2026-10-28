#include "config.hpp"
#include "config_snapshot.hpp"
#include "draft_store.hpp"
#include "json.hpp"
#include "live_sessions.hpp"
#include "neighbor_metrics.hpp"
#include "path.hpp"
#include "runtime_metrics.hpp"
#include "tls_metrics.hpp"

#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <limits>
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

    DraftStore draft{"draft-test", "revision-7"};
    assert(draft.snapshot().version == 0U);
    assert(draft.snapshot().base_revision == "revision-7");
    assert(draft.upsert(0U, {"policy.[0].action", std::string("accept")}) ==
           DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 1U);
    assert(draft.upsert(0U, {"policy.[0].action", std::string("reject")}) ==
           DraftMutationResult::VersionConflict);
    assert(draft.upsert(1U, {"policy.[0].action", std::string("reject")}) ==
           DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 1U);
    assert(std::get<std::string>(draft.snapshot().changes.front().value) == "reject");
    assert(draft.upsert(2U, {"../unsafe", true}) == DraftMutationResult::InvalidPath);
    assert(draft.upsert(2U, {"settings.ratio", std::numeric_limits<double>::infinity()}) ==
           DraftMutationResult::InvalidValue);
    assert(draft.remove(2U, "settings.missing") == DraftMutationResult::Missing);
    assert(draft.remove(2U, "policy.[0].action") == DraftMutationResult::Applied);
    assert(draft.snapshot().changes.empty());
    assert(draft.clear(3U) == DraftMutationResult::Applied);
    assert(draft.snapshot().version == 4U);

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

    const auto tls_cache = parse_tls_cache_metrics(R"({"cache_size":42,"max_size":1000})");
    assert(tls_cache.metrics);
    assert(tls_cache.metrics->size == 42U);
    assert(tls_cache.metrics->capacity == 1000U);
    assert(!parse_tls_cache_metrics(R"({"cache_size":1001,"max_size":1000})").metrics);
    assert(!parse_tls_cache_metrics(R"({"cache_size":-1,"max_size":1000})").metrics);

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

    const auto neighbors = parse_neighbor_metrics(R"([
        {"hostname":"private.example","tags":"office","last_seen":1,"stats":[
            {"relative_days":0,"counter":3,"bytes_up":100,"bytes_down":200},
            {"relative_days":7,"counter":2,"bytes_up":50,"bytes_down":75}]},
        {"hostname":"another.private","tags":"","last_seen":1,"stats":[
            {"relative_days":3,"counter":4,"bytes_up":10,"bytes_down":20}]}
    ])");
    assert(neighbors.metrics);
    assert(neighbors.metrics->hosts_total == 2U);
    assert(neighbors.metrics->active_today == 1U);
    assert(neighbors.metrics->active_week == 2U);
    assert(neighbors.metrics->observations == 9U);
    assert(neighbors.metrics->bytes_down == 295U);
    assert(!parse_neighbor_metrics(R"([{"hostname":"duplicate","tags":"","last_seen":1,"stats":[]},
        {"hostname":"duplicate","tags":"","last_seen":1,"stats":[]}])").metrics);

    const auto configuration = parse_config_snapshot(
        R"({"success":{"policy":[{"name":"office policy","disabled":"0","proto":"tcp","src":["office"],"sport":["any"],"dst":["internet"],"dport":["https"],"features":["sinkhole"],"action":"accept","nat":"masquerade","routing":"main","tls_profile":"inspect"}]}})",
        R"({"success":{"address_objects":{"office":{"type":"cidr","value":"10.0.0.0/24"},"internet":{"type":"fqdn","value":"example.test"}}}})",
        R"({"success":{"port_objects":{"https":{"start":"443","end":"443"}}}})",
        R"({"success":{"proto_objects":{"tcp":{"id":"6"}}}})");
    assert(configuration.snapshot);
    assert(configuration.snapshot->policies.size() == 1U);
    assert(configuration.snapshot->policies.front().name == "office policy");
    assert(configuration.snapshot->policies.front().enabled);
    assert(configuration.snapshot->policies.front().features == std::vector<std::string>{"sinkhole"});
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
    const auto profiles = parse_config_profiles(
        R"({"success":{"tls_profiles":{"inspect":{},"bypass":{}}}})",
        "tls_profiles", "tls");
    assert(profiles.profiles);
    assert(profiles.profiles->size() == 2U);
    assert(profiles.profiles->front().type == "tls");
    assert(!parse_config_profiles("{}", "tls_profiles", "tls").profiles);
    const auto routing_profiles = parse_config_profiles(
        R"({"success":{"routing":{"main":{"dnat_address":["internet"],"dnat_port":["https"],"dnat_lb_method":"sticky-l4","rewrite_sni":"old.example","rewrite_sni_to":"new.example"}}}})",
        "routing", "routing");
    assert(routing_profiles.profiles);
    assert(routing_profiles.profiles->front().routing);
    assert(routing_profiles.profiles->front().routing->destination_addresses ==
           std::vector<std::string>{"internet"});
    assert(routing_profiles.profiles->front().routing->load_balancing_method == "sticky-l4");
    assert(!parse_config_profiles(
        R"({"success":{"routing":{"bad":{"dnat_lb_method":"random"}}}})",
        "routing", "routing").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"routing":{"bad":{"rewrite_sni":"one-sided.example"}}}})",
        "routing", "routing").profiles);
    const auto tls_profiles = parse_config_profiles(
        R"({"success":{"tls_profiles":{"strict":{"inspect":"true","allow_invalid_certs":"false","client_hello_timeout":"3000","handshake_timeout":"10000","sni_filter_bypass":["secret.example"],"client_cert_action":"use_configured","alerts":"unusual"}}}})",
        "tls_profiles", "tls");
    assert(tls_profiles.profiles);
    assert(tls_profiles.profiles->front().tls);
    assert(tls_profiles.profiles->front().tls->inspect);
    assert(tls_profiles.profiles->front().tls->sni_bypass_entries == 1U);
    assert(tls_profiles.profiles->front().tls->alerts == "unusual");
    assert(!parse_config_profiles(
        R"({"success":{"tls_profiles":{"bad":{"alerts":"verbose"}}}})",
        "tls_profiles", "tls").profiles);
    const auto detection_profiles = parse_config_profiles(
        R"({"success":{"detection_profiles":{"default":{"mode":"2","engines_enabled":"true","kb_enabled":"false"}}}})",
        "detection_profiles", "detection");
    assert(detection_profiles.profiles);
    assert(detection_profiles.profiles->front().detection);
    assert(detection_profiles.profiles->front().detection->mode == 2U);
    assert(!detection_profiles.profiles->front().detection->knowledge_base_enabled);
    const auto content_profiles = parse_config_profiles(
        R"({"success":{"content_profiles":{"capture":{"write_payload":"false","write_format":"pcap_single","webhook_enable":"true","rules_session_filter":"sensitive regex","content_rules":[{"match":"secret","replace":"redacted"}]}}}})",
        "content_profiles", "content");
    assert(content_profiles.profiles);
    assert(content_profiles.profiles->front().content);
    assert(content_profiles.profiles->front().content->session_filter_configured);
    assert(content_profiles.profiles->front().content->rule_count == 1U);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","write_format":"raw"}}}})",
        "content_profiles", "content").profiles);
    const auto ssh_profiles = parse_config_profiles(
        R"({"success":{"ssh_profiles":{"strict":{"host_key":"/sensitive/key/path","hostkey_policy":"strict","shell":"pass","exec":"reject","subsystem":"pass","pty":"pass","environment":"reject","local_forward":"reject","remote_forward":"reject","x11":"reject","agent":"reject"}}}})",
        "ssh_profiles", "ssh");
    assert(ssh_profiles.profiles);
    assert(ssh_profiles.profiles->front().ssh);
    assert(ssh_profiles.profiles->front().ssh->host_key_policy == "strict");
    assert(!ssh_profiles.profiles->front().ssh->exec);
    const auto dns_profiles = parse_config_profiles(
        R"({"success":{"alg_dns_profiles":{"safe":{"match_request_id":"true","randomize_id":"true","cached_responses":"false"}}}})",
        "alg_dns_profiles", "dns");
    assert(dns_profiles.profiles);
    assert(dns_profiles.profiles->front().dns);
    assert(dns_profiles.profiles->front().dns->randomize_id);
    assert(!parse_config_profiles(
        R"({"success":{"ssh_profiles":{"bad":{"host_key":"/key","shell":"allow"}}}})",
        "ssh_profiles", "ssh").profiles);
    const auto script_profiles = parse_config_profiles(
        R"({"success":{"script_profiles":{"audit":{"type":"0","script-file":"/sensitive/audit.py"}}}})",
        "script_profiles", "script");
    assert(script_profiles.profiles);
    assert(script_profiles.profiles->front().script);
    assert(script_profiles.profiles->front().script->runtime == "python");
    assert(script_profiles.profiles->front().script->module_path_configured);
    const auto auth_profiles = parse_config_profiles(
        R"({"success":{"auth_profiles":{"legacy":{"authenticate":"true","resolve":"false","identities":{"alice":{"tls_profile":"inspect"},"bob":{}}}}}})",
        "auth_profiles", "authentication");
    assert(auth_profiles.profiles);
    assert(auth_profiles.profiles->front().authentication);
    assert(auth_profiles.profiles->front().authentication->identity_count == 2U);
    assert(!auth_profiles.profiles->front().authentication->resolve);
    assert(!parse_config_profiles(
        R"({"success":{"script_profiles":{"bad":{"type":"7"}}}})",
        "script_profiles", "script").profiles);
    const auto settings = parse_config_settings(
        R"({"success":{"settings":{"accept_tproxy":"true","policy_fail_open":"false","plaintext_workers":"2","ssl_workers":"4","nameservers":["192.0.2.53"],"http_api":{"keys":["secret"],"allowed_ips":["127.0.0.1"],"loopback_only":"true"},"webhook":{"enabled":"true","tls_verify":"true","url":"https://private.example/"}}}})");
    assert(settings.settings);
    assert(settings.settings->accept_tproxy);
    assert(settings.settings->tls_workers == 4U);
    assert(settings.settings->api_key_count == 1U);
    assert(settings.settings->webhook_url_configured);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"http_api":{"keys":"secret"}}}})").settings);
    const auto captures = parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/private/captures","format":"pcap_single","pcap_quota":"512"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"192.0.2.10","tun_ttl":"1","bind_interface":"private0"},"options":{"calculate_checksums":"true"}}}})");
    assert(captures.captures);
    assert(captures.captures->local_enabled);
    assert(captures.captures->local_quota_mib == 512U);
    assert(captures.captures->remote_destination_configured);
    assert(!parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/tmp","format":"raw"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"","tun_ttl":"1"}}}})").captures);
    const auto security_assets = parse_config_security_assets(
        R"({"success":{"tls_ca":{"default":{"path":"/private/ca"}}}})",
        R"({"success":{"starttls_signatures":[{"flow":[{},{}]}]}})",
        R"({"success":{"detection_signatures":[{"flow":[{}]},{"flow":[{},{}]}]}})");
    assert(security_assets.security_assets);
    assert(security_assets.security_assets->certificate_authority_count == 1U);
    assert(security_assets.security_assets->starttls_flow_step_count == 2U);
    assert(security_assets.security_assets->detection_signature_count == 2U);
    assert(security_assets.security_assets->detection_flow_step_count == 3U);
    assert(!parse_config_security_assets(
        R"({"success":{"tls_ca":{}}})",
        R"({"success":{"starttls_signatures":[{"flow":"secret"}]}})",
        R"({"success":{"detection_signatures":[]}})").security_assets);

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
