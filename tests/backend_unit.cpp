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
    assert(draft.upsert_many(2U, {
        {"policy.[0].name", std::string("office")},
        {"policy.[0].disabled", false},
        {"policy.[0].dst", std::vector<std::string>{"internet", "backup"}},
        {"tls_profiles.[0].redirect_warning_ports", std::vector<std::int64_t>{443, 44443}},
    }) == DraftMutationResult::Applied);
    const auto batched = draft.snapshot();
    assert(batched.version == 3U);
    assert(batched.changes.size() == 5U);
    assert(std::get<std::vector<std::string>>(batched.changes[3].value) ==
           std::vector<std::string>({"internet", "backup"}));
    assert(std::get<std::vector<std::int64_t>>(batched.changes.back().value) ==
           std::vector<std::int64_t>({443, 44443}));
    assert(draft.upsert_many(3U, {
        {"policy.[0].name", std::string("changed")},
        {"policy.[0].name", std::string("duplicate")},
    }) == DraftMutationResult::InvalidPath);
    assert(draft.snapshot().version == 3U);
    assert(std::get<std::string>(draft.snapshot().changes[1].value) == "office");
    assert(draft.remove(3U, "settings.missing") == DraftMutationResult::Missing);
    assert(draft.remove(3U, "policy.[0].action") == DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 4U);
    assert(draft.clear(4U) == DraftMutationResult::Applied);
    assert(draft.snapshot().version == 5U);

    DraftStore bounded_draft{"bounded"};
    std::vector<DraftChange> oversized_changes;
    for (std::size_t index = 0; index < 17U; ++index) {
        oversized_changes.push_back({
            "settings.large.[" + std::to_string(index) + "]",
            std::string(65536U, 'x'),
        });
    }
    assert(bounded_draft.upsert_many(0U, std::move(oversized_changes)) ==
           DraftMutationResult::CapacityExceeded);
    assert(bounded_draft.snapshot().changes.empty());
    assert(bounded_draft.snapshot().version == 0U);

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
        R"({"success":{"tls_profiles":{"strict":{"inspect":"true","use_pfs":"true","left_use_pfs":"false","right_use_pfs":"true","left_disable_reuse":"true","right_disable_reuse":"false","allow_invalid_certs":"false","ocsp_mode":"2","ocsp_stapling":"true","ocsp_stapling_mode":"1","sni_based_cert":"true","ip_based_cert":"false","sni_filter_use_dns_cache":"true","sni_filter_use_dns_domain_tree":"false","redirect_warning_ports":[443,"44443"],"failed_certcheck_replacement":"true","failed_certcheck_override":"true","failed_certcheck_override_timeout":"900","failed_certcheck_override_timeout_type":"1","client_hello_timeout":"3000","handshake_timeout":"10000","sni_filter_bypass":["secret.example"],"client_cert_action":"use_configured","alerts":"unusual"}}}})",
        "tls_profiles", "tls");
    assert(tls_profiles.profiles);
    assert(tls_profiles.profiles->front().tls);
    assert(tls_profiles.profiles->front().tls->inspect);
    assert(!tls_profiles.profiles->front().tls->left_use_pfs);
    assert(tls_profiles.profiles->front().tls->left_disable_reuse);
    assert(tls_profiles.profiles->front().tls->ocsp_mode == 2U);
    assert(tls_profiles.profiles->front().tls->redirect_warning_ports ==
           std::vector<std::uint64_t>({443U, 44443U}));
    assert(tls_profiles.profiles->front().tls->failed_certificate_override_timeout == 900U);
    assert(tls_profiles.profiles->front().tls->sni_bypass_entries == 1U);
    assert(tls_profiles.profiles->front().tls->alerts == "unusual");
    assert(!parse_config_profiles(
        R"({"success":{"tls_profiles":{"bad":{"alerts":"verbose"}}}})",
        "tls_profiles", "tls").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"tls_profiles":{"bad":{"redirect_warning_ports":[443,443]}}}})",
        "tls_profiles", "tls").profiles);
    const auto detection_profiles = parse_config_profiles(
        R"({"success":{"detection_profiles":{"default":{"mode":"2","engines_enabled":"true","kb_enabled":"false"}}}})",
        "detection_profiles", "detection");
    assert(detection_profiles.profiles);
    assert(detection_profiles.profiles->front().detection);
    assert(detection_profiles.profiles->front().detection->mode == 2U);
    assert(!detection_profiles.profiles->front().detection->knowledge_base_enabled);
    const auto content_profiles = parse_config_profiles(
        R"({"success":{"content_profiles":{"capture":{"write_payload":"false","write_format":"pcap_single","webhook_enable":"true","rules_session_filter":"sensitive regex","content_rules":[{"match":"secret","replace":"redacted","fill_length":"true","replace_each_nth":"3"}]}}}})",
        "content_profiles", "content");
    assert(content_profiles.profiles);
    assert(content_profiles.profiles->front().content);
    assert(content_profiles.profiles->front().content->session_filter_configured);
    assert(content_profiles.profiles->front().content->rule_count == 1U);
    assert(content_profiles.profiles->front().content->rules.front().match_configured);
    assert(content_profiles.profiles->front().content->rules.front().replacement_has_value);
    assert(content_profiles.profiles->front().content->rules.front().fill_length);
    assert(content_profiles.profiles->front().content->rules.front().replace_each_nth == 3);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","content_rules":[{"replace":"missing match"}]}}}})",
        "content_profiles", "content").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","content_rules":[{"match":"ok","replace":"value","replace_each_nth":"2147483648"}]}}}})",
        "content_profiles", "content").profiles);
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
        R"({"success":{"settings":{"accept_tproxy":"true","policy_fail_open":"false","plaintext_workers":"2","ssl_workers":"4","quic_workers":"-1","socks_workers":"-1","plaintext_port":"50080","ssl_port":"50443","udp_port":"50080","quic_port":"443","http_connect_port":"3128","ssl_ocsp_status_ttl":"1800","ssl_crl_status_ttl":"86400","default_write_payload":"false","write_payload_dir":"/private/payloads","write_pcap_single_quota":"100","log_level":"6","log_file":"/private/messages.log","log_console":"true","sslkeylog_file":"/private/tls.keys","syslog_server":"192.0.2.60","syslog_port":"514","syslog_facility":"23","syslog_level":"6","syslog_family":"4","udp_quick_ports":["0"],"certs_path":"/private/certs","certs_ca_key_password":"password","ca_bundle_path":"/private/ca","messages_dir":"/private/messages","write_payload_file_prefix":"prefix","write_payload_file_suffix":"suffix","cli":{"port":"50000","enable_password":"password"},"web_rating":{"wot_key":"key"},"socks":{"async_dns":"true"},"nameservers":["192.0.2.53"],"http_api":{"keys":["secret"],"allowed_ips":["127.0.0.1"],"loopback_only":"true"},"webhook":{"enabled":"true","tls_verify":"true","url":"https://private.example/"}}}})");
    assert(settings.settings);
    assert(settings.settings->accept_tproxy);
    assert(settings.settings->tls_workers == 4);
    assert(settings.settings->quic_workers == -1);
    assert(settings.settings->socks_workers == -1);
    assert(settings.settings->tls_port == 50443U);
    assert(settings.settings->ocsp_status_ttl == 1800U);
    assert(settings.settings->payload_directory_configured);
    assert(settings.settings->log_file_configured);
    assert(settings.settings->syslog_server_configured);
    assert(settings.settings->syslog_family == 4U);
    assert(settings.settings->udp_quick_port_count == 1U);
    assert(settings.settings->udp_quick_ports == std::vector<std::string>{"0"});
    assert(settings.settings->certificate_password_configured);
    assert(settings.settings->cli_password_configured);
    assert(settings.settings->web_rating_key_configured);
    assert(settings.settings->socks_async_dns);
    assert(settings.settings->nameservers == std::vector<std::string>{"192.0.2.53"});
    assert(settings.settings->api_key_count == 1U);
    assert(settings.settings->api_allowed_ips == std::vector<std::string>{"127.0.0.1"});
    assert(settings.settings->api_key_timeout == 3600U);
    assert(settings.settings->api_port == 55555U);
    assert(settings.settings->api_key_extend_on_access);
    assert(!settings.settings->api_bind_address_configured);
    assert(settings.settings->webhook_url_configured);
    const auto http_api_settings = parse_config_settings(
        R"({"success":{"settings":{"default_write_payload":"false","http_api":{"key_timeout":"900","port":"55580","key_extend_on_access":"false","bind_address":"127.0.0.1","bind_interface":"private0"}}}})");
    assert(http_api_settings.settings);
    assert(http_api_settings.settings->api_key_timeout == 900U);
    assert(http_api_settings.settings->api_port == 55580U);
    assert(!http_api_settings.settings->api_key_extend_on_access);
    assert(http_api_settings.settings->api_bind_address_configured);
    assert(http_api_settings.settings->api_bind_interface_configured);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"http_api":{"keys":"secret"}}}})").settings);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"quic_workers":"-2"}}})").settings);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"default_write_payload":"false","http_api":{"port":"1024"}}}})").settings);
    const auto debug = parse_config_debug(
        R"({"success":{"debug":{"log_data_crc":"true","log_sockets":"false","log_online_cx_name":"true","log_srclines":"false","log_srclines_always":"true","log":{"proxy":"7","tls":"8"}}}})");
    assert(debug.debug);
    assert(debug.debug->log_data_crc);
    assert(debug.debug->log_online_connection_name);
    assert(debug.debug->log_source_lines_always);
    assert(debug.debug->module_override_count == 2U);
    assert(debug.debug->module_overrides.size() == 2U);
    assert(debug.debug->module_overrides[0].name == "proxy");
    assert(debug.debug->module_overrides[0].kind == "integer");
    assert(debug.debug->module_overrides[0].value == "7");
    assert(!parse_config_debug(
        R"({"success":{"debug":{"log":{"proxy":{}}}}})").debug);
    const auto captures = parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/private/captures","format":"pcap_single","pcap_quota":"512"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"192.0.2.10","tun_ttl":"1","bind_interface":"private0"},"options":{"calculate_checksums":"true"}}}})");
    assert(captures.captures);
    assert(captures.captures->local_enabled);
    assert(!captures.captures->local_file_prefix_configured);
    assert(!captures.captures->local_file_suffix_configured);
    assert(captures.captures->local_quota_mib == 512U);
    assert(captures.captures->remote_destination_configured);
    assert(!parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/tmp","format":"raw"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"","tun_ttl":"1"}}}})").captures);
    const auto security_assets = parse_config_security_assets(
        R"({"success":{"tls_ca":{"default":{"path":"/private/ca"}}}})",
        R"({"success":{"starttls_signatures":[{"cat":"mail","name":"smtp/starttls","side":"client","flow":[{"side":"r","type":"regex","signature":"^STARTTLS","bytes_start":"0","bytes_max":"16"},{"side":"w","type":"regex","signature":"^2[0-5]0","bytes_start":"0","bytes_max":"512"}]}]}})",
        R"({"success":{"detection_signatures":[{"cat":"www","name":"http/request","side":"client","group":"base","enables":"http","engine":"http1","flow":[{"side":"r","type":"regex","signature":"^GET","bytes_start":"0","bytes_max":"200"}]},{"name":"eicar","flow":[{"signature":"EICAR"},{"side":"w","type":"simple","signature":"test"}]}]}})");
    assert(security_assets.security_assets);
    assert(security_assets.security_assets->certificate_authority_count == 1U);
    assert(security_assets.security_assets->certificate_authorities.size() == 1U);
    assert(security_assets.security_assets->certificate_authorities.front().name == "default");
    assert(security_assets.security_assets->certificate_authorities.front().path_configured);
    assert(security_assets.security_assets->starttls_flow_step_count == 2U);
    assert(security_assets.security_assets->detection_signature_count == 2U);
    assert(security_assets.security_assets->detection_flow_step_count == 3U);
    assert(security_assets.security_assets->signatures.size() == 3U);
    assert(security_assets.security_assets->signatures.front().name == "smtp/starttls");
    assert(security_assets.security_assets->signatures.front().flow.front().expression_configured);
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
