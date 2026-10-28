#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct ConfigAddressObject {
    std::string id;
    std::string name;
    std::string type;
    std::string value;
};

struct ConfigPortObject {
    std::string id;
    std::string name;
    std::uint64_t start{};
    std::uint64_t end{};
};

struct ConfigProtocolObject {
    std::string id;
    std::string name;
    std::uint64_t number{};
};

struct ConfigProfile {
    std::string id;
    std::string name;
    std::string type;
};

struct ConfigPolicy {
    std::string id;
    std::string name;
    bool enabled{true};
    std::string protocol;
    std::vector<std::string> sources;
    std::vector<std::string> source_ports;
    std::vector<std::string> destinations;
    std::vector<std::string> destination_ports;
    std::string action;
    std::string nat;
    std::string routing;
    std::string tls_profile;
};

struct ConfigSnapshot {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy configuration is not configured"};
    std::chrono::system_clock::time_point checked_at{};
    std::chrono::system_clock::time_point last_success_at{};
    std::vector<ConfigPolicy> policies;
    std::vector<ConfigAddressObject> addresses;
    std::vector<ConfigPortObject> ports;
    std::vector<ConfigProtocolObject> protocols;
    std::vector<ConfigProfile> profiles;
};

struct ConfigSnapshotParseResult {
    std::optional<ConfigSnapshot> snapshot;
    std::string error;
};

ConfigSnapshotParseResult parse_config_snapshot(
    std::string_view policy_payload,
    std::string_view address_payload,
    std::string_view port_payload,
    std::string_view protocol_payload);

struct ConfigProfileParseResult {
    std::optional<std::vector<ConfigProfile>> profiles;
    std::string error;
};

ConfigProfileParseResult parse_config_profiles(
    std::string_view payload,
    std::string_view section,
    std::string_view type);

} // namespace smithproxy::gui
