#pragma once

#include "smithproxy_client.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace smithproxy::gui {

struct OperationalAlert {
    std::string id;
    std::string severity;
    std::string title;
    std::string detail;
};

[[nodiscard]] std::vector<OperationalAlert> derive_operational_alerts(
    const SmithproxyStatus& status, bool configured, bool config_enabled,
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

} // namespace smithproxy::gui
