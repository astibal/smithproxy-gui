#pragma once

#include "config.hpp"
#include "smithproxy_client.hpp"

#include <atomic>

namespace smithproxy::gui {

int run_http_server(const AppConfig& config, SmithproxyMonitor& monitor, std::atomic_bool& stop_requested);

} // namespace smithproxy::gui
