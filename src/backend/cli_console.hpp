#pragma once

#include "config.hpp"

#include <atomic>
#include <memory>

namespace lmh {
class Controller;
}

namespace smithproxy::gui {

// Build the authenticated WebSocket endpoint that bridges browser terminal
// bytes to Smithproxy's existing libcli2 broker. The endpoint stays absent
// when SMITHPROXY_CLI is not configured.
std::shared_ptr<lmh::Controller> make_cli_console_controller(
    const AppConfig& config, std::shared_ptr<std::atomic_bool> stop_requested);

} // namespace smithproxy::gui
