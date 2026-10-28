#include "config.hpp"
#include "http_server.hpp"
#include "smithproxy_client.hpp"

#include <curl/curl.h>

#include <atomic>
#include <csignal>
#include <filesystem>
#include <iostream>

namespace {
std::atomic_bool stop_requested{};
void handle_signal(int) { stop_requested.store(true); }
}

int main(int argc, char** argv) {
    const auto parsed = smithproxy::gui::parse_config(
        argc, argv, std::filesystem::path(SMITHPROXY_GUI_DEFAULT_ASSET_ROOT));
    if (parsed.show_help) {
        std::cout << smithproxy::gui::usage();
        return 0;
    }
    if (!parsed.config) {
        std::cerr << "Configuration error: " << parsed.error << '\n';
        return 2;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        std::cerr << "Cannot initialize HTTP client\n";
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
    smithproxy::gui::SmithproxyMonitor monitor(
        parsed.config->smithproxy, parsed.config->gateway_secret.has_value());
    monitor.start();
    std::cout << "Smithproxy GUI listening on http://" << parsed.config->bind_address << ':'
              << parsed.config->port << parsed.config->base_path << '\n';
    const auto result = smithproxy::gui::run_http_server(*parsed.config, monitor, stop_requested);
    stop_requested.store(true);
    monitor.stop();
    curl_global_cleanup();
    return result;
}
