#pragma once

#include "config.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace smithproxy::gui {

struct SmithproxyStatus {
    std::string state{"unconfigured"};
    std::string detail{"Smithproxy environment is not configured"};
    std::chrono::system_clock::time_point checked_at{};
};

class SmithproxyMonitor {
public:
    explicit SmithproxyMonitor(std::optional<SmithproxyConfig> config);
    ~SmithproxyMonitor();

    SmithproxyMonitor(const SmithproxyMonitor&) = delete;
    SmithproxyMonitor& operator=(const SmithproxyMonitor&) = delete;

    void start();
    void stop();
    [[nodiscard]] SmithproxyStatus status() const;

private:
    void run(std::stop_token stop_token);
    SmithproxyStatus ping() const;

    std::optional<SmithproxyConfig> config_;
    mutable std::mutex mutex_;
    SmithproxyStatus status_;
    std::jthread worker_;
};

} // namespace smithproxy::gui
