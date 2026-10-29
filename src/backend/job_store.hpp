#pragma once

#include "config_snapshot.hpp"

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace smithproxy::gui {

struct JobRecord {
    std::string id;
    std::string type;
    std::string state;
    std::string phase;
    std::size_t progress_percent{};
    bool cancelable{};
    std::chrono::system_clock::time_point created_at{};
    std::chrono::system_clock::time_point updated_at{};
    std::chrono::system_clock::time_point deadline_at{};
    std::optional<std::string> result;
};

class JobStore {
public:
    explicit JobStore(
        std::chrono::milliseconds config_refresh_timeout = std::chrono::seconds(30));

    [[nodiscard]] std::optional<std::string> create_config_refresh(
        std::string_view expected_revision);
    void reconcile(const ConfigSnapshot& config);
    [[nodiscard]] std::vector<JobRecord> snapshot() const;
    [[nodiscard]] std::optional<JobRecord> find(std::string_view id) const;

private:
    struct StoredJob {
        JobRecord record;
        std::string expected_revision;
        std::chrono::steady_clock::time_point deadline;
    };

    std::chrono::milliseconds config_refresh_timeout_;
    mutable std::mutex mutex_;
    std::vector<StoredJob> jobs_;
};

} // namespace smithproxy::gui
