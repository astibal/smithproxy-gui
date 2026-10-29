#pragma once

#include "job_store.hpp"
#include "smithproxy_client.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace smithproxy::gui {

struct OperationalEventRecord {
    std::string id;
    std::uint64_t source_revision{};
    std::chrono::system_clock::time_point occurred_at{};
    std::string category;
    std::string code;
    std::string severity;
    std::string message;
};

class OperationalEventStore {
public:
    void observe(const SmithproxyStatus& status, const std::vector<JobRecord>& jobs);
    [[nodiscard]] std::vector<OperationalEventRecord> snapshot() const;

private:
    void append(OperationalEventRecord event);

    mutable std::mutex mutex_;
    std::vector<OperationalEventRecord> records_;
    std::uint64_t next_sequence_{};
    std::uint64_t last_probe_sequence_{};
    std::string last_probe_state_;
    std::uint64_t last_job_snapshot_max_{};
    std::map<std::uint64_t, std::string> observed_job_states_;
};

} // namespace smithproxy::gui
