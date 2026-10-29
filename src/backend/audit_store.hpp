#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace smithproxy::gui {

struct AuditEntry {
    std::uint64_t sequence{};
    std::chrono::system_clock::time_point occurred_at;
    std::string request_id;
    std::string operation;
    std::string outcome;
    std::string authentication;
    std::size_t target_count{};
    std::vector<std::string> targets;
    bool targets_truncated{};
};

class AuditStore {
public:
    void record(std::string request_id, std::string operation, std::string outcome,
                std::string authentication, std::size_t target_count,
                std::vector<std::string> targets, bool targets_truncated);
    [[nodiscard]] std::vector<AuditEntry> snapshot() const;

private:
    mutable std::mutex mutex_;
    std::uint64_t sequence_{};
    std::vector<AuditEntry> entries_;
};

} // namespace smithproxy::gui
