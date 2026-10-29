#include "audit_store.hpp"

#include <utility>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_entries = 256U;
constexpr std::size_t maximum_targets = 32U;

} // namespace

void AuditStore::record(std::string request_id, std::string operation, std::string outcome,
                        std::string authentication, const std::size_t target_count,
                        std::vector<std::string> targets, const bool targets_truncated) {
    if (targets.size() > maximum_targets) {
        targets.resize(maximum_targets);
    }
    std::scoped_lock lock(mutex_);
    entries_.push_back({
        ++sequence_, std::chrono::system_clock::now(), std::move(request_id),
        std::move(operation), std::move(outcome), std::move(authentication), target_count,
        std::move(targets), targets_truncated || target_count > maximum_targets,
    });
    if (entries_.size() > maximum_entries) entries_.erase(entries_.begin());
}

std::vector<AuditEntry> AuditStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    return entries_;
}

} // namespace smithproxy::gui
