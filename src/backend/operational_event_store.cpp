#include "operational_event_store.hpp"

#include <algorithm>
#include <limits>
#include <set>
#include <string_view>
#include <utility>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_events = 60U;

bool terminal_job_state(const std::string_view state) {
    return state == "succeeded" || state == "failed" || state == "cancelled";
}

OperationalEventRecord probe_event(const ProbeSample& sample) {
    const auto code = sample.state == "ready" ? "control-plane.ready" :
                      sample.state == "starting" ? "control-plane.starting" :
                      sample.state == "unreachable" ? "control-plane.unreachable" :
                      sample.state == "unauthorized" ? "control-plane.unauthorized" :
                      sample.state == "unconfigured" ? "control-plane.unconfigured" :
                      "control-plane.error";
    return {
        .id = {},
        .source_revision = 0U,
        .occurred_at = sample.checked_at,
        .category = "control-plane",
        .code = code,
        .severity = sample.state == "ready" ? "info" :
                    sample.state == "starting" ? "notice" : "error",
        .message = sample.state == "ready" ? "Smithproxy control plane is reachable" :
                   sample.state == "starting" ? "Smithproxy probe is starting" :
                   sample.state == "unreachable" ? "Smithproxy control plane changed to unreachable" :
                   sample.state == "unauthorized" ? "Smithproxy control plane changed to unauthorized" :
                   sample.state == "unconfigured" ? "Smithproxy control plane changed to unconfigured" :
                   "Smithproxy control plane changed to error",
    };
}

OperationalEventRecord job_event(const JobRecord& job) {
    return {
        .id = {},
        .source_revision = 0U,
        .occurred_at = job.updated_at,
        .category = "backend-job",
        .code = "config-refresh." + job.state,
        .severity = job.state == "succeeded" ? "info" :
                    job.state == "cancelled" ? "notice" : "warning",
        .message = job.state == "succeeded" ? "Configuration refresh synchronized" :
                   job.state == "cancelled" ? "Configuration refresh was cancelled" :
                   "Configuration refresh did not converge",
    };
}

} // namespace

void OperationalEventStore::observe(
    const SmithproxyStatus& status, const std::vector<JobRecord>& jobs) {
    std::scoped_lock lock(mutex_);
    std::vector<OperationalEventRecord> pending;
    pending.reserve(status.history.size() + jobs.size());

    for (const auto& sample : status.history) {
        if (sample.sequence <= last_probe_sequence_) continue;
        last_probe_sequence_ = sample.sequence;
        if (sample.state == last_probe_state_) continue;
        last_probe_state_ = sample.state;
        pending.push_back(probe_event(sample));
    }

    const auto job_snapshot_max = jobs.empty() ? 0U : jobs.back().sequence;
    if (job_snapshot_max >= last_job_snapshot_max_) {
        std::set<std::uint64_t> current_jobs;
        for (const auto& job : jobs) {
            current_jobs.insert(job.sequence);
            const auto previous = observed_job_states_.find(job.sequence);
            if (previous != observed_job_states_.end() &&
                terminal_job_state(previous->second) && !terminal_job_state(job.state)) {
                continue;
            }
            const bool state_changed = previous == observed_job_states_.end() ||
                                       previous->second != job.state;
            observed_job_states_[job.sequence] = job.state;
            if (state_changed && terminal_job_state(job.state)) pending.push_back(job_event(job));
        }
        std::erase_if(observed_job_states_, [&](const auto& item) {
            return !current_jobs.contains(item.first);
        });
        last_job_snapshot_max_ = job_snapshot_max;
    }

    std::stable_sort(pending.begin(), pending.end(), [](const auto& left, const auto& right) {
        return left.occurred_at < right.occurred_at;
    });
    for (auto& event : pending) append(std::move(event));
}

std::vector<OperationalEventRecord> OperationalEventStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    return records_;
}

void OperationalEventStore::append(OperationalEventRecord event) {
    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) return;
    const auto sequence = ++next_sequence_;
    event.id = "event-" + std::to_string(sequence);
    event.source_revision = sequence;
    if (!records_.empty()) {
        event.occurred_at = std::max(event.occurred_at, records_.back().occurred_at);
    }
    records_.push_back(std::move(event));
    if (records_.size() > maximum_events) records_.erase(records_.begin());
}

} // namespace smithproxy::gui
