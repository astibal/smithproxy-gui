#include "job_store.hpp"

#include "revision.hpp"
#include "transaction_envelope.hpp"

#include <algorithm>
#include <limits>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_jobs = 128U;

bool terminal(const std::string_view state) {
    return state == "succeeded" || state == "failed" || state == "cancelled";
}

} // namespace

JobStore::JobStore(const std::chrono::milliseconds config_refresh_timeout)
    : config_refresh_timeout_(std::max(config_refresh_timeout, std::chrono::milliseconds::zero())) {}

std::optional<std::string> JobStore::create_config_refresh(
    const std::string_view expected_revision) {
    if (!is_canonical_revision(expected_revision)) return std::nullopt;
    const auto identifier = generate_transaction_idempotency_key();
    if (!identifier) return std::nullopt;
    const auto wall_now = std::chrono::system_clock::now();
    const auto monotonic_now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    if (next_sequence_ == std::numeric_limits<std::uint64_t>::max()) return std::nullopt;
    if (jobs_.size() >= maximum_jobs) {
        const auto completed = std::find_if(jobs_.begin(), jobs_.end(), [](const StoredJob& job) {
            return terminal(job.record.state);
        });
        if (completed == jobs_.end()) return std::nullopt;
        jobs_.erase(completed);
    }
    const auto record_now = jobs_.empty()
        ? wall_now
        : std::max(wall_now, jobs_.back().record.created_at);
    const auto id = "job-" + *identifier;
    const auto sequence = ++next_sequence_;
    jobs_.push_back({
        .record = {
            .sequence = sequence,
            .id = id,
            .type = "config-refresh",
            .state = "running",
            .phase = "refreshing",
            .progress_percent = 10U,
            .cancelable = false,
            .created_at = record_now,
            .updated_at = record_now,
            .deadline_at = record_now + config_refresh_timeout_,
            .result = std::nullopt,
        },
        .expected_revision = std::string(expected_revision),
        .deadline = monotonic_now + config_refresh_timeout_,
    });
    return id;
}

void JobStore::reconcile(const ConfigSnapshot& config) {
    const auto wall_now = std::chrono::system_clock::now();
    const auto monotonic_now = std::chrono::steady_clock::now();
    std::scoped_lock lock(mutex_);
    for (auto& job : jobs_) {
        if (job.record.state != "running") continue;
        std::string phase;
        std::size_t progress{};
        std::optional<std::string> result;
        std::string state{"running"};
        if (config.state == "ready" && config.revision == job.expected_revision) {
            state = "succeeded";
            phase = "synchronized";
            progress = 100U;
            result = "Configuration snapshot synchronized";
        } else if (monotonic_now >= job.deadline) {
            state = "failed";
            phase = "timed-out";
            progress = 100U;
            result = "Configuration refresh deadline exceeded";
        } else if (config.state == "starting") {
            phase = "refreshing";
            progress = 50U;
        } else if (config.state == "ready") {
            phase = "waiting-for-revision";
            progress = 75U;
        } else {
            phase = "waiting-for-control-plane";
            progress = 25U;
        }
        if (state == "running") progress = std::max(progress, job.record.progress_percent);
        if (job.record.state == state && job.record.phase == phase &&
            job.record.progress_percent == progress && job.record.result == result) {
            continue;
        }
        job.record.state = std::move(state);
        job.record.phase = std::move(phase);
        job.record.progress_percent = progress;
        job.record.result = std::move(result);
        job.record.updated_at = std::max(wall_now, job.record.created_at);
    }
}

std::vector<JobRecord> JobStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    std::vector<JobRecord> result;
    result.reserve(jobs_.size());
    for (const auto& job : jobs_) result.push_back(job.record);
    return result;
}

std::optional<JobRecord> JobStore::find(const std::string_view id) const {
    std::scoped_lock lock(mutex_);
    const auto found = std::find_if(jobs_.begin(), jobs_.end(), [&](const StoredJob& job) {
        return job.record.id == id;
    });
    if (found == jobs_.end()) return std::nullopt;
    return found->record;
}

} // namespace smithproxy::gui
