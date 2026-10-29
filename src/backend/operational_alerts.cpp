#include "operational_alerts.hpp"

#include <cstdint>
#include <string_view>

namespace smithproxy::gui {
namespace {

bool is_stale(const std::chrono::system_clock::time_point last_success,
              const std::chrono::seconds maximum_age,
              const std::chrono::system_clock::time_point now) {
    return last_success.time_since_epoch().count() != 0 && now > last_success + maximum_age;
}

void append_collector_alert(std::vector<OperationalAlert>& alerts, const std::string_view id,
                            const std::string_view title, const std::string_view state,
                            const std::chrono::system_clock::time_point last_success,
                            const std::chrono::seconds maximum_age,
                            const std::chrono::system_clock::time_point now) {
    if (state != "ready") {
        alerts.push_back({std::string{id}, "warning", std::string{title},
                          "The collector is unavailable; retained values may be out of date."});
    } else if (is_stale(last_success, maximum_age, now)) {
        alerts.push_back({std::string{id} + "-stale", "warning", std::string{title},
                          "The last successful sample is older than the expected collection window."});
    }
}

} // namespace

std::vector<OperationalAlert> derive_operational_alerts(
    const SmithproxyStatus& status, const bool configured, const bool config_enabled,
    const std::chrono::system_clock::time_point now) {
    std::vector<OperationalAlert> alerts;
    alerts.reserve(9U);

    if (!configured) {
        alerts.push_back({"control-plane-unconfigured", "notice", "Control plane is not configured",
                          "Smithproxy API credentials have not been supplied to the GUI core."});
        return alerts;
    }
    if (status.state != "ready") {
        alerts.push_back({"control-plane-unavailable", "critical", "Control plane is unavailable",
                          "The GUI core cannot currently reach the authenticated Smithproxy API."});
        return alerts;
    }

    if (status.history.size() >= 12U) {
        std::size_t successful{};
        for (const auto& sample : status.history) {
            if (sample.state == "ready") ++successful;
        }
        if (successful * 100U < status.history.size() * 95U) {
            alerts.push_back({"control-plane-availability", "warning", "Control-plane availability is degraded",
                              "Fewer than 95% of recent authenticated probes succeeded."});
        }
    }

    append_collector_alert(alerts, "listener-metrics", "Listener metrics are degraded",
                           status.runtime_metrics.state, status.runtime_metrics.last_success_at,
                           std::chrono::seconds{30}, now);
    append_collector_alert(alerts, "session-activity", "Session activity is degraded",
                           status.live_sessions.state, status.live_sessions.last_success_at,
                           std::chrono::seconds{60}, now);
    append_collector_alert(alerts, "tls-cache", "TLS cache monitoring is degraded",
                           status.tls_cache_metrics.state, status.tls_cache_metrics.last_success_at,
                           std::chrono::seconds{30}, now);
    append_collector_alert(alerts, "neighborhood", "Neighborhood monitoring is degraded",
                           status.neighbor_metrics.state, status.neighbor_metrics.last_success_at,
                           std::chrono::seconds{180}, now);
    if (config_enabled) {
        append_collector_alert(alerts, "configuration", "Configuration snapshot is degraded",
                               status.config_snapshot.state, status.config_snapshot.last_success_at,
                               std::chrono::seconds{180}, now);
        if (status.config_snapshot.state == "ready" && status.config_snapshot.settings &&
            !status.config_snapshot.settings->extended_local_destination_protection) {
            alerts.push_back({"local-destination-protection-disabled", "warning",
                              "Local destination protection is disabled",
                              "Explicit-proxy clients may reach services bound to local host addresses."});
        }
    }

    const auto capacity = status.tls_cache_metrics.capacity;
    if (status.tls_cache_metrics.state == "ready" && capacity != 0U &&
        status.tls_cache_metrics.size >= capacity - capacity / 10U) {
        const auto full = status.tls_cache_metrics.size >= capacity;
        alerts.push_back({"tls-cache-capacity", full ? "critical" : "warning",
                          full ? "TLS cache capacity is exhausted" : "TLS cache capacity is high",
                          full ? "The reported cache size has reached its configured capacity."
                               : "The reported cache size is at least 90% of its configured capacity."});
    }
    return alerts;
}

std::vector<OperationalAlert> derive_job_alerts(const std::vector<JobRecord>& jobs) {
    const JobRecord* latest = nullptr;
    for (const auto& job : jobs) {
        if (job.type != "config-refresh" ||
            (job.state != "succeeded" && job.state != "failed")) continue;
        if (latest == nullptr || job.sequence > latest->sequence) latest = &job;
    }
    if (latest == nullptr || latest->state != "failed") return {};
    return {{
        "configuration-refresh-failed",
        "warning",
        "Configuration refresh did not converge",
        "The authoritative configuration snapshot did not reach the committed revision before the deadline.",
    }};
}

} // namespace smithproxy::gui
