#include "audit_store.hpp"
#include "commit_coordinator.hpp"
#include "config.hpp"
#include "config_snapshot.hpp"
#include "draft_operation.hpp"
#include "draft_operation_json.hpp"
#include "draft_store.hpp"
#include "json.hpp"
#include "job_store.hpp"
#include "interface_metrics.hpp"
#include "live_sessions.hpp"
#include "neighbor_metrics.hpp"
#include "operational_alerts.hpp"
#include "operational_event_store.hpp"
#include "path.hpp"
#include "runtime_metrics.hpp"
#include "smithproxy_client.hpp"
#include "tls_metrics.hpp"
#include "transaction_capabilities.hpp"
#include "transaction_envelope.hpp"

#include <nlohmann/json.hpp>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <string>
#include <utility>
#include <vector>

using namespace smithproxy::gui;

int main() {
    unsetenv("SMITHPROXY_API_URL");
    unsetenv("SMITHPROXY_API_KEY");
    unsetenv("SMITHPROXY_CA_CERT");
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS");
    assert(normalize_base_path("/") == "/");
    assert(normalize_base_path("/ws001/smithproxy-gui/") == "/ws001/smithproxy-gui");
    assert(!normalize_base_path("ws001"));
    assert(!normalize_base_path("/ws001/../gui"));
    assert(!normalize_base_path("/ws001//gui"));

    DraftStore draft{"draft-test", "revision-7"};
    assert(draft.snapshot().version == 0U);
    assert(draft.snapshot().base_revision == "revision-7");
    assert(draft.upsert(0U, {"policy.[0].action", std::string("accept")}) ==
           DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 1U);
    assert(draft.upsert(0U, {"policy.[0].action", std::string("reject")}) ==
           DraftMutationResult::VersionConflict);
    assert(draft.upsert(1U, {"policy.[0].action", std::string("reject")}) ==
           DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 1U);
    assert(std::get<std::string>(draft.snapshot().changes.front().value) == "reject");
    assert(draft.upsert(2U, {"../unsafe", true}) == DraftMutationResult::InvalidPath);
    assert(draft.upsert(2U, {"settings.ratio", std::numeric_limits<double>::infinity()}) ==
           DraftMutationResult::InvalidValue);
    assert(draft.upsert_many(2U, {
        {"policy.[0].name", std::string("office")},
        {"policy.[0].disabled", false},
        {"policy.[0].dst", std::vector<std::string>{"internet", "backup"}},
        {"tls_profiles.[0].redirect_warning_ports", std::vector<std::int64_t>{443, 44443}},
    }) == DraftMutationResult::Applied);
    const auto batched = draft.snapshot();
    assert(batched.version == 3U);
    assert(batched.changes.size() == 5U);
    assert(std::get<std::vector<std::string>>(batched.changes[3].value) ==
           std::vector<std::string>({"internet", "backup"}));
    assert(std::get<std::vector<std::int64_t>>(batched.changes.back().value) ==
           std::vector<std::int64_t>({443, 44443}));
    assert(draft.upsert_many(3U, {
        {"policy.[0].name", std::string("changed")},
        {"policy.[0].name", std::string("duplicate")},
    }) == DraftMutationResult::InvalidPath);
    assert(draft.snapshot().version == 3U);
    assert(std::get<std::string>(draft.snapshot().changes[1].value) == "office");
    assert(draft.remove(3U, "settings.missing") == DraftMutationResult::Missing);
    assert(draft.remove(3U, "policy.[0].action") == DraftMutationResult::Applied);
    assert(draft.snapshot().changes.size() == 4U);
    assert(draft.clear(4U) == DraftMutationResult::Applied);
    assert(draft.snapshot().version == 5U);

    DraftStore grouped_removal{"grouped-removal"};
    assert(grouped_removal.upsert_many(0U, {
        {"policy.[0].name", std::string("office")},
        {"policy.[0].action", std::string("accept")},
        {"settings.policy_fail_open", true},
    }) == DraftMutationResult::Applied);
    assert(grouped_removal.remove_many(0U, {
        "policy.[0].name", "policy.[0].action",
    }) == DraftMutationResult::VersionConflict);
    assert(grouped_removal.remove_many(1U, {
        "policy.[0].name", "policy.[0].name",
    }) == DraftMutationResult::InvalidPath);
    assert(grouped_removal.remove_many(1U, {
        "policy.[0].name", "policy.[0].missing",
    }) == DraftMutationResult::Missing);
    assert(grouped_removal.snapshot().changes.size() == 3U);
    assert(grouped_removal.remove_many(1U, {
        "policy.[0].name", "policy.[0].action",
    }) == DraftMutationResult::Applied);
    assert(grouped_removal.snapshot().version == 2U);
    assert(grouped_removal.snapshot().changes.size() == 1U);

    DraftStore structural_store{"structural-store"};
    const DraftCreateOperation create_address{
        .local_id = "create-address-1",
        .collection = "address_objects",
        .client_id = "new-office-network",
        .parent_id = std::nullopt,
        .position = {DraftPositionKind::Last, std::nullopt},
        .fields = {
            {"name", std::string("office-net")},
            {"type", std::string("cidr")},
            {"value", std::string("192.0.2.0/24")},
        },
    };
    const auto parsed_create = parse_draft_structural_operation(nlohmann::json{
        {"op", "create"}, {"local_id", "create-address-1"},
        {"collection", "address_objects"}, {"client_id", "new-office-network"},
        {"position", {{"last", true}}},
        {"fields", {{"name", "office-net"}, {"type", "cidr"},
                    {"value", "192.0.2.0/24"}}},
    });
    assert(parsed_create);
    assert(std::get<DraftCreateOperation>(*parsed_create).fields == create_address.fields);
    assert(!parse_draft_structural_operation(nlohmann::json{
        {"op", "create"}, {"local_id", "create-address-1"},
        {"collection", "address_objects"}, {"client_id", "new-office-network"},
        {"position", {{"last", true}}}, {"fields", {{"name", "office-net"}}},
        {"unexpected", true},
    }));
    assert(!parse_draft_structural_operation(nlohmann::json{
        {"op", "create"}, {"local_id", "create-address-1"},
        {"collection", "address_objects"}, {"client_id", "new-office-network"},
        {"position", {{"last", true}}},
        {"fields", {{"name", "office-net"}, {"type", "invalid"}}},
    }));
    assert(parse_draft_structural_operation(nlohmann::json{
        {"op", "delete"}, {"local_id", "delete-address-1"},
        {"collection", "address_objects"}, {"entity_id", "cfg:address:old"},
    }));
    assert(parse_draft_structural_operation(nlohmann::json{
        {"op", "move"}, {"local_id", "move-policy-1"}, {"collection", "policy"},
        {"entity_id", "cfg:policy:second"}, {"position", {{"before", "cfg:policy:first"}}},
    }));
    assert(!parse_draft_structural_operation(nlohmann::json{
        {"op", "move"}, {"local_id", "move-policy-1"}, {"collection", "unknown"},
        {"entity_id", "cfg:policy:second"}, {"position", {{"first", true}}},
    }));
    assert(draft_structural_field_path("content_profiles.content_rules", "match") ==
           "content_profiles.[0].content_rules.[0].match");
    assert(!draft_structural_field_path("settings", "log_level"));
    assert(structural_store.upsert_structural(0U, create_address) ==
           DraftMutationResult::Applied);
    assert(structural_store.snapshot().operation_count() == 1U);
    assert(structural_store.upsert_structural(0U, create_address) ==
           DraftMutationResult::VersionConflict);
    auto duplicate_client = create_address;
    duplicate_client.local_id = "create-address-2";
    assert(structural_store.upsert_structural(1U, duplicate_client) ==
           DraftMutationResult::InvalidValue);
    assert(structural_store.upsert(1U, {"policy.[0].action", std::string("accept")}) ==
           DraftMutationResult::Applied);
    assert(structural_store.snapshot().operation_count() == 2U);
    assert(structural_store.remove_structural(1U, "create-address-1") ==
           DraftMutationResult::VersionConflict);
    assert(structural_store.remove_structural(2U, "missing-operation") ==
           DraftMutationResult::Missing);
    assert(structural_store.remove_structural(2U, "create-address-1") ==
           DraftMutationResult::Applied);
    assert(structural_store.snapshot().operation_count() == 1U);
    assert(structural_store.clear(3U) == DraftMutationResult::Applied);
    assert(structural_store.snapshot().empty());

    DraftStore ordered_removal_store{"ordered-removal-draft"};
    auto ordered_anchor = create_address;
    ordered_anchor.local_id = "ordered-anchor";
    ordered_anchor.client_id = "ordered-anchor";
    auto ordered_dependent = create_address;
    ordered_dependent.local_id = "ordered-dependent";
    ordered_dependent.client_id = "ordered-dependent";
    ordered_dependent.position = {DraftPositionKind::Before, "client:ordered-anchor"};
    std::get<std::string>(ordered_dependent.fields["name"]) = "dependent-office-network";
    assert(ordered_removal_store.upsert_structural_many(
               0U, {ordered_anchor, ordered_dependent}) == DraftMutationResult::Applied);
    assert(ordered_removal_store.remove_structural(1U, "ordered-anchor") ==
           DraftMutationResult::InvalidValue);
    assert(ordered_removal_store.snapshot().version == 1U);
    assert(ordered_removal_store.snapshot().structural_operations.size() == 2U);
    assert(ordered_removal_store.remove_structural(1U, "ordered-dependent") ==
           DraftMutationResult::Applied);
    const DraftMoveOperation ordered_move{
        .local_id = "ordered-move-dependent",
        .collection = "address_objects",
        .entity_id = "cfg:address:existing",
        .position = {DraftPositionKind::Before, "client:ordered-anchor"},
    };
    assert(ordered_removal_store.upsert_structural(2U, ordered_move) ==
           DraftMutationResult::Applied);
    assert(ordered_removal_store.remove_structural(3U, "ordered-anchor") ==
           DraftMutationResult::InvalidValue);
    assert(ordered_removal_store.remove_structural(3U, "ordered-move-dependent") ==
           DraftMutationResult::Applied);
    assert(ordered_removal_store.remove_structural(4U, "ordered-anchor") ==
           DraftMutationResult::Applied);
    assert(ordered_removal_store.snapshot().empty());

    DraftStore signature_store{"signature-draft"};
    const DraftCreateOperation create_signature{
        .local_id = "create-signature-1",
        .collection = "starttls_signatures",
        .client_id = "new-starttls-signature",
        .parent_id = std::nullopt,
        .position = {DraftPositionKind::Last, std::nullopt},
        .fields = {
            {"cat", std::string("mail")},
            {"name", std::string("smtp-starttls")},
            {"side", std::string("server")},
            {"severity", std::int64_t{5}},
            {"group", std::string{}},
            {"enables", std::string{}},
            {"engine", std::string{}},
        },
    };
    const DraftCreateOperation create_signature_flow{
        .local_id = "create-signature-flow-1",
        .collection = "starttls_signatures.flow",
        .client_id = "new-starttls-signature-flow",
        .parent_id = "new-starttls-signature",
        .position = {DraftPositionKind::Last, std::nullopt},
        .fields = {
            {"side", std::string("w")},
            {"type", std::string("regex")},
            {"bytes_start", std::int64_t{0}},
            {"bytes_max", std::int64_t{4096}},
            {"signature", std::string("STARTTLS")},
        },
    };
    assert(signature_store.upsert_structural(0U, create_signature) ==
           DraftMutationResult::InvalidValue);
    assert(signature_store.snapshot().version == 0U);
    assert(signature_store.upsert_structural_many(
               0U, {create_signature, create_signature_flow}) == DraftMutationResult::Applied);
    const auto atomic_signature = signature_store.snapshot();
    assert(atomic_signature.version == 1U);
    assert(atomic_signature.structural_operations.size() == 2U);
    auto invalid_flow = create_signature_flow;
    invalid_flow.local_id = "create-signature-flow-2";
    invalid_flow.client_id = "new-starttls-signature-flow-2";
    std::get<std::string>(invalid_flow.fields["side"]) = "invalid";
    assert(signature_store.upsert_structural_many(
               1U, {create_signature, invalid_flow}) == DraftMutationResult::InvalidValue);
    assert(signature_store.snapshot().version == 1U);
    assert(signature_store.snapshot().structural_operations.size() == 2U);
    assert(signature_store.upsert_structural_many(
               0U, {create_signature, create_signature_flow}) ==
           DraftMutationResult::VersionConflict);
    assert(signature_store.remove_structural(1U, "create-signature-flow-1") ==
           DraftMutationResult::Applied);
    assert(signature_store.snapshot().version == 2U);
    assert(signature_store.snapshot().structural_operations.empty());

    const std::string canonical_revision_a = "sha256:" + std::string(64U, 'a');
    const std::string canonical_revision_b = "sha256:" + std::string(64U, 'b');
    const auto revision_observation = std::chrono::steady_clock::now();
    DraftStore revision_draft{"revision-draft"};
    assert(!revision_draft.bind_base_revision("revision-7", revision_observation));
    assert(!revision_draft.bind_base_revision(
        canonical_revision_a, std::chrono::steady_clock::time_point{}));
    assert(revision_draft.bind_base_revision(canonical_revision_a, revision_observation));
    assert(revision_draft.snapshot().version == 1U);
    assert(!revision_draft.bind_base_revision(canonical_revision_a, revision_observation));
    assert(revision_draft.bind_base_revision(
        canonical_revision_a, revision_observation + std::chrono::milliseconds(1)));
    assert(revision_draft.snapshot().version == 1U);
    assert(revision_draft.upsert(1U, {"policy.[0].action", std::string("accept")}) ==
           DraftMutationResult::Applied);
    assert(!revision_draft.bind_base_revision(
        canonical_revision_b, revision_observation + std::chrono::milliseconds(2)));
    assert(revision_draft.snapshot().base_revision == canonical_revision_a);
    assert(revision_draft.clear(2U) == DraftMutationResult::Applied);
    assert(revision_draft.bind_base_revision(
        canonical_revision_b, revision_observation + std::chrono::milliseconds(3)));
    assert(revision_draft.snapshot().version == 4U);
    assert(revision_draft.snapshot().base_revision == canonical_revision_b);

    DraftStore commit_draft{"commit-draft", canonical_revision_a};
    assert(commit_draft.upsert(0U, {"policy.[0].action", std::string("reject")}) ==
           DraftMutationResult::Applied);
    assert(commit_draft.complete_commit(0U, canonical_revision_b) ==
           DraftMutationResult::VersionConflict);
    assert(commit_draft.complete_commit(1U, "revision-8") ==
           DraftMutationResult::InvalidValue);
    assert(commit_draft.complete_commit(1U, canonical_revision_a) ==
           DraftMutationResult::InvalidValue);
    assert(commit_draft.snapshot().changes.size() == 1U);
    assert(commit_draft.complete_commit(1U, canonical_revision_b) ==
           DraftMutationResult::Applied);
    assert(commit_draft.snapshot().version == 2U);
    assert(commit_draft.snapshot().base_revision == canonical_revision_b);
    assert(commit_draft.snapshot().changes.empty());
    assert(!commit_draft.bind_base_revision(canonical_revision_a, revision_observation));
    assert(commit_draft.snapshot().base_revision == canonical_revision_b);
    assert(commit_draft.complete_commit(2U, canonical_revision_a) ==
           DraftMutationResult::Missing);

    DraftStore coordinated_draft{"coordinated-draft", canonical_revision_a};
    CommitCoordinator coordinator{coordinated_draft};
    assert(coordinator.begin(0U).result() == CommitPreparationResult::Empty);
    assert(coordinator.mutate([&] {
        return coordinated_draft.upsert(
            0U, {"policy.[0].action", std::string("reject")});
    }) == DraftMutationResult::Applied);
    assert(coordinator.begin(0U).result() == CommitPreparationResult::VersionConflict);
    std::string retained_key;
    {
        auto lease = coordinator.begin(1U);
        assert(lease);
        auto moved_lease = std::move(lease);
        assert(moved_lease);
        retained_key = moved_lease.idempotency_key();
        assert(moved_lease.draft().version == 1U);
        assert(coordinator.busy());
        assert(coordinator.begin(1U).result() == CommitPreparationResult::Busy);
        assert(coordinator.mutate([&] {
            return coordinated_draft.clear(1U);
        }) == DraftMutationResult::Busy);
    }
    assert(!coordinator.busy());
    auto retry = coordinator.begin(1U);
    assert(retry);
    assert(retry.idempotency_key() == retained_key);
    retry.release(false);
    auto replacement = coordinator.begin(1U);
    assert(replacement);
    assert(replacement.idempotency_key().size() == 36U);
    assert(replacement.complete_success(canonical_revision_b) == DraftMutationResult::Applied);
    assert(!coordinator.busy());
    assert(coordinated_draft.snapshot().version == 2U);
    assert(coordinated_draft.snapshot().base_revision == canonical_revision_b);
    assert(coordinated_draft.snapshot().changes.empty());

    DraftStore structural_commit_draft{"structural-commit-draft", canonical_revision_a};
    CommitCoordinator structural_coordinator{structural_commit_draft};
    assert(structural_coordinator.mutate([&] {
        return structural_commit_draft.upsert_structural(0U, create_address);
    }) == DraftMutationResult::Applied);
    auto structural_lease = structural_coordinator.begin(1U);
    assert(structural_lease);
    assert(structural_lease.draft().changes.empty());
    assert(structural_lease.draft().structural_operations.size() == 1U);
    assert(structural_lease.complete_success(canonical_revision_b) ==
           DraftMutationResult::Applied);
    assert(structural_commit_draft.snapshot().version == 2U);
    assert(structural_commit_draft.snapshot().base_revision == canonical_revision_b);
    assert(structural_commit_draft.snapshot().empty());

    DraftStore invalid_commit_draft{"invalid-commit-draft", "revision-7"};
    assert(invalid_commit_draft.upsert(
        0U, {"policy.[0].action", std::string("reject")}) == DraftMutationResult::Applied);
    CommitCoordinator invalid_coordinator{invalid_commit_draft};
    assert(invalid_coordinator.begin(1U).result() == CommitPreparationResult::InvalidDraft);

    const auto parsed_revision = parse_config_revision(
        "{\"success\":{\"revision\":\"" + canonical_revision_a + "\"}}");
    assert(parsed_revision.revision == canonical_revision_a);
    assert(!parse_config_revision(R"({"success":{"revision":"sha256:ABC"}})").revision);
    assert(!parse_config_revision(
        "{\"success\":{\"revision\":\"" + canonical_revision_a + "\",\"extra\":true}}")
                .revision);

    JobStore jobs;
    assert(!jobs.create_config_refresh("revision-7"));
    const auto successful_job_id = jobs.create_config_refresh(canonical_revision_b);
    assert(successful_job_id && successful_job_id->starts_with("job-") &&
           successful_job_id->size() == 40U);
    auto job_records = jobs.snapshot();
    assert(job_records.size() == 1U);
    assert(job_records.front().state == "running");
    assert(job_records.front().phase == "refreshing");
    assert(job_records.front().progress_percent == 10U);
    assert(!job_records.front().cancelable);
    ConfigSnapshot synchronized_config;
    synchronized_config.state = "ready";
    synchronized_config.revision = canonical_revision_b;
    jobs.reconcile(synchronized_config);
    const auto successful_job = jobs.find(*successful_job_id);
    assert(successful_job && successful_job->state == "succeeded");
    assert(successful_job->phase == "synchronized");
    assert(successful_job->progress_percent == 100U);
    assert(successful_job->result == "Configuration snapshot synchronized");
    assert(!jobs.find("job-00000000-0000-0000-0000-000000000000"));

    JobStore monotonic_jobs;
    const auto monotonic_job_id = monotonic_jobs.create_config_refresh(canonical_revision_a);
    assert(monotonic_job_id);
    ConfigSnapshot different_config;
    different_config.state = "ready";
    different_config.revision = canonical_revision_b;
    monotonic_jobs.reconcile(different_config);
    assert(monotonic_jobs.find(*monotonic_job_id)->progress_percent == 75U);
    different_config.state = "unavailable";
    monotonic_jobs.reconcile(different_config);
    assert(monotonic_jobs.find(*monotonic_job_id)->progress_percent == 75U);
    assert(monotonic_jobs.find(*monotonic_job_id)->phase == "waiting-for-revision");

    JobStore expiring_jobs{std::chrono::milliseconds{0}};
    const auto expired_job_id = expiring_jobs.create_config_refresh(canonical_revision_a);
    assert(expired_job_id);
    ConfigSnapshot stale_config;
    stale_config.state = "ready";
    stale_config.revision = canonical_revision_b;
    expiring_jobs.reconcile(stale_config);
    const auto expired_job = expiring_jobs.find(*expired_job_id);
    assert(expired_job && expired_job->state == "failed");
    assert(expired_job->phase == "timed-out");
    assert(expired_job->progress_percent == 100U);

    SmithproxyStatus event_status;
    const auto event_time = std::chrono::system_clock::now();
    event_status.history = {
        {.state = "ready", .checked_at = event_time, .latency_ms = 1U, .sequence = 1U},
        {.state = "ready", .checked_at = event_time + std::chrono::seconds{1},
         .latency_ms = 2U, .sequence = 2U},
    };
    JobStore event_jobs;
    const auto event_job_id = event_jobs.create_config_refresh(canonical_revision_b);
    assert(event_job_id);
    OperationalEventStore events;
    const auto running_event_jobs = event_jobs.snapshot();
    events.observe(event_status, running_event_jobs);
    auto event_records = events.snapshot();
    assert(event_records.size() == 1U);
    assert(event_records.front().id == "event-1");
    assert(event_records.front().category == "control-plane");
    assert(event_records.front().code == "control-plane.ready");
    assert(event_records.front().message == "Smithproxy control plane is reachable");
    event_jobs.reconcile(synchronized_config);
    events.observe(event_status, event_jobs.snapshot());
    event_records = events.snapshot();
    assert(event_records.size() == 2U);
    assert(event_records.back().id == "event-2");
    assert(event_records.back().severity == "info");
    assert(event_records.back().category == "backend-job");
    assert(event_records.back().code == "config-refresh.succeeded");
    assert(event_records.back().message == "Configuration refresh synchronized");
    events.observe(event_status, running_event_jobs);
    events.observe(event_status, event_jobs.snapshot());
    assert(events.snapshot().size() == 2U);
    event_status.history.push_back({
        .state = "error",
        .checked_at = event_time + std::chrono::seconds{2},
        .latency_ms = std::nullopt,
        .sequence = 3U,
    });
    events.observe(event_status, event_jobs.snapshot());
    event_records = events.snapshot();
    assert(event_records.size() == 3U);
    assert(event_records.back().message == "Smithproxy control plane changed to error");

    SmithproxyStatus rotating_status;
    for (std::uint64_t sequence = 1U; sequence <= 70U; ++sequence) {
        rotating_status.history.push_back({
            .state = sequence % 2U == 0U ? "ready" : "error",
            .checked_at = event_time + std::chrono::seconds{sequence},
            .latency_ms = std::nullopt,
            .sequence = sequence,
        });
    }
    OperationalEventStore rotating_events;
    rotating_events.observe(rotating_status, {});
    const auto rotated = rotating_events.snapshot();
    assert(rotated.size() == 60U);
    assert(rotated.front().id == "event-11");
    assert(rotated.back().id == "event-70");

    auto failed_alerts = derive_job_alerts(expiring_jobs.snapshot());
    assert(failed_alerts.size() == 1U);
    assert(failed_alerts.front().id == "configuration-refresh-failed");
    auto retrying_jobs = expiring_jobs.snapshot();
    retrying_jobs.push_back(*monotonic_jobs.find(*monotonic_job_id));
    assert(derive_job_alerts(retrying_jobs).size() == 1U);
    auto resolved_jobs = expiring_jobs.snapshot();
    auto resolved_success = *successful_job;
    resolved_success.sequence = resolved_jobs.front().sequence + 1U;
    resolved_jobs.push_back(std::move(resolved_success));
    assert(derive_job_alerts(resolved_jobs).empty());

    DraftStore schema_draft{"schema"};
    assert(schema_draft.upsert(0U, {"settings.enabled", true}) ==
           DraftMutationResult::InvalidPath);
    assert(schema_draft.upsert(0U, {"policy.[00].action", std::string("accept")}) ==
           DraftMutationResult::InvalidPath);
    assert(schema_draft.upsert(0U, {"policy.[0].action", true}) ==
           DraftMutationResult::InvalidValue);
    assert(schema_draft.upsert(0U, {"port_objects.[0].start", std::int64_t{65536}}) ==
           DraftMutationResult::InvalidValue);
    assert(schema_draft.upsert(0U, {"settings.syslog_family", std::int64_t{5}}) ==
           DraftMutationResult::InvalidValue);
    assert(schema_draft.upsert(0U, {"captures.remote.tun_type", std::string("vxlan")}) ==
           DraftMutationResult::InvalidValue);
    assert(schema_draft.upsert_many(0U, {
        {"settings.accept_api", true},
        {"captures.remote.tun_type", std::string("gre")},
        {"captures.remote.tun_ttl", std::int64_t{64}},
        {"content_profiles.[0].content_rules.[0].replace", std::string("first\nsecond")},
        {"detection_signatures.[0].flow.[0].type", std::string("regex")},
        {"debug.log.tls", std::string("trace")},
    }) == DraftMutationResult::Applied);
    assert(schema_draft.upsert(1U, {"policy.[4096].name", std::string("outside")}) ==
           DraftMutationResult::InvalidPath);

    DraftStore reconciled_draft{"reconciled"};
    assert(reconciled_draft.upsert_many(0U, {
        {"policy.[0].name", std::string("office")},
        {"policy.[0].action", std::string("accept")},
    }) == DraftMutationResult::Applied);
    assert(reconciled_draft.reconcile(
        1U,
        {{"policy.[0].name", std::string("office-updated")}},
        {"policy.[0].action"}) == DraftMutationResult::Applied);
    const auto reconciled = reconciled_draft.snapshot();
    assert(reconciled.version == 2U);
    assert(reconciled.changes.size() == 1U);
    assert(reconciled.changes.front().path == "policy.[0].name");
    assert(std::get<std::string>(reconciled.changes.front().value) == "office-updated");
    assert(reconciled_draft.reconcile(
        2U,
        {{"policy.[0].name", std::string("must-not-apply")}},
        {"policy.[0].missing"}) == DraftMutationResult::Missing);
    assert(std::get<std::string>(reconciled_draft.snapshot().changes.front().value) ==
           "office-updated");
    assert(reconciled_draft.reconcile(
        2U,
        {{"policy.[0].name", std::string("duplicate")}},
        {"policy.[0].name"}) == DraftMutationResult::InvalidPath);

    DraftStore schema_coverage{"schema-coverage"};
    assert(schema_coverage.upsert_many(0U, {
        {"address_objects.[0].type", std::string("cidr")},
        {"port_objects.[0].start", std::int64_t{443}},
        {"proto_objects.[0].id", std::int64_t{6}},
        {"policy.[0].features", std::vector<std::string>{"sinkhole", "statistics"}},
        {"routing.[0].dnat_lb_method", std::string("round-robin")},
        {"tls_profiles.[0].client_cert_action", std::string("use_configured")},
        {"content_profiles.[0].write_format", std::string("smcap")},
        {"ssh_profiles.[0].hostkey_policy", std::string("strict")},
        {"script_profiles.[0].type", std::string("0")},
        {"auth_profiles.[0].authenticate", true},
        {"detection_profiles.[0].mode", std::int64_t{2}},
        {"alg_dns_profiles.[0].randomize_id", true},
        {"tls_ca.[0].path", std::string("/etc/smithproxy/ca.pem")},
        {"starttls_signatures.[0].severity", std::int64_t{3}},
        {"detection_signatures.[0].flow.[0].signature", std::string("^TLS")},
    }) == DraftMutationResult::Applied);

    DraftStore bounded_draft{"bounded"};
    std::vector<DraftChange> oversized_changes;
    for (std::size_t index = 0; index < 1024U; ++index) {
        oversized_changes.push_back({
            "tls_ca.[" + std::to_string(index) + "].path",
            "/" + std::string(1023U, 'x'),
        });
    }
    assert(bounded_draft.upsert_many(0U, std::move(oversized_changes)) ==
           DraftMutationResult::CapacityExceeded);
    assert(bounded_draft.snapshot().changes.empty());
    assert(bounded_draft.snapshot().version == 0U);

    AuditStore audit;
    audit.record("request-1", "config.draft.upsert", "succeeded", "gateway", 1U,
                 {"policy.[0].action"}, false);
    audit.record("request-2", "config.draft.clear", "conflict", "gateway", 0U, {}, false);
    const auto audit_entries = audit.snapshot();
    assert(audit_entries.size() == 2U);
    assert(audit_entries.front().sequence == 1U);
    assert(audit_entries.front().targets == std::vector<std::string>{"policy.[0].action"});
    assert(audit_entries.back().sequence == 2U);
    assert(audit_entries.back().outcome == "conflict");

    AuditStore bounded_audit;
    std::vector<std::string> audit_targets;
    for (std::size_t index = 0U; index < 40U; ++index) {
        audit_targets.push_back("policy.[" + std::to_string(index) + "].action");
    }
    bounded_audit.record("request-1", "config.draft.upsert", "succeeded", "gateway",
                         audit_targets.size(), audit_targets, false);
    for (std::size_t index = 1U; index < 260U; ++index) {
        bounded_audit.record("request-" + std::to_string(index + 1U), "api.mutation",
                             "rejected", "none", 0U, {}, false);
    }
    const auto bounded_entries = bounded_audit.snapshot();
    assert(bounded_entries.size() == 256U);
    assert(bounded_entries.front().sequence == 5U);
    assert(bounded_entries.back().sequence == 260U);

    AuditStore target_bounded_audit;
    const auto audit_target_count = audit_targets.size();
    target_bounded_audit.record("request-targets", "config.draft.upsert", "succeeded",
                                "gateway", audit_target_count, std::move(audit_targets), false);
    const auto target_bounded_entry = target_bounded_audit.snapshot().front();
    assert(target_bounded_entry.targets.size() == 32U);
    assert(target_bounded_entry.targets_truncated);

    assert(path_below_base("/ws001/gui", "/ws001/gui") == "/");
    assert(path_below_base("/ws001/gui/assets/a.js", "/ws001/gui") == "/assets/a.js");
    assert(!path_below_base("/ws001/gui-evil", "/ws001/gui"));

    const std::filesystem::path root("/srv/gui");
    assert(safe_asset_path(root, "/assets/app.js") == root / "assets/app.js");
    assert(!safe_asset_path(root, "/../secret"));
    assert(!safe_asset_path(root, "/%2e%2e/secret"));
    assert(!safe_asset_path(root, "/assets%2fsecret"));
    assert(!safe_asset_path(root, "/assets\\secret"));

    assert(json_string("line\n\"quoted\"") == "\"line\\n\\\"quoted\\\"\"");

    const std::string policy_revision = "sha256:" + std::string(64U, 'a');
    const std::string address_revision = "sha256:" + std::string(64U, 'b');
    const auto capability_payload = std::string(R"({"success":{
        "transaction_version":1,"operation_version":1,"stable_entity_ids":true,
        "operations":["set","create","delete","move"],
        "maximum_operations":8192,"maximum_request_bytes":2097152,
        "collections":[
          {"id":"policy","ordered":true,"nested":false,"schema_revision":")") +
        policy_revision + R"("},
          {"id":"address_objects","ordered":false,"nested":false,"schema_revision":")" +
        address_revision + R"("}
        ]}})";
    const auto unreviewed_capabilities = parse_transaction_capabilities(capability_payload, {});
    assert(unreviewed_capabilities.state == "review-required");
    assert(unreviewed_capabilities.maximum_operations == 4096U);
    assert(unreviewed_capabilities.maximum_request_bytes == 1024U * 1024U);
    assert(unreviewed_capabilities.collections.size() == 2U);

    const ReviewedTransactionSchemas reviewed_schemas{
        {"address_objects", address_revision}, {"policy", policy_revision},
    };
    const auto ready_capabilities = parse_transaction_capabilities(
        capability_payload, reviewed_schemas);
    assert(ready_capabilities.state == "ready");
    assert(ready_capabilities.operations ==
           std::vector<std::string>({"create", "delete", "move", "set"}));
    assert(parse_transaction_capabilities("{}", reviewed_schemas).state == "incompatible");
    assert(parse_transaction_capabilities(
        R"({"success":{"transaction_version":2}})", reviewed_schemas).state == "incompatible");
    const auto duplicate_collection_payload = std::string(R"({"success":{
        "transaction_version":1,"operation_version":1,"stable_entity_ids":true,
        "operations":["set","create","delete","move"],
        "maximum_operations":1,"maximum_request_bytes":1,
        "collections":[
          {"id":"policy","ordered":true,"nested":false,"schema_revision":")") +
        policy_revision + R"("},
          {"id":"policy","ordered":true,"nested":false,"schema_revision":")" +
        policy_revision + R"("}
        ]}})";
    assert(parse_transaction_capabilities(duplicate_collection_payload, reviewed_schemas).state ==
           "incompatible");

    TransactionCapabilities ready_transaction{
        .state = "ready",
        .detail = "reviewed",
        .checked_at = {},
        .maximum_operations = 8U,
        .maximum_request_bytes = 4096U,
        .operations = {"create", "delete", "move", "set"},
        .collections = {
            {"address_objects", false, false, address_revision},
            {"content_profiles.content_rules", true, true, address_revision},
            {"policy", true, false, policy_revision},
        },
    };
    DraftSnapshot transaction_draft{
        .id = "workspace-draft",
        .base_revision = "sha256:" + std::string(64U, '1'),
        .version = 3U,
        .changes = {
            {"policy.[0].action", std::string("reject")},
            {"settings.accept_api", true},
        },
        .structural_operations = {},
    };
    constexpr std::string_view idempotency_key{"018f47a1-7b2c-7def-8123-123456789abc"};
    const auto generated_idempotency_key = generate_transaction_idempotency_key();
    assert(generated_idempotency_key);
    assert(generated_idempotency_key->size() == 36U);
    assert((*generated_idempotency_key)[14] == '4');
    assert((*generated_idempotency_key)[19] == '8' || (*generated_idempotency_key)[19] == '9' ||
           (*generated_idempotency_key)[19] == 'a' || (*generated_idempotency_key)[19] == 'b');
    const auto validation_envelope = build_transaction_envelope(
        transaction_draft, TransactionMode::Validate, idempotency_key, ready_transaction);
    assert(validation_envelope.body);
    const auto validation_document = nlohmann::json::parse(*validation_envelope.body);
    assert(validation_document["mode"] == "validate");
    assert(validation_document["base_revision"] == *transaction_draft.base_revision);
    assert(validation_document["idempotency_key"] == idempotency_key);
    assert(validation_document["operations"].size() == 2U);
    assert(validation_document["operations"][0] == nlohmann::json({
        {"op", "set"}, {"path", "policy.[0].action"}, {"value", "reject"},
    }));
    DraftSnapshot structural_draft{
        .id = "workspace-draft",
        .base_revision = transaction_draft.base_revision,
        .version = 4U,
        .changes = {},
        .structural_operations = {
            DraftCreateOperation{
                .local_id = "create-address-1",
                .collection = "address_objects",
                .client_id = "new-office-network",
                .parent_id = std::nullopt,
                .position = {DraftPositionKind::Last, std::nullopt},
                .fields = {
                    {"name", std::string("office-net")},
                    {"type", std::string("cidr")},
                    {"value", std::string("192.0.2.0/24")},
                },
            },
            DraftDeleteOperation{
                .local_id = "delete-address-1",
                .collection = "address_objects",
                .entity_id = "cfg:address:old",
            },
            DraftMoveOperation{
                .local_id = "move-policy-1",
                .collection = "policy",
                .entity_id = "cfg:policy:second",
                .position = {DraftPositionKind::Before, "cfg:policy:first"},
            },
        },
    };
    assert(structural_draft.operation_count() == 3U);
    const auto structural_envelope = build_transaction_envelope(
        structural_draft, TransactionMode::Validate, idempotency_key, ready_transaction);
    assert(structural_envelope.body);
    const auto structural_document = nlohmann::json::parse(*structural_envelope.body);
    assert(structural_document["operations"] == nlohmann::json::array({
        {
            {"op", "create"}, {"collection", "address_objects"},
            {"client_id", "new-office-network"}, {"position", {{"last", true}}},
            {"fields", {{"name", "office-net"}, {"type", "cidr"}, {"value", "192.0.2.0/24"}}},
        },
        {
            {"op", "delete"}, {"collection", "address_objects"},
            {"entity_id", "cfg:address:old"}, {"if_referenced", "reject"},
        },
        {
            {"op", "move"}, {"collection", "policy"},
            {"entity_id", "cfg:policy:second"}, {"position", {{"before", "cfg:policy:first"}}},
        },
    }));
    auto invalid_structural_draft = structural_draft;
    std::get<DraftMoveOperation>(invalid_structural_draft.structural_operations.back()).collection =
        "address_objects";
    assert(build_transaction_envelope(
        invalid_structural_draft, TransactionMode::Validate, idempotency_key, ready_transaction)
        .error_code == "transaction.invalid_draft");
    assert(!valid_draft_structural_operation(DraftCreateOperation{
        .local_id = "invalid id",
        .collection = "address_objects",
        .client_id = "new-address",
        .parent_id = std::nullopt,
        .position = {DraftPositionKind::Last, std::nullopt},
        .fields = {{"name", std::string("new")}},
    }));
    const auto commit_envelope = build_transaction_envelope(
        transaction_draft, TransactionMode::Commit, idempotency_key, ready_transaction);
    assert(commit_envelope.body);
    assert(nlohmann::json::parse(*commit_envelope.body)["mode"] == "commit");
    assert(build_transaction_envelope(
        transaction_draft, TransactionMode::Commit, "invalid", ready_transaction).error_code ==
        "transaction.unavailable");
    auto oversized_transaction = ready_transaction;
    oversized_transaction.maximum_request_bytes = 64U;
    assert(build_transaction_envelope(
        transaction_draft, TransactionMode::Commit, idempotency_key, oversized_transaction)
        .error_code == "transaction.request_too_large");

    const std::string committed_revision = "sha256:" + std::string(64U, '2');
    const nlohmann::json success_document{{"success", {
        {"revision", committed_revision},
        {"previous_revision", *transaction_draft.base_revision},
        {"validated_operations", 2U},
        {"restart", "not-required"},
        {"warnings", nlohmann::json::array({"bounded warning"})},
    }}};
    const auto success_response = success_document.dump();
    const auto transaction_success = parse_transaction_response(
        200L, success_response, TransactionMode::Commit, *transaction_draft.base_revision, 2U);
    assert(transaction_success.state == "succeeded");
    assert(transaction_success.revision == committed_revision);
    assert(transaction_success.warning_count == 1U);
    assert(parse_transaction_response(
        409L, R"({"error":{"code":"revision_conflict","message":"redacted"}})",
        TransactionMode::Commit, *transaction_draft.base_revision, 2U).state ==
        "conflict");
    assert(parse_transaction_response(
        422L, R"({"error":{"code":"invalid\ncode"}})", TransactionMode::Validate,
        *transaction_draft.base_revision, 2U).state == "invalid-response");
    assert(parse_transaction_response(
        200L, success_response, TransactionMode::Commit, *transaction_draft.base_revision, 1U).state ==
        "invalid-response");
    auto validation_success_document = success_document;
    validation_success_document["success"]["revision"] = *transaction_draft.base_revision;
    assert(parse_transaction_response(
        200L, validation_success_document.dump(), TransactionMode::Validate,
        *transaction_draft.base_revision, 2U).state == "succeeded");

    SmithproxyMonitor unconfigured_monitor{std::nullopt, true};
    assert(unconfigured_monitor.validate_transaction(transaction_draft).state == "unavailable");
    assert(unconfigured_monitor.commit_transaction(transaction_draft, idempotency_key).state ==
           "unavailable");
    assert(!unconfigured_monitor.note_config_committed(canonical_revision_b));
    SmithproxyMonitor undiscovered_monitor{SmithproxyConfig{
        .api_url = "https://127.0.0.1:1",
        .api_key = "not-sent-before-capability-readiness",
        .ca_cert = "/nonexistent",
    }, true};
    assert(undiscovered_monitor.validate_transaction(transaction_draft).state == "unavailable");
    assert(undiscovered_monitor.commit_transaction(transaction_draft, idempotency_key).state ==
           "unavailable");
    assert(!undiscovered_monitor.note_config_committed("revision-8"));
    assert(undiscovered_monitor.note_config_committed(canonical_revision_b));
    assert(undiscovered_monitor.status().config_snapshot.state == "starting");
    assert(undiscovered_monitor.status().config_snapshot.revision == std::nullopt);

    const auto metrics = parse_listener_metrics(R"({"listeners":[
        {"name":"tcp","workers":2,"sessions_total":12,"sessions_active":3,
         "bytes_up":1024,"bytes_down":2048},
        {"name":"tls","workers":1,"sessions_total":7,"sessions_active":1,
         "bytes_up":512,"bytes_down":256}
    ]})");
    assert(metrics.metrics);
    assert(metrics.metrics->listeners.size() == 2U);
    assert(metrics.metrics->workers == 3U);
    assert(metrics.metrics->sessions_total == 19U);
    assert(metrics.metrics->sessions_active == 4U);
    assert(metrics.metrics->bytes_up == 1536U);
    assert(metrics.metrics->bytes_down == 2304U);
    assert(!parse_listener_metrics("not json").metrics);
    assert(!parse_listener_metrics(R"({"listeners":[{"name":"tcp","workers":1,
        "sessions_total":1,"sessions_active":2,"bytes_up":0,"bytes_down":0}]})").metrics);
    assert(!parse_listener_metrics(R"({"listeners":[
        {"name":"tcp","workers":1,"sessions_total":1,"sessions_active":0,"bytes_up":0,"bytes_down":0},
        {"name":"tcp","workers":1,"sessions_total":1,"sessions_active":0,"bytes_up":0,"bytes_down":0}
    ]})").metrics);

    const auto tls_cache = parse_tls_cache_metrics(R"({"cache_size":42,"max_size":1000})");
    assert(tls_cache.metrics);
    assert(tls_cache.metrics->size == 42U);
    assert(tls_cache.metrics->capacity == 1000U);
    assert(!parse_tls_cache_metrics(R"({"cache_size":1001,"max_size":1000})").metrics);
    assert(!parse_tls_cache_metrics(R"({"cache_size":-1,"max_size":1000})").metrics);

    const auto activity = parse_live_sessions(R"([
        {"oid":"private-session","origin":"tls acceptor","policy":"internal-policy",
         "left":[{"host":"10.0.0.10","port":"43100","com":"tls"}],
         "right":[{"host":"private.example","port":"443","com":"tls"}],
         "stats":{"speed":{"up":100,"down":200},
                  "counters":{"bytes_up":1000,"bytes_down":2000}}},
        {"oid":"another-session","origin":"tls acceptor","policy":"other-policy",
         "left":[{"host":"10.0.0.11","port":"43101","com":"tls"}],
         "right":[{"host":"secret.example","port":"443","com":"tls"}],
         "stats":{"speed":{"up":50,"down":75},
                  "counters":{"bytes_up":500,"bytes_down":750}}}
    ])");
    assert(activity.snapshot);
    assert(activity.snapshot->total == 2U);
    assert(activity.snapshot->speed_up == 150U);
    assert(activity.snapshot->speed_down == 275U);
    assert(activity.snapshot->protocols.size() == 1U);
    assert(activity.snapshot->protocols.front().protocol == "tls");
    assert(activity.snapshot->protocols.front().sessions == 2U);
    assert(!parse_live_sessions("not json").snapshot);
    assert(!parse_live_sessions(R"([{"left":[{"com":"tls"}],"right":[{"com":"tls"}],
        "stats":{"speed":{"up":-1,"down":0},"counters":{"bytes_up":0,"bytes_down":0}}}])").snapshot);

    const auto neighbors = parse_neighbor_metrics(R"([
        {"hostname":"private.example","tags":"office","last_seen":1,"stats":[
            {"relative_days":0,"counter":3,"bytes_up":100,"bytes_down":200},
            {"relative_days":7,"counter":2,"bytes_up":50,"bytes_down":75}]},
        {"hostname":"another.private","tags":"","last_seen":1,"stats":[
            {"relative_days":3,"counter":4,"bytes_up":10,"bytes_down":20}]}
    ])");
    assert(neighbors.metrics);
    assert(neighbors.metrics->hosts_total == 2U);
    assert(neighbors.metrics->active_today == 1U);
    assert(neighbors.metrics->active_week == 2U);
    assert(neighbors.metrics->observations == 9U);
    assert(neighbors.metrics->bytes_down == 295U);
    assert(!parse_neighbor_metrics(R"([{"hostname":"duplicate","tags":"","last_seen":1,"stats":[]},
        {"hostname":"duplicate","tags":"","last_seen":1,"stats":[]}])").metrics);

    const auto interfaces = parse_interface_metrics(R"({
        "schema_version":1,"state":"ready","generation":42,"sampled_at_unix_ms":1793239515319,
        "synchronization":{"running":true,"attempts":2,"successes":2,"errors":0,
            "event_datagrams":15,"changed_event_datagrams":4},
        "totals":{"interfaces":3,"addresses":5,"ipv4_addresses":3,"ipv6_addresses":2},
        "last_error":null})");
    assert(interfaces.metrics);
    assert(interfaces.metrics->generation == 42U);
    assert(interfaces.metrics->interfaces == 3U);
    assert(interfaces.metrics->addresses == 5U);
    assert(interfaces.metrics->changed_event_datagrams == 4U);
    assert(!parse_interface_metrics(R"({
        "schema_version":1,"state":"ready","generation":1,"sampled_at_unix_ms":1,
        "synchronization":{"running":true,"attempts":1,"successes":2,"errors":0,
            "event_datagrams":1,"changed_event_datagrams":0},
        "totals":{"interfaces":1,"addresses":1,"ipv4_addresses":1,"ipv6_addresses":0},
        "last_error":null})").metrics);
    assert(!parse_interface_metrics(R"({
        "schema_version":1,"state":"ready","generation":1,"sampled_at_unix_ms":1,
        "synchronization":{"running":true,"attempts":1,"successes":1,"errors":0,
            "event_datagrams":1,"changed_event_datagrams":0},
        "totals":{"interfaces":1,"addresses":1,"ipv4_addresses":1,"ipv6_addresses":0},
        "last_error":"raw kernel error"})").metrics);
    assert(!parse_interface_metrics(R"({
        "schema_version":1,"state":"ready","generation":1,
        "sampled_at_unix_ms":9007199254740991,
        "synchronization":{"running":true,"attempts":1,"successes":1,"errors":0,
            "event_datagrams":1,"changed_event_datagrams":0},
        "totals":{"interfaces":1,"addresses":1,"ipv4_addresses":1,"ipv6_addresses":0},
        "last_error":null})").metrics);

    const auto configuration = parse_config_snapshot(
        R"({"success":{"policy":[{"name":"office policy","disabled":"0","proto":"tcp","src":["office"],"sport":["any"],"dst":["internet"],"dport":["https"],"features":["sinkhole"],"action":"accept","nat":"masquerade","routing":"main","tls_profile":"inspect"}]}})",
        R"({"success":{"address_objects":{"office":{"type":"cidr","value":"10.0.0.0/24"},"internet":{"type":"fqdn","value":"example.test"}}}})",
        R"({"success":{"port_objects":{"https":{"start":"443","end":"443"}}}})",
        R"({"success":{"proto_objects":{"tcp":{"id":"6"}}}})");
    assert(configuration.snapshot);
    assert(configuration.snapshot->policies.size() == 1U);
    assert(configuration.snapshot->policies.front().name == "office policy");
    assert(configuration.snapshot->policies.front().enabled);
    assert(configuration.snapshot->policies.front().features == std::vector<std::string>{"sinkhole"});
    assert(configuration.snapshot->policies.front().sources == std::vector<std::string>{"office"});
    assert(configuration.snapshot->addresses.size() == 2U);
    assert(configuration.snapshot->ports.front().start == 443U);
    assert(configuration.snapshot->protocols.front().number == 6U);

    const auto legacy_address = parse_config_snapshot(
        R"({"success":{"policy":[]}})",
        R"({"success":{"address_objects":{"legacy":{"type":"0","cidr":"192.0.2.1/32"}}}})",
        R"({"success":{"port_objects":{}}})",
        R"({"success":{"proto_objects":{}}})");
    assert(legacy_address.snapshot);
    assert(legacy_address.snapshot->addresses.front().type == "cidr");
    assert(!parse_config_snapshot("{}", "{}", "{}", "{}").snapshot);
    assert(!parse_config_snapshot(
        R"({"success":{"policy":[]}})", R"({"success":{"address_objects":{}}})",
        R"({"success":{"port_objects":{"bad":{"start":"2","end":"1"}}}})",
        R"({"success":{"proto_objects":{}}})").snapshot);
    const auto profiles = parse_config_profiles(
        R"({"success":{"tls_profiles":{"inspect":{},"bypass":{}}}})",
        "tls_profiles", "tls");
    assert(profiles.profiles);
    assert(profiles.profiles->size() == 2U);
    assert(profiles.profiles->front().type == "tls");
    assert(!parse_config_profiles("{}", "tls_profiles", "tls").profiles);
    const auto routing_profiles = parse_config_profiles(
        R"({"success":{"routing":{"main":{"dnat_address":["internet"],"dnat_port":["https"],"dnat_lb_method":"sticky-l4","rewrite_sni":"old.example","rewrite_sni_to":"new.example"}}}})",
        "routing", "routing");
    assert(routing_profiles.profiles);
    assert(routing_profiles.profiles->front().routing);
    assert(routing_profiles.profiles->front().routing->destination_addresses ==
           std::vector<std::string>{"internet"});
    assert(routing_profiles.profiles->front().routing->load_balancing_method == "sticky-l4");
    assert(!parse_config_profiles(
        R"({"success":{"routing":{"bad":{"dnat_lb_method":"random"}}}})",
        "routing", "routing").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"routing":{"bad":{"rewrite_sni":"one-sided.example"}}}})",
        "routing", "routing").profiles);
    const auto tls_profiles = parse_config_profiles(
        R"({"success":{"tls_profiles":{"strict":{"inspect":"true","use_pfs":"true","left_use_pfs":"false","right_use_pfs":"true","left_disable_reuse":"true","right_disable_reuse":"false","allow_invalid_certs":"false","ocsp_mode":"2","ocsp_stapling":"true","ocsp_stapling_mode":"1","sni_based_cert":"true","ip_based_cert":"false","sni_filter_use_dns_cache":"true","sni_filter_use_dns_domain_tree":"false","redirect_warning_ports":[443,"44443"],"failed_certcheck_replacement":"true","failed_certcheck_override":"true","failed_certcheck_override_timeout":"900","failed_certcheck_override_timeout_type":"1","client_hello_timeout":"3000","handshake_timeout":"10000","sni_filter_bypass":["secret.example"],"client_cert_action":"use_configured","alerts":"unusual"}}}})",
        "tls_profiles", "tls");
    assert(tls_profiles.profiles);
    assert(tls_profiles.profiles->front().tls);
    assert(tls_profiles.profiles->front().tls->inspect);
    assert(!tls_profiles.profiles->front().tls->left_use_pfs);
    assert(tls_profiles.profiles->front().tls->left_disable_reuse);
    assert(tls_profiles.profiles->front().tls->ocsp_mode == 2U);
    assert(tls_profiles.profiles->front().tls->redirect_warning_ports ==
           std::vector<std::uint64_t>({443U, 44443U}));
    assert(tls_profiles.profiles->front().tls->failed_certificate_override_timeout == 900U);
    assert(tls_profiles.profiles->front().tls->sni_bypass_entries == 1U);
    assert(tls_profiles.profiles->front().tls->alerts == "unusual");
    assert(!parse_config_profiles(
        R"({"success":{"tls_profiles":{"bad":{"alerts":"verbose"}}}})",
        "tls_profiles", "tls").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"tls_profiles":{"bad":{"redirect_warning_ports":[443,443]}}}})",
        "tls_profiles", "tls").profiles);
    const auto detection_profiles = parse_config_profiles(
        R"({"success":{"detection_profiles":{"default":{"mode":"2","engines_enabled":"true","kb_enabled":"false"}}}})",
        "detection_profiles", "detection");
    assert(detection_profiles.profiles);
    assert(detection_profiles.profiles->front().detection);
    assert(detection_profiles.profiles->front().detection->mode == 2U);
    assert(!detection_profiles.profiles->front().detection->knowledge_base_enabled);
    const auto content_profiles = parse_config_profiles(
        R"({"success":{"content_profiles":{"capture":{"write_payload":"false","write_format":"pcap_single","webhook_enable":"true","rules_session_filter":"sensitive regex","content_rules":[{"match":"secret","replace":"redacted","fill_length":"true","replace_each_nth":"3"}]}}}})",
        "content_profiles", "content");
    assert(content_profiles.profiles);
    assert(content_profiles.profiles->front().content);
    assert(content_profiles.profiles->front().content->session_filter_configured);
    assert(content_profiles.profiles->front().content->rule_count == 1U);
    assert(content_profiles.profiles->front().content->rules.front().match_configured);
    assert(content_profiles.profiles->front().content->rules.front().replacement_has_value);
    assert(content_profiles.profiles->front().content->rules.front().fill_length);
    assert(content_profiles.profiles->front().content->rules.front().replace_each_nth == 3);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","content_rules":[{"replace":"missing match"}]}}}})",
        "content_profiles", "content").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","content_rules":[{"match":"ok","replace":"value","replace_each_nth":"2147483648"}]}}}})",
        "content_profiles", "content").profiles);
    assert(!parse_config_profiles(
        R"({"success":{"content_profiles":{"bad":{"write_payload":"false","write_format":"raw"}}}})",
        "content_profiles", "content").profiles);
    const auto ssh_profiles = parse_config_profiles(
        R"({"success":{"ssh_profiles":{"strict":{"host_key":"/sensitive/key/path","hostkey_policy":"strict","shell":"pass","exec":"reject","subsystem":"pass","pty":"pass","environment":"reject","local_forward":"reject","remote_forward":"reject","x11":"reject","agent":"reject"}}}})",
        "ssh_profiles", "ssh");
    assert(ssh_profiles.profiles);
    assert(ssh_profiles.profiles->front().ssh);
    assert(ssh_profiles.profiles->front().ssh->host_key_policy == "strict");
    assert(!ssh_profiles.profiles->front().ssh->exec);
    const auto dns_profiles = parse_config_profiles(
        R"({"success":{"alg_dns_profiles":{"safe":{"match_request_id":"true","randomize_id":"true","cached_responses":"false"}}}})",
        "alg_dns_profiles", "dns");
    assert(dns_profiles.profiles);
    assert(dns_profiles.profiles->front().dns);
    assert(dns_profiles.profiles->front().dns->randomize_id);
    assert(!parse_config_profiles(
        R"({"success":{"ssh_profiles":{"bad":{"host_key":"/key","shell":"allow"}}}})",
        "ssh_profiles", "ssh").profiles);
    const auto script_profiles = parse_config_profiles(
        R"({"success":{"script_profiles":{"audit":{"type":"0","script-file":"/sensitive/audit.py"}}}})",
        "script_profiles", "script");
    assert(script_profiles.profiles);
    assert(script_profiles.profiles->front().script);
    assert(script_profiles.profiles->front().script->runtime == "python");
    assert(script_profiles.profiles->front().script->module_path_configured);
    const auto auth_profiles = parse_config_profiles(
        R"({"success":{"auth_profiles":{"legacy":{"authenticate":"true","resolve":"false","identities":{"alice":{"tls_profile":"inspect"},"bob":{}}}}}})",
        "auth_profiles", "authentication");
    assert(auth_profiles.profiles);
    assert(auth_profiles.profiles->front().authentication);
    assert(auth_profiles.profiles->front().authentication->identity_count == 2U);
    assert(!auth_profiles.profiles->front().authentication->resolve);
    assert(!parse_config_profiles(
        R"({"success":{"script_profiles":{"bad":{"type":"7"}}}})",
        "script_profiles", "script").profiles);
    const auto settings = parse_config_settings(
        R"({"success":{"settings":{"accept_tproxy":"true","policy_fail_open":"false","plaintext_workers":"2","ssl_workers":"4","quic_workers":"-1","socks_workers":"-1","plaintext_port":"50080","ssl_port":"50443","udp_port":"50080","dtls_port":"50444","quic_port":"443","socks_port":"1081","http_connect_port":"3128","tpool_log":"true","ssl_ocsp_status_ttl":"1800","ssl_crl_status_ttl":"86400","default_write_payload":"false","write_payload_dir":"/private/payloads","write_pcap_single_quota":"100","log_level":"6","log_file":"/private/messages.log","log_console":"true","sslkeylog_file":"/private/tls.keys","syslog_server":"192.0.2.60","syslog_port":"514","syslog_facility":"23","syslog_level":"6","syslog_family":"4","udp_quick_ports":["0"],"certs_path":"/private/certs","certs_ca_key_password":"password","ca_bundle_path":"/private/ca","messages_dir":"/private/messages","write_payload_file_prefix":"prefix","write_payload_file_suffix":"suffix","cli":{"port":"50000","enable_password":"password"},"web_rating":{"wot_key":"key"},"socks":{"async_dns":"true","ipver_mixing":"false","prefer_ipv6":"true"},"nameservers":["192.0.2.53"],"http_api":{"keys":["secret"],"allowed_ips":["127.0.0.1"],"loopback_only":"true"},"webhook":{"enabled":"true","tls_verify":"true","url":"https://private.example/","sift":"true","sift_url":"http://private-sift/","sift_tenant_id":"tenant","sift_instance_id":"instance","sift_payload_limit_per_direction":"524288","hostid":"host","bind_interface":"vrf0","ping_interval":"60","nbr_update_interval":"600","nbr_tag_refresh_age":"240","task_debug":"true","task_debug_dump":"false"}}}})");
    assert(settings.settings);
    assert(settings.settings->accept_tproxy);
    assert(settings.settings->tls_workers == 4);
    assert(settings.settings->quic_workers == -1);
    assert(settings.settings->socks_workers == -1);
    assert(settings.settings->tls_port == 50443U);
    assert(settings.settings->ocsp_status_ttl == 1800U);
    assert(settings.settings->payload_directory_configured);
    assert(settings.settings->log_file_configured);
    assert(settings.settings->syslog_server_configured);
    assert(settings.settings->syslog_family == 4U);
    assert(settings.settings->udp_quick_port_count == 1U);
    assert(settings.settings->udp_quick_ports == std::vector<std::string>{"0"});
    assert(settings.settings->certificate_password_configured);
    assert(settings.settings->cli_password_configured);
    assert(settings.settings->web_rating_key_configured);
    assert(settings.settings->socks_async_dns);
    assert(settings.settings->dtls_port == 50444U);
    assert(settings.settings->socks_port == 1081U);
    assert(settings.settings->thread_pool_logging);
    assert(!settings.settings->socks_ip_version_mixing);
    assert(settings.settings->socks_prefer_ipv6);
    assert(settings.settings->webhook_sift_enabled);
    assert(settings.settings->webhook_sift_url_configured);
    assert(settings.settings->webhook_sift_tenant_configured);
    assert(settings.settings->webhook_sift_instance_configured);
    assert(settings.settings->webhook_sift_payload_limit == 524288U);
    assert(settings.settings->webhook_host_id_configured);
    assert(settings.settings->webhook_bind_interface_configured);
    assert(settings.settings->webhook_ping_interval == 60U);
    assert(settings.settings->webhook_neighbor_update_interval == 600U);
    assert(settings.settings->webhook_neighbor_tag_refresh_age == 240U);
    assert(settings.settings->webhook_task_debug);
    assert(!settings.settings->webhook_task_debug_dump);
    assert(settings.settings->extended_local_destination_protection);
    assert(settings.settings->webhook_sift_lored_mode == "disabled");
    assert(!settings.settings->webhook_sift_lored_include_url);
    const auto current_security_settings = parse_config_settings(
        R"({"success":{"settings":{"extended_local_destination_protection":"false","webhook":{"sift_lored_mode":"required","sift_lored_include_url":"true"}}}})");
    assert(current_security_settings.settings);
    assert(!current_security_settings.settings->extended_local_destination_protection);
    assert(current_security_settings.settings->webhook_sift_lored_mode == "required");
    assert(current_security_settings.settings->webhook_sift_lored_include_url);
    const auto tuning_settings = parse_config_settings(
        R"({"success":{"settings":{"certs_ctlog":"/private/ct-log.cnf","ca_bundle_file":"/private/ca.pem","admin":{"group":"smithproxy-admins"},"tuning":{"host_bufsz_min":"4096","host_bufsz_max_multiplier":"512","host_write_full":"100000","host_io_batch":"131072","tls_write_chunk":"32768","host_open_timeout":"9","host_idle_timeout":"1800","nbr_cache_size":"4000"}}}})");
    assert(tuning_settings.settings);
    assert(tuning_settings.settings->certificate_transparency_log_configured);
    assert(tuning_settings.settings->ca_bundle_file_configured);
    assert(tuning_settings.settings->admin_group_configured);
    assert(tuning_settings.settings->tuning_host_buffer_min == 4096U);
    assert(tuning_settings.settings->tuning_host_buffer_max_multiplier == 512U);
    assert(tuning_settings.settings->tuning_host_write_full == 100000U);
    assert(tuning_settings.settings->tuning_host_io_batch == 131072U);
    assert(tuning_settings.settings->tuning_tls_write_chunk == 32768U);
    assert(tuning_settings.settings->tuning_host_open_timeout == 9U);
    assert(tuning_settings.settings->tuning_host_idle_timeout == 1800U);
    assert(tuning_settings.settings->tuning_neighbor_cache_size == 4000U);
    assert(settings.settings->nameservers == std::vector<std::string>{"192.0.2.53"});
    assert(settings.settings->api_key_count == 1U);
    assert(settings.settings->api_allowed_ips == std::vector<std::string>{"127.0.0.1"});
    assert(settings.settings->api_key_timeout == 3600U);
    assert(settings.settings->api_port == 55555U);
    assert(settings.settings->api_key_extend_on_access);
    assert(!settings.settings->api_bind_address_configured);
    assert(settings.settings->webhook_url_configured);
    const auto http_api_settings = parse_config_settings(
        R"({"success":{"settings":{"default_write_payload":"false","http_api":{"key_timeout":"900","port":"55580","key_extend_on_access":"false","bind_address":"127.0.0.1","bind_interface":"private0"}}}})");
    assert(http_api_settings.settings);
    assert(http_api_settings.settings->api_key_timeout == 900U);
    assert(http_api_settings.settings->api_port == 55580U);
    assert(!http_api_settings.settings->api_key_extend_on_access);
    assert(http_api_settings.settings->api_bind_address_configured);
    assert(http_api_settings.settings->api_bind_interface_configured);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"http_api":{"keys":"secret"}}}})").settings);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"quic_workers":"-2"}}})").settings);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"default_write_payload":"false","http_api":{"port":"1024"}}}})").settings);
    assert(!parse_config_settings(
        R"({"success":{"settings":{"webhook":{"sift_lored_mode":"unexpected"}}}})").settings);
    const auto debug = parse_config_debug(
        R"({"success":{"debug":{"log_data_crc":"true","log_sockets":"false","log_online_cx_name":"true","log_srclines":"false","log_srclines_always":"true","log":{"proxy":"7","tls":"8"}}}})");
    assert(debug.debug);
    assert(debug.debug->log_data_crc);
    assert(debug.debug->log_online_connection_name);
    assert(debug.debug->log_source_lines_always);
    assert(debug.debug->module_override_count == 2U);
    assert(debug.debug->module_overrides.size() == 2U);
    assert(debug.debug->module_overrides[0].name == "proxy");
    assert(debug.debug->module_overrides[0].kind == "integer");
    assert(debug.debug->module_overrides[0].value == "7");
    assert(!parse_config_debug(
        R"({"success":{"debug":{"log":{"proxy":{}}}}})").debug);
    const auto captures = parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/private/captures","format":"pcap_single","pcap_quota":"512"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"192.0.2.10","tun_ttl":"1","bind_interface":"private0"},"options":{"calculate_checksums":"true"}}}})");
    assert(captures.captures);
    assert(captures.captures->local_enabled);
    assert(!captures.captures->local_file_prefix_configured);
    assert(!captures.captures->local_file_suffix_configured);
    assert(captures.captures->local_quota_mib == 512U);
    assert(captures.captures->remote_destination_configured);
    assert(!parse_config_captures(
        R"({"success":{"captures":{"local":{"enabled":"true","dir":"/tmp","format":"raw"},"remote":{"enabled":"false","tun_type":"gre","gre_format":"traffic","tun_dst":"","tun_ttl":"1"}}}})").captures);
    const auto security_assets = parse_config_security_assets(
        R"({"success":{"tls_ca":{"default":{"path":"/private/ca"}}}})",
        R"({"success":{"starttls_signatures":[{"cat":"mail","name":"smtp/starttls","side":"client","severity":"2","flow":[{"side":"r","type":"regex","signature":"^STARTTLS","bytes_start":"0","bytes_max":"16"},{"side":"w","type":"regex","signature":"^2[0-5]0","bytes_start":"0","bytes_max":"512"}]}]}})",
        R"({"success":{"detection_signatures":[{"cat":"www","name":"http/request","side":"client","severity":"4","group":"base","enables":"http","engine":"http1","flow":[{"side":"r","type":"regex","signature":"^GET","bytes_start":"0","bytes_max":"200"}]},{"name":"eicar","flow":[{"signature":"EICAR"},{"side":"w","type":"simple","signature":"test"}]}]}})");
    assert(security_assets.security_assets);
    assert(security_assets.security_assets->certificate_authority_count == 1U);
    assert(security_assets.security_assets->certificate_authorities.size() == 1U);
    assert(security_assets.security_assets->certificate_authorities.front().name == "default");
    assert(security_assets.security_assets->certificate_authorities.front().path_configured);
    assert(security_assets.security_assets->starttls_flow_step_count == 2U);
    assert(security_assets.security_assets->detection_signature_count == 2U);
    assert(security_assets.security_assets->detection_flow_step_count == 3U);
    assert(security_assets.security_assets->signatures.size() == 3U);
    assert(security_assets.security_assets->signatures.front().name == "smtp/starttls");
    assert(security_assets.security_assets->signatures.front().severity == 2);
    assert(security_assets.security_assets->signatures.front().flow.front().expression_configured);
    assert(!parse_config_security_assets(
        R"({"success":{"tls_ca":{}}})",
        R"({"success":{"starttls_signatures":[{"flow":"secret"}]}})",
        R"({"success":{"detection_signatures":[]}})").security_assets);

    const auto now = std::chrono::system_clock::now();
    SmithproxyStatus alert_status;
    alert_status.state = "ready";
    alert_status.last_success_at = now;
    alert_status.runtime_metrics.state = "ready";
    alert_status.runtime_metrics.last_success_at = now;
    alert_status.live_sessions.state = "ready";
    alert_status.live_sessions.last_success_at = now;
    alert_status.tls_cache_metrics.state = "ready";
    alert_status.tls_cache_metrics.last_success_at = now;
    alert_status.tls_cache_metrics.capacity = 100U;
    alert_status.tls_cache_metrics.size = 42U;
    alert_status.neighbor_metrics.state = "ready";
    alert_status.neighbor_metrics.last_success_at = now;
    alert_status.interface_metrics.state = "ready";
    alert_status.interface_metrics.last_success_at = now;
    alert_status.config_snapshot.state = "ready";
    alert_status.config_snapshot.last_success_at = now;
    assert(derive_operational_alerts(alert_status, true, true, now).empty());

    alert_status.tls_cache_metrics.size = 90U;
    auto active_alerts = derive_operational_alerts(alert_status, true, true, now);
    assert(active_alerts.size() == 1U);
    assert(active_alerts.front().id == "tls-cache-capacity");
    assert(active_alerts.front().severity == "warning");
    alert_status.tls_cache_metrics.size = 100U;
    active_alerts = derive_operational_alerts(alert_status, true, true, now);
    assert(active_alerts.front().severity == "critical");

    alert_status.tls_cache_metrics.size = 42U;
    alert_status.live_sessions.last_success_at = now - std::chrono::seconds{61};
    active_alerts = derive_operational_alerts(alert_status, true, true, now);
    assert(active_alerts.size() == 1U);
    assert(active_alerts.front().id == "session-activity-stale");
    alert_status.live_sessions.last_success_at = now;
    alert_status.interface_metrics.state = "degraded";
    active_alerts = derive_operational_alerts(alert_status, true, true, now);
    assert(active_alerts.size() == 1U);
    assert(active_alerts.front().id == "interfaces");
    alert_status.interface_metrics.state = "ready";
    alert_status.config_snapshot.settings.emplace();
    alert_status.config_snapshot.settings->extended_local_destination_protection = false;
    active_alerts = derive_operational_alerts(alert_status, true, true, now);
    assert(active_alerts.size() == 1U);
    assert(active_alerts.front().id == "local-destination-protection-disabled");
    assert(active_alerts.front().severity == "warning");

    const auto unconfigured_alerts = derive_operational_alerts({}, false, false, now);
    assert(unconfigured_alerts.size() == 1U);
    assert(unconfigured_alerts.front().id == "control-plane-unconfigured");

    std::vector<std::string> arguments{"smithproxy-gui", "--base-path", "/", "--port", "18082"};
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    const auto parsed = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(parsed.config);
    assert(parsed.config->base_path == "/");
    assert(parsed.config->port == 18082);

    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "short", 1);
    const auto invalid_secret = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(!invalid_secret.config);
    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "0123456789abcdef0123456789abcdef", 1);
    const auto authenticated = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(authenticated.config);
    assert(authenticated.config->gateway_secret == "0123456789abcdef0123456789abcdef");
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");

    setenv("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS", "previous-0123456789abcdef01234567", 1);
    const auto previous_without_current = parse_config(
        static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(!previous_without_current.config);
    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "0123456789abcdef0123456789abcdef", 1);
    const auto rotating = parse_config(static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(rotating.config);
    assert(rotating.config->previous_gateway_secret == "previous-0123456789abcdef01234567");
    setenv("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS", "0123456789abcdef0123456789abcdef", 1);
    const auto duplicate_secrets = parse_config(
        static_cast<int>(argv.size()), argv.data(), "/srv/gui");
    assert(!duplicate_secrets.config);
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS");

    std::vector<std::string> remote_arguments{"smithproxy-gui", "--bind", "0.0.0.0"};
    std::vector<char*> remote_argv;
    for (auto& argument : remote_arguments) remote_argv.push_back(argument.data());
    const auto unauthenticated_remote = parse_config(
        static_cast<int>(remote_argv.size()), remote_argv.data(), "/srv/gui");
    assert(!unauthenticated_remote.config);
    assert(unauthenticated_remote.error ==
           "non-loopback bind requires SMITHPROXY_GUI_GATEWAY_SECRET");

    setenv("SMITHPROXY_GUI_GATEWAY_SECRET", "0123456789abcdef0123456789abcdef", 1);
    const auto authenticated_remote = parse_config(
        static_cast<int>(remote_argv.size()), remote_argv.data(), "/srv/gui");
    assert(authenticated_remote.config);
    unsetenv("SMITHPROXY_GUI_GATEWAY_SECRET");
    return 0;
}
