#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace smithproxy::gui {

using DraftScalar = std::variant<bool, std::int64_t, double, std::string,
                                 std::vector<std::string>, std::vector<std::int64_t>>;

struct DraftChange {
    std::string path;
    DraftScalar value;
};

enum class DraftPositionKind { First, Last, Before, After };

struct DraftPosition {
    DraftPositionKind kind{DraftPositionKind::Last};
    std::optional<std::string> reference;
};

struct DraftCreateOperation {
    std::string local_id;
    std::string collection;
    std::string client_id;
    std::optional<std::string> parent_id;
    DraftPosition position;
    std::map<std::string, DraftScalar, std::less<>> fields;
};

struct DraftDeleteOperation {
    std::string local_id;
    std::string collection;
    std::string entity_id;
};

struct DraftMoveOperation {
    std::string local_id;
    std::string collection;
    std::string entity_id;
    DraftPosition position;
};

using DraftStructuralOperation =
    std::variant<DraftCreateOperation, DraftDeleteOperation, DraftMoveOperation>;

struct DraftSnapshot {
    std::string id;
    std::optional<std::string> base_revision;
    std::uint64_t version{};
    std::vector<DraftChange> changes;
    std::vector<DraftStructuralOperation> structural_operations;

    [[nodiscard]] bool empty() const noexcept {
        return changes.empty() && structural_operations.empty();
    }
    [[nodiscard]] std::size_t operation_count() const noexcept {
        return changes.size() + structural_operations.size();
    }
};

enum class DraftMutationResult {
    Applied,
    VersionConflict,
    InvalidPath,
    InvalidValue,
    CapacityExceeded,
    Missing,
    Busy,
};

class DraftStore {
public:
    explicit DraftStore(std::string id, std::optional<std::string> base_revision = std::nullopt);

    [[nodiscard]] DraftSnapshot snapshot() const;
    bool bind_base_revision(
        const std::string& revision,
        std::chrono::steady_clock::time_point observation_started_at);
    DraftMutationResult upsert(std::uint64_t expected_version, DraftChange change);
    DraftMutationResult upsert_many(std::uint64_t expected_version, std::vector<DraftChange> changes);
    DraftMutationResult reconcile(
        std::uint64_t expected_version,
        std::vector<DraftChange> changes,
        std::vector<std::string> remove_paths);
    DraftMutationResult remove(std::uint64_t expected_version, const std::string& path);
    DraftMutationResult remove_many(std::uint64_t expected_version, std::vector<std::string> paths);
    DraftMutationResult upsert_structural(
        std::uint64_t expected_version, DraftStructuralOperation operation);
    DraftMutationResult upsert_structural_many(
        std::uint64_t expected_version, std::vector<DraftStructuralOperation> operations);
    DraftMutationResult remove_structural(
        std::uint64_t expected_version, const std::string& local_id);
    DraftMutationResult clear(std::uint64_t expected_version);
    DraftMutationResult complete_commit(
        std::uint64_t expected_version, const std::string& committed_revision);

private:
    static bool valid_path(const std::string& path);
    static bool valid_value(const DraftScalar& value);

    mutable std::mutex mutex_;
    DraftSnapshot draft_;
    std::chrono::steady_clock::time_point minimum_revision_observation_{};
};

} // namespace smithproxy::gui
