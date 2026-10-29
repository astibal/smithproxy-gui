#pragma once

#include <cstdint>
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

struct DraftSnapshot {
    std::string id;
    std::optional<std::string> base_revision;
    std::uint64_t version{};
    std::vector<DraftChange> changes;
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
    bool bind_base_revision(const std::string& revision);
    DraftMutationResult upsert(std::uint64_t expected_version, DraftChange change);
    DraftMutationResult upsert_many(std::uint64_t expected_version, std::vector<DraftChange> changes);
    DraftMutationResult remove(std::uint64_t expected_version, const std::string& path);
    DraftMutationResult clear(std::uint64_t expected_version);
    DraftMutationResult complete_commit(
        std::uint64_t expected_version, const std::string& committed_revision);

private:
    static bool valid_path(const std::string& path);
    static bool valid_value(const DraftScalar& value);

    mutable std::mutex mutex_;
    DraftSnapshot draft_;
};

} // namespace smithproxy::gui
