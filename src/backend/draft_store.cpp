#include "draft_store.hpp"

#include <algorithm>
#include <cmath>
#include <type_traits>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_changes = 4096U;
constexpr std::size_t maximum_path_length = 512U;
constexpr std::size_t maximum_string_length = 65536U;

} // namespace

DraftStore::DraftStore(std::string id, std::optional<std::string> base_revision)
    : draft_{std::move(id), std::move(base_revision), 0U, {}} {}

DraftSnapshot DraftStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    return draft_;
}

DraftMutationResult DraftStore::upsert(const std::uint64_t expected_version, DraftChange change) {
    if (!valid_path(change.path)) return DraftMutationResult::InvalidPath;
    if (!valid_value(change.value)) return DraftMutationResult::InvalidValue;
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    const auto found = std::find_if(draft_.changes.begin(), draft_.changes.end(),
                                    [&](const DraftChange& item) { return item.path == change.path; });
    if (found == draft_.changes.end()) {
        if (draft_.changes.size() >= maximum_changes) return DraftMutationResult::CapacityExceeded;
        draft_.changes.push_back(std::move(change));
    } else {
        found->value = std::move(change.value);
    }
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::remove(const std::uint64_t expected_version, const std::string& path) {
    if (!valid_path(path)) return DraftMutationResult::InvalidPath;
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    const auto found = std::find_if(draft_.changes.begin(), draft_.changes.end(),
                                    [&](const DraftChange& item) { return item.path == path; });
    if (found == draft_.changes.end()) return DraftMutationResult::Missing;
    draft_.changes.erase(found);
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::clear(const std::uint64_t expected_version) {
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    draft_.changes.clear();
    ++draft_.version;
    return DraftMutationResult::Applied;
}

bool DraftStore::valid_path(const std::string& path) {
    if (path.empty() || path.size() > maximum_path_length) return false;
    return std::all_of(path.begin(), path.end(), [](const unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') ||
               (character >= '0' && character <= '9') || character == '_' || character == '-' ||
               character == '.' || character == '[' || character == ']';
    });
}

bool DraftStore::valid_value(const DraftScalar& value) {
    return std::visit([](const auto& item) {
        using Value = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Value, std::string>) {
            if (item.size() > maximum_string_length) return false;
            return std::none_of(item.begin(), item.end(), [](const unsigned char character) {
                return character == 0U;
            });
        } else if constexpr (std::is_same_v<Value, double>) {
            return std::isfinite(item);
        } else {
            return true;
        }
    }, value);
}

} // namespace smithproxy::gui
