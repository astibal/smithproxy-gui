#include "draft_store.hpp"

#include "draft_schema.hpp"

#include <algorithm>
#include <cmath>
#include <type_traits>

namespace smithproxy::gui {
namespace {

constexpr std::size_t maximum_changes = 4096U;
constexpr std::size_t maximum_path_length = 512U;
constexpr std::size_t maximum_string_length = 65536U;
constexpr std::size_t maximum_array_items = 256U;
constexpr std::size_t maximum_draft_bytes = 1024U * 1024U;

std::size_t value_size(const DraftScalar& value) {
    return std::visit([](const auto& item) -> std::size_t {
        using Value = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Value, std::string>) {
            return item.size();
        } else if constexpr (std::is_same_v<Value, std::vector<std::string>>) {
            std::size_t total{};
            for (const auto& entry : item) total += entry.size();
            return total;
        } else if constexpr (std::is_same_v<Value, std::vector<std::int64_t>>) {
            return item.size() * sizeof(std::int64_t);
        } else {
            return sizeof(item);
        }
    }, value);
}

} // namespace

DraftStore::DraftStore(std::string id, std::optional<std::string> base_revision)
    : draft_{std::move(id), std::move(base_revision), 0U, {}} {}

DraftSnapshot DraftStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    return draft_;
}

DraftMutationResult DraftStore::upsert(const std::uint64_t expected_version, DraftChange change) {
    std::vector<DraftChange> changes;
    changes.push_back(std::move(change));
    return upsert_many(expected_version, std::move(changes));
}

DraftMutationResult DraftStore::upsert_many(
    const std::uint64_t expected_version, std::vector<DraftChange> changes) {
    if (changes.empty() || changes.size() > maximum_changes) {
        return DraftMutationResult::CapacityExceeded;
    }
    for (std::size_t index = 0; index < changes.size(); ++index) {
        if (!valid_path(changes[index].path)) return DraftMutationResult::InvalidPath;
        if (!valid_value(changes[index].value)) return DraftMutationResult::InvalidValue;
        const auto schema = validate_draft_schema(changes[index]);
        if (schema == DraftSchemaResult::UnknownPath) return DraftMutationResult::InvalidPath;
        if (schema == DraftSchemaResult::InvalidValue) return DraftMutationResult::InvalidValue;
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (changes[previous].path == changes[index].path) return DraftMutationResult::InvalidPath;
        }
    }
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    auto proposed = draft_.changes;
    for (auto& change : changes) {
        const auto found = std::find_if(proposed.begin(), proposed.end(),
                                        [&](const DraftChange& item) { return item.path == change.path; });
        if (found == proposed.end()) proposed.push_back(std::move(change));
        else found->value = std::move(change.value);
    }
    if (proposed.size() > maximum_changes) return DraftMutationResult::CapacityExceeded;
    std::size_t proposed_size{};
    for (const auto& change : proposed) {
        if (change.path.size() > maximum_draft_bytes - proposed_size) {
            return DraftMutationResult::CapacityExceeded;
        }
        proposed_size += change.path.size();
        const auto size = value_size(change.value);
        if (size > maximum_draft_bytes - proposed_size) {
            return DraftMutationResult::CapacityExceeded;
        }
        proposed_size += size;
    }
    draft_.changes = std::move(proposed);
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
        } else if constexpr (std::is_same_v<Value, std::vector<std::string>>) {
            if (item.size() > maximum_array_items) return false;
            return std::all_of(item.begin(), item.end(), [](const std::string& entry) {
                return !entry.empty() && entry.size() <= maximum_string_length &&
                       std::none_of(entry.begin(), entry.end(), [](const unsigned char character) {
                           return character == 0U;
                       });
            });
        } else if constexpr (std::is_same_v<Value, std::vector<std::int64_t>>) {
            return item.size() <= maximum_array_items;
        } else if constexpr (std::is_same_v<Value, double>) {
            return std::isfinite(item);
        } else {
            return true;
        }
    }, value);
}

} // namespace smithproxy::gui
