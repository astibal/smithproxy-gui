#include "draft_store.hpp"

#include "draft_operation.hpp"
#include "draft_schema.hpp"
#include "revision.hpp"

#include <algorithm>
#include <cmath>
#include <type_traits>

#include <nlohmann/json.hpp>

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
        } else if constexpr (std::is_same_v<Value, DraftAuthIdentities>) {
            std::size_t total{};
            for (const auto& identity : item) {
                total += identity.name.size() + identity.detection_profile.size() +
                         identity.content_profile.size() + identity.tls_profile.size() +
                         identity.alg_dns_profile.size();
            }
            return total;
        } else {
            return sizeof(item);
        }
    }, value);
}

bool add_size(std::size_t& total, const std::size_t increment) {
    if (increment > maximum_draft_bytes - total) return false;
    total += increment;
    return true;
}

std::optional<std::size_t> structural_size(const DraftStructuralOperation& operation) {
    std::size_t total{};
    const auto valid = std::visit([&](const auto& item) {
        if (!add_size(total, item.local_id.size()) || !add_size(total, item.collection.size())) {
            return false;
        }
        using Operation = std::decay_t<decltype(item)>;
        if constexpr (std::is_same_v<Operation, DraftCreateOperation>) {
            if (!add_size(total, item.client_id.size()) ||
                (item.parent_id && !add_size(total, item.parent_id->size())) ||
                (item.position.reference && !add_size(total, item.position.reference->size()))) {
                return false;
            }
            for (const auto& [name, value] : item.fields) {
                if (!add_size(total, name.size()) || !add_size(total, value_size(value))) return false;
            }
            return true;
        } else if constexpr (std::is_same_v<Operation, DraftDeleteOperation>) {
            return add_size(total, item.entity_id.size());
        } else {
            return add_size(total, item.entity_id.size()) &&
                   (!item.position.reference || add_size(total, item.position.reference->size()));
        }
    }, operation);
    return valid ? std::optional<std::size_t>{total} : std::nullopt;
}

bool valid_structural_set(const std::vector<DraftStructuralOperation>& operations) {
    for (std::size_t index = 0; index < operations.size(); ++index) {
        if (!valid_draft_structural_operation(operations[index])) return false;
        const auto local_id = draft_structural_local_id(operations[index]);
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (draft_structural_local_id(operations[previous]) == local_id) return false;
        }
        const auto* create = std::get_if<DraftCreateOperation>(&operations[index]);
        const auto target = std::visit([](const auto& item) -> std::optional<std::string> {
            using Operation = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<Operation, DraftCreateOperation>) return std::nullopt;
            else return item.collection + "\n" + item.entity_id;
        }, operations[index]);
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (create != nullptr) {
                const auto* previous_create = std::get_if<DraftCreateOperation>(&operations[previous]);
                if (previous_create != nullptr && previous_create->client_id == create->client_id) return false;
            } else if (target) {
                const auto previous_target = std::visit([](const auto& item) -> std::optional<std::string> {
                    using Operation = std::decay_t<decltype(item)>;
                    if constexpr (std::is_same_v<Operation, DraftCreateOperation>) return std::nullopt;
                    else return item.collection + "\n" + item.entity_id;
                }, operations[previous]);
                if (previous_target == target) return false;
            }
        }
    }
    for (std::size_t index = 0; index < operations.size(); ++index) {
        const auto* parent = std::get_if<DraftCreateOperation>(&operations[index]);
        if (parent == nullptr || (parent->collection != "starttls_signatures" &&
                                  parent->collection != "detection_signatures")) {
            continue;
        }
        const auto expected_flow_collection = parent->collection + ".flow";
        const auto child = std::find_if(
            operations.begin() + static_cast<std::ptrdiff_t>(index + 1U), operations.end(),
            [&](const auto& candidate) {
                const auto* create = std::get_if<DraftCreateOperation>(&candidate);
                return create != nullptr && create->collection == expected_flow_collection &&
                       create->parent_id == parent->client_id;
            });
        if (child == operations.end()) return false;
    }
    return true;
}

bool scalar_references_name(const DraftScalar& value, const std::string_view name) {
    if (const auto* scalar = std::get_if<std::string>(&value)) return *scalar == name;
    const auto* values = std::get_if<std::vector<std::string>>(&value);
    return values != nullptr && std::find(values->begin(), values->end(), name) != values->end();
}

bool identity_references_name(
    const DraftScalar& value, const std::string_view target_collection, const std::string_view name) {
    const auto* identities = std::get_if<DraftAuthIdentities>(&value);
    if (identities == nullptr) return false;
    return std::any_of(identities->begin(), identities->end(), [&](const DraftAuthIdentity& identity) {
        if (target_collection == "detection_profiles") return identity.detection_profile == name;
        if (target_collection == "content_profiles") return identity.content_profile == name;
        if (target_collection == "tls_profiles") return identity.tls_profile == name;
        if (target_collection == "alg_dns_profiles") return identity.alg_dns_profile == name;
        return false;
    });
}

bool field_references_created_entity(
    const std::string_view target_collection, const std::string_view target_name,
    const std::string_view consumer_collection, const std::string_view field,
    const DraftScalar& value) {
    if (consumer_collection == "auth_profiles" && field == "identities" &&
        identity_references_name(value, target_collection, target_name)) {
        return true;
    }
    const auto policy_reference = [&](const std::string_view expected_field) {
        return consumer_collection == "policy" && field == expected_field &&
               scalar_references_name(value, target_name);
    };
    if (target_collection == "address_objects") {
        return ((consumer_collection == "policy" && (field == "src" || field == "dst")) ||
                (consumer_collection == "routing" && field == "dnat_address")) &&
               scalar_references_name(value, target_name);
    }
    if (target_collection == "port_objects") {
        return ((consumer_collection == "policy" && (field == "sport" || field == "dport")) ||
                (consumer_collection == "routing" && field == "dnat_port")) &&
               scalar_references_name(value, target_name);
    }
    if (target_collection == "proto_objects") return policy_reference("proto");
    if (target_collection == "routing") return policy_reference("routing");
    if (target_collection == "tls_profiles") return policy_reference("tls_profile");
    if (target_collection == "ssh_profiles") return policy_reference("ssh_profile");
    if (target_collection == "detection_profiles") return policy_reference("detection_profile");
    if (target_collection == "content_profiles") return policy_reference("content_profile");
    if (target_collection == "auth_profiles") return policy_reference("auth_profile");
    if (target_collection == "alg_dns_profiles") return policy_reference("alg_dns_profile");
    if (target_collection == "script_profiles") return policy_reference("script_profile");
    return false;
}

} // namespace

DraftStore::DraftStore(std::string id, std::optional<std::string> base_revision)
    : draft_{std::move(id), std::move(base_revision), 0U, {}, {}} {}

DraftSnapshot DraftStore::snapshot() const {
    std::scoped_lock lock(mutex_);
    return draft_;
}

bool DraftStore::bind_base_revision(
    const std::string& revision,
    const std::chrono::steady_clock::time_point observation_started_at) {
    if (!is_canonical_revision(revision)) return false;
    std::scoped_lock lock(mutex_);
    if (observation_started_at == std::chrono::steady_clock::time_point{} ||
        observation_started_at <= minimum_revision_observation_) {
        return false;
    }
    if (!draft_.empty()) {
        if (draft_.base_revision != revision) return false;
        minimum_revision_observation_ = observation_started_at;
        return true;
    }
    minimum_revision_observation_ = observation_started_at;
    if (draft_.base_revision == revision) return true;
    draft_.base_revision = revision;
    ++draft_.version;
    return true;
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
    return reconcile(expected_version, std::move(changes), {});
}

DraftMutationResult DraftStore::reconcile(
    const std::uint64_t expected_version,
    std::vector<DraftChange> changes,
    std::vector<std::string> remove_paths) {
    if ((changes.empty() && remove_paths.empty()) ||
        changes.size() > maximum_changes || remove_paths.size() > maximum_changes ||
        changes.size() > maximum_changes - remove_paths.size()) {
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
    for (std::size_t index = 0; index < remove_paths.size(); ++index) {
        if (!valid_path(remove_paths[index])) return DraftMutationResult::InvalidPath;
        if (std::find(remove_paths.begin(),
                      remove_paths.begin() + static_cast<std::ptrdiff_t>(index),
                      remove_paths[index]) != remove_paths.begin() + static_cast<std::ptrdiff_t>(index)) {
            return DraftMutationResult::InvalidPath;
        }
        if (std::any_of(changes.begin(), changes.end(), [&](const DraftChange& change) {
                return change.path == remove_paths[index];
            })) {
            return DraftMutationResult::InvalidPath;
        }
    }
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    auto proposed = draft_.changes;
    for (const auto& path : remove_paths) {
        const auto found = std::find_if(proposed.begin(), proposed.end(),
                                        [&](const DraftChange& item) { return item.path == path; });
        if (found == proposed.end()) return DraftMutationResult::Missing;
    }
    std::erase_if(proposed, [&](const DraftChange& change) {
        return std::find(remove_paths.begin(), remove_paths.end(), change.path) != remove_paths.end();
    });
    for (auto& change : changes) {
        const auto found = std::find_if(proposed.begin(), proposed.end(),
                                        [&](const DraftChange& item) { return item.path == change.path; });
        if (found == proposed.end()) proposed.push_back(std::move(change));
        else found->value = std::move(change.value);
    }
    if (proposed.size() + draft_.structural_operations.size() > maximum_changes) {
        return DraftMutationResult::CapacityExceeded;
    }
    std::size_t proposed_size{};
    for (const auto& change : proposed) {
        if (!add_size(proposed_size, change.path.size())) {
            return DraftMutationResult::CapacityExceeded;
        }
        const auto size = value_size(change.value);
        if (!add_size(proposed_size, size)) {
            return DraftMutationResult::CapacityExceeded;
        }
    }
    for (const auto& item : draft_.structural_operations) {
        const auto size = structural_size(item);
        if (!size || !add_size(proposed_size, *size)) return DraftMutationResult::CapacityExceeded;
    }
    draft_.changes = std::move(proposed);
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::remove(const std::uint64_t expected_version, const std::string& path) {
    return remove_many(expected_version, {path});
}

DraftMutationResult DraftStore::remove_many(
    const std::uint64_t expected_version, std::vector<std::string> paths) {
    if (paths.empty() || paths.size() > maximum_changes) return DraftMutationResult::InvalidPath;
    return reconcile(expected_version, {}, std::move(paths));
}

DraftMutationResult DraftStore::upsert_structural(
    const std::uint64_t expected_version, DraftStructuralOperation operation) {
    std::vector<DraftStructuralOperation> operations;
    operations.push_back(std::move(operation));
    return upsert_structural_many(expected_version, std::move(operations));
}

DraftMutationResult DraftStore::upsert_structural_many(
    const std::uint64_t expected_version, std::vector<DraftStructuralOperation> operations) {
    if (operations.empty() || operations.size() > maximum_changes) {
        return DraftMutationResult::InvalidValue;
    }
    if (!std::all_of(operations.begin(), operations.end(), [](const auto& operation) {
            return valid_draft_structural_operation(operation);
        })) {
        return DraftMutationResult::InvalidValue;
    }
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    auto proposed = draft_.structural_operations;
    for (auto& operation : operations) {
        const auto local_id = draft_structural_local_id(operation);
        const auto found = std::find_if(proposed.begin(), proposed.end(), [local_id](const auto& item) {
            return draft_structural_local_id(item) == local_id;
        });
        if (found == proposed.end()) proposed.push_back(std::move(operation));
        else *found = std::move(operation);
    }
    if (draft_.changes.size() + proposed.size() > maximum_changes) {
        return DraftMutationResult::CapacityExceeded;
    }
    if (!valid_structural_set(proposed)) return DraftMutationResult::InvalidValue;
    std::size_t proposed_size{};
    for (const auto& change : draft_.changes) {
        if (!add_size(proposed_size, change.path.size()) ||
            !add_size(proposed_size, value_size(change.value))) {
            return DraftMutationResult::CapacityExceeded;
        }
    }
    for (const auto& item : proposed) {
        const auto size = structural_size(item);
        if (!size || !add_size(proposed_size, *size)) return DraftMutationResult::CapacityExceeded;
    }
    draft_.structural_operations = std::move(proposed);
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::remove_structural(
    const std::uint64_t expected_version, const std::string& local_id) {
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    const auto found = std::find_if(
        draft_.structural_operations.begin(), draft_.structural_operations.end(),
        [&local_id](const auto& item) { return draft_structural_local_id(item) == local_id; });
    if (found == draft_.structural_operations.end()) return DraftMutationResult::Missing;
    const auto linked_signature_parent = [&]() -> std::optional<std::string> {
        const auto* create = std::get_if<DraftCreateOperation>(&*found);
        if (create == nullptr) return std::nullopt;
        if (create->collection == "starttls_signatures" ||
            create->collection == "detection_signatures") {
            return create->client_id;
        }
        if (create->collection != "starttls_signatures.flow" &&
            create->collection != "detection_signatures.flow") {
            return std::nullopt;
        }
        const auto parent = std::find_if(
            draft_.structural_operations.begin(), draft_.structural_operations.end(),
            [&](const auto& candidate) {
                const auto* parent_create = std::get_if<DraftCreateOperation>(&candidate);
                return parent_create != nullptr &&
                       (parent_create->collection == "starttls_signatures" ||
                        parent_create->collection == "detection_signatures") &&
                       parent_create->client_id == create->parent_id;
            });
        if (parent == draft_.structural_operations.end()) return std::nullopt;
        return std::get<DraftCreateOperation>(*parent).client_id;
    }();
    const auto removed_by_request = [&](const DraftStructuralOperation& candidate) {
        if (!linked_signature_parent) {
            return draft_structural_local_id(candidate) == local_id;
        }
        const auto* create = std::get_if<DraftCreateOperation>(&candidate);
        return create != nullptr &&
               (create->client_id == *linked_signature_parent ||
                create->parent_id == linked_signature_parent);
    };
    std::vector<std::string> removed_references;
    for (const auto& candidate : draft_.structural_operations) {
        if (!removed_by_request(candidate)) continue;
        const auto* create = std::get_if<DraftCreateOperation>(&candidate);
        if (create != nullptr) removed_references.push_back("client:" + create->client_id);
    }
    const auto has_ordered_dependent = std::any_of(
        draft_.structural_operations.begin(), draft_.structural_operations.end(),
        [&](const auto& candidate) {
            if (removed_by_request(candidate)) return false;
            const auto reference = std::visit([](const auto& item) -> std::optional<std::string> {
                using Operation = std::decay_t<decltype(item)>;
                if constexpr (std::is_same_v<Operation, DraftCreateOperation> ||
                              std::is_same_v<Operation, DraftMoveOperation>) {
                    return item.position.reference;
                }
                return std::nullopt;
            }, candidate);
            return reference && std::find(
                removed_references.begin(), removed_references.end(), *reference) != removed_references.end();
        });
    if (has_ordered_dependent) return DraftMutationResult::InvalidValue;
    const auto has_semantic_dependent = std::any_of(
        draft_.structural_operations.begin(), draft_.structural_operations.end(),
        [&](const auto& removed_candidate) {
            if (!removed_by_request(removed_candidate)) return false;
            const auto* removed_create = std::get_if<DraftCreateOperation>(&removed_candidate);
            if (removed_create == nullptr) return false;
            const auto name = removed_create->fields.find("name");
            if (name == removed_create->fields.end()) return false;
            const auto* target_name = std::get_if<std::string>(&name->second);
            if (target_name == nullptr) return false;
            const auto structural_reference = std::any_of(
                draft_.structural_operations.begin(), draft_.structural_operations.end(),
                [&](const auto& consumer_candidate) {
                    if (removed_by_request(consumer_candidate)) return false;
                    const auto* consumer = std::get_if<DraftCreateOperation>(&consumer_candidate);
                    if (consumer == nullptr) return false;
                    return std::any_of(consumer->fields.begin(), consumer->fields.end(),
                        [&](const auto& field) {
                            return field_references_created_entity(
                                removed_create->collection, *target_name,
                                consumer->collection, field.first, field.second);
                        });
                });
            if (structural_reference) return true;
            return std::any_of(draft_.changes.begin(), draft_.changes.end(), [&](const DraftChange& change) {
                const auto collection_end = change.path.find(".[");
                const auto field_start = change.path.rfind("].");
                if (collection_end == std::string::npos || field_start == std::string::npos ||
                    field_start <= collection_end + 1U) {
                    return false;
                }
                return field_references_created_entity(
                    removed_create->collection, *target_name,
                    std::string_view(change.path).substr(0U, collection_end),
                    std::string_view(change.path).substr(field_start + 2U), change.value);
            });
        });
    if (has_semantic_dependent) return DraftMutationResult::InvalidValue;
    if (linked_signature_parent) {
        std::erase_if(draft_.structural_operations, removed_by_request);
        ++draft_.version;
        return DraftMutationResult::Applied;
    }
    draft_.structural_operations.erase(found);
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::clear(const std::uint64_t expected_version) {
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    draft_.changes.clear();
    draft_.structural_operations.clear();
    ++draft_.version;
    return DraftMutationResult::Applied;
}

DraftMutationResult DraftStore::complete_commit(
    const std::uint64_t expected_version, const std::string& committed_revision) {
    if (!is_canonical_revision(committed_revision)) return DraftMutationResult::InvalidValue;
    std::scoped_lock lock(mutex_);
    if (expected_version != draft_.version) return DraftMutationResult::VersionConflict;
    if (draft_.empty()) return DraftMutationResult::Missing;
    if (!draft_.base_revision || !is_canonical_revision(*draft_.base_revision) ||
        *draft_.base_revision == committed_revision) {
        return DraftMutationResult::InvalidValue;
    }
    draft_.changes.clear();
    draft_.structural_operations.clear();
    draft_.base_revision = committed_revision;
    minimum_revision_observation_ = std::chrono::steady_clock::now();
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
        } else if constexpr (std::is_same_v<Value, DraftAuthIdentities>) {
            if (item.empty() || item.size() > maximum_array_items) return false;
            const auto valid_text = [](const std::string& text) {
                return text.size() <= maximum_string_length &&
                       std::none_of(text.begin(), text.end(), [](const unsigned char character) {
                           return character == 0U;
                       });
            };
            return std::all_of(item.begin(), item.end(), [&](const DraftAuthIdentity& identity) {
                return !identity.name.empty() && valid_text(identity.name) &&
                       valid_text(identity.detection_profile) &&
                       valid_text(identity.content_profile) && valid_text(identity.tls_profile) &&
                       valid_text(identity.alg_dns_profile);
            });
        } else if constexpr (std::is_same_v<Value, double>) {
            return std::isfinite(item);
        } else {
            return true;
        }
    }, value);
}

void to_json(nlohmann::json& output, const DraftAuthIdentity& identity) {
    output = {{"name", identity.name}};
    if (!identity.detection_profile.empty()) {
        output["detection_profile"] = identity.detection_profile;
    }
    if (!identity.content_profile.empty()) output["content_profile"] = identity.content_profile;
    if (!identity.tls_profile.empty()) output["tls_profile"] = identity.tls_profile;
    if (!identity.alg_dns_profile.empty()) output["alg_dns_profile"] = identity.alg_dns_profile;
}

} // namespace smithproxy::gui
