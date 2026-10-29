#include "commit_coordinator.hpp"

#include "revision.hpp"
#include "transaction_envelope.hpp"

namespace smithproxy::gui {

CommitCoordinator::Lease::Lease(
    CommitCoordinator* owner, const CommitPreparationResult result,
    DraftSnapshot draft, std::string idempotency_key)
    : owner_(owner), result_(result), draft_(std::move(draft)),
      idempotency_key_(std::move(idempotency_key)) {}

CommitCoordinator::Lease::~Lease() {
    release();
}

CommitCoordinator::Lease::Lease(Lease&& other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)), result_(other.result_),
      draft_(std::move(other.draft_)), idempotency_key_(std::move(other.idempotency_key_)) {}

CommitCoordinator::Lease& CommitCoordinator::Lease::operator=(Lease&& other) noexcept {
    if (this == &other) return *this;
    release();
    owner_ = std::exchange(other.owner_, nullptr);
    result_ = other.result_;
    draft_ = std::move(other.draft_);
    idempotency_key_ = std::move(other.idempotency_key_);
    return *this;
}

void CommitCoordinator::Lease::release(const bool retain_intent) noexcept {
    if (owner_ == nullptr) return;
    owner_->release(retain_intent);
    owner_ = nullptr;
}

DraftMutationResult CommitCoordinator::Lease::complete_success(
    const std::string& committed_revision) {
    if (owner_ == nullptr || result_ != CommitPreparationResult::Ready) {
        return DraftMutationResult::InvalidValue;
    }
    const auto result = owner_->complete_success(draft_.version, committed_revision);
    owner_ = nullptr;
    return result;
}

CommitCoordinator::Lease CommitCoordinator::begin(const std::uint64_t expected_version) {
    std::scoped_lock lock(mutex_);
    if (in_flight_) return {nullptr, CommitPreparationResult::Busy};
    auto draft = draft_.snapshot();
    if (draft.version != expected_version) {
        return {nullptr, CommitPreparationResult::VersionConflict};
    }
    if (draft.changes.empty()) return {nullptr, CommitPreparationResult::Empty};
    if (!draft.base_revision || !is_canonical_revision(*draft.base_revision)) {
        return {nullptr, CommitPreparationResult::InvalidDraft};
    }
    if (!intent_ || intent_->version != draft.version ||
        intent_->base_revision != *draft.base_revision) {
        const auto key = generate_transaction_idempotency_key();
        if (!key) return {nullptr, CommitPreparationResult::EntropyUnavailable};
        intent_ = Intent{draft.version, *draft.base_revision, *key};
    }
    in_flight_ = true;
    return {this, CommitPreparationResult::Ready, std::move(draft), intent_->idempotency_key};
}

bool CommitCoordinator::busy() const {
    std::scoped_lock lock(mutex_);
    return in_flight_;
}

void CommitCoordinator::release(const bool retain_intent) noexcept {
    std::scoped_lock lock(mutex_);
    if (!retain_intent) intent_.reset();
    in_flight_ = false;
}

DraftMutationResult CommitCoordinator::complete_success(
    const std::uint64_t expected_version, const std::string& committed_revision) {
    std::scoped_lock lock(mutex_);
    const auto result = draft_.complete_commit(expected_version, committed_revision);
    if (result == DraftMutationResult::Applied) intent_.reset();
    in_flight_ = false;
    return result;
}

} // namespace smithproxy::gui
