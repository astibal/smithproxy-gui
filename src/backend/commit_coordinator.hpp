#pragma once

#include "draft_store.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace smithproxy::gui {

enum class CommitPreparationResult {
    Ready,
    Busy,
    VersionConflict,
    Empty,
    InvalidDraft,
    EntropyUnavailable,
};

class CommitCoordinator {
public:
    class Lease {
    public:
        Lease() = default;
        ~Lease();

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) noexcept;

        [[nodiscard]] CommitPreparationResult result() const noexcept { return result_; }
        [[nodiscard]] explicit operator bool() const noexcept {
            return result_ == CommitPreparationResult::Ready;
        }
        [[nodiscard]] const DraftSnapshot& draft() const noexcept { return draft_; }
        [[nodiscard]] const std::string& idempotency_key() const noexcept {
            return idempotency_key_;
        }

        void release(bool retain_intent = true) noexcept;
        [[nodiscard]] DraftMutationResult complete_success(
            const std::string& committed_revision);

    private:
        friend class CommitCoordinator;
        Lease(CommitCoordinator* owner, CommitPreparationResult result,
              DraftSnapshot draft = {}, std::string idempotency_key = {});

        CommitCoordinator* owner_{};
        CommitPreparationResult result_{CommitPreparationResult::InvalidDraft};
        DraftSnapshot draft_;
        std::string idempotency_key_;
    };

    explicit CommitCoordinator(DraftStore& draft) : draft_(draft) {}

    [[nodiscard]] Lease begin(std::uint64_t expected_version);

    template <typename Mutation>
    DraftMutationResult mutate(Mutation&& mutation) {
        std::scoped_lock lock(mutex_);
        if (in_flight_) return DraftMutationResult::Busy;
        const auto result = std::invoke(std::forward<Mutation>(mutation));
        if (result == DraftMutationResult::Applied) intent_.reset();
        return result;
    }

    [[nodiscard]] bool busy() const;

private:
    struct Intent {
        std::uint64_t version{};
        std::string base_revision;
        std::string idempotency_key;
    };

    void release(bool retain_intent) noexcept;
    DraftMutationResult complete_success(
        std::uint64_t expected_version, const std::string& committed_revision);

    DraftStore& draft_;
    mutable std::mutex mutex_;
    std::optional<Intent> intent_;
    bool in_flight_{};
};

} // namespace smithproxy::gui
