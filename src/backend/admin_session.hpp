#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace smithproxy::gui {

// Owns authenticated standalone GUI sessions. Sessions are intentionally
// process-local; a service restart requires authentication against persistent
// administrator verifiers again.
class AdminSessionStore {
public:
    struct IssuedSession {
        std::string token;
        std::int64_t expires_at_unix_seconds{};
    };

    static constexpr std::int64_t ttl_seconds = 8 * 60 * 60;
    static constexpr std::size_t capacity = 256U;

    [[nodiscard]] std::optional<IssuedSession> issue(
        std::string administrator,
        std::int64_t now = unix_seconds());
    [[nodiscard]] std::optional<std::string> authenticate(
        std::string_view token,
        std::int64_t now = unix_seconds());
    void revoke(std::string_view token);
    void clear();
    [[nodiscard]] std::size_t size(std::int64_t now = unix_seconds());

private:
    struct Session {
        std::string administrator;
        std::int64_t expires_at_unix_seconds{};
    };

    static std::int64_t unix_seconds();
    void prune_locked(std::int64_t now);

    std::mutex mutex_;
    std::map<std::string, Session, std::less<>> sessions_;
};

} // namespace smithproxy::gui
