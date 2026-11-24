#include "admin_session.hpp"

#include <sys/random.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <limits>

namespace smithproxy::gui {
namespace {

std::optional<std::string> random_token() {
    std::array<unsigned char, 32U> bytes{};
    std::size_t offset = 0U;
    while(offset < bytes.size()) {
        const auto count = ::getrandom(bytes.data() + offset, bytes.size() - offset, 0);
        const bool interrupted = count < 0 && errno == EINTR;
        if(interrupted) continue;
        if(count <= 0) return std::nullopt;
        offset += static_cast<std::size_t>(count);
    }
    constexpr char digits[] = "0123456789abcdef";
    std::string token(bytes.size() * 2U, '0');
    for(std::size_t index = 0; index < bytes.size(); ++index) {
        token[index * 2U] = digits[bytes[index] >> 4U];
        token[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    return token;
}

bool valid_token(const std::string_view token) {
    return token.size() == 64U &&
        std::all_of(token.begin(), token.end(), [](const unsigned char value) {
            return std::isdigit(value) || (value >= 'a' && value <= 'f');
        });
}

} // namespace

std::optional<AdminSessionStore::IssuedSession> AdminSessionStore::issue(
    std::string administrator,
    std::string upstream_auth_token,
    std::string upstream_csrf_token,
    const std::int64_t now) {
    if(administrator.empty() || administrator.size() > 64U ||
       upstream_auth_token.empty() || upstream_csrf_token.empty() ||
       now > std::numeric_limits<std::int64_t>::max() - ttl_seconds)
        return std::nullopt;
    auto token = random_token();
    if(!token) return std::nullopt;
    const auto expires_at = now + ttl_seconds;
    auto lock = std::scoped_lock(mutex_);
    prune_locked(now);
    if(sessions_.size() >= capacity) return std::nullopt;
    const bool inserted = sessions_.emplace(
        *token, Session{
            std::move(administrator),
            std::move(upstream_auth_token),
            std::move(upstream_csrf_token),
            expires_at,
        }).second;
    if(!inserted) return std::nullopt;
    return IssuedSession{std::move(*token), expires_at};
}

std::optional<AdminSessionStore::AuthenticatedSession> AdminSessionStore::authenticate(
    const std::string_view token, const std::int64_t now) {
    if(!valid_token(token)) return std::nullopt;
    auto lock = std::scoped_lock(mutex_);
    const auto found = sessions_.find(token);
    if(found == sessions_.end()) return std::nullopt;
    if(found->second.expires_at_unix_seconds <= now) {
        sessions_.erase(found);
        return std::nullopt;
    }
    return AuthenticatedSession{
        .administrator = found->second.administrator,
        .upstream_auth_token = found->second.upstream_auth_token,
        .upstream_csrf_token = found->second.upstream_csrf_token,
    };
}

void AdminSessionStore::revoke(const std::string_view token) {
    if(!valid_token(token)) return;
    auto lock = std::scoped_lock(mutex_);
    const auto found = sessions_.find(token);
    if(found != sessions_.end()) sessions_.erase(found);
}

void AdminSessionStore::revoke_administrator(const std::string_view administrator) {
    if(administrator.empty()) return;
    auto lock = std::scoped_lock(mutex_);
    std::erase_if(sessions_, [&](const auto& entry) {
        return entry.second.administrator == administrator;
    });
}

void AdminSessionStore::clear() {
    auto lock = std::scoped_lock(mutex_);
    sessions_.clear();
}

std::size_t AdminSessionStore::size(const std::int64_t now) {
    auto lock = std::scoped_lock(mutex_);
    prune_locked(now);
    return sessions_.size();
}

std::int64_t AdminSessionStore::unix_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

void AdminSessionStore::prune_locked(const std::int64_t now) {
    for(auto iterator = sessions_.begin(); iterator != sessions_.end();) {
        if(iterator->second.expires_at_unix_seconds <= now)
            iterator = sessions_.erase(iterator);
        else
            ++iterator;
    }
}

} // namespace smithproxy::gui
