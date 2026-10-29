#include "config_snapshot.hpp"
#include "draft_schema.hpp"
#include "draft_store.hpp"
#include "live_sessions.hpp"
#include "neighbor_metrics.hpp"
#include "runtime_metrics.hpp"
#include "tls_metrics.hpp"
#include "transaction_capabilities.hpp"
#include "transaction_envelope.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

using namespace smithproxy::gui;

namespace {

class DeterministicRandom {
public:
    std::uint64_t next() {
        state_ ^= state_ >> 12U;
        state_ ^= state_ << 25U;
        state_ ^= state_ >> 27U;
        return state_ * 0x2545f4914f6cdd1dULL;
    }

    std::size_t bounded(const std::size_t maximum) {
        return maximum == 0U ? 0U : static_cast<std::size_t>(next() % maximum);
    }

private:
    std::uint64_t state_{0x5f3759df0ddc0ffeULL};
};

std::string random_bytes(DeterministicRandom& random, const std::size_t maximum) {
    std::string value(random.bounded(maximum + 1U), '\0');
    for (char& character : value) character = static_cast<char>(random.next() & 0xffU);
    return value;
}

std::string mutate(DeterministicRandom& random, std::string value) {
    const auto operations = 1U + random.bounded(8U);
    for (std::size_t operation = 0U; operation < operations; ++operation) {
        const auto choice = random.bounded(3U);
        const auto offset = random.bounded(value.size() + 1U);
        if (choice == 0U && !value.empty()) {
            value.erase(random.bounded(value.size()), 1U);
        } else if (choice == 1U && value.size() < 4096U) {
            value.insert(offset, 1U, static_cast<char>(random.next() & 0xffU));
        } else if (!value.empty()) {
            value[random.bounded(value.size())] = static_cast<char>(random.next() & 0xffU);
        }
    }
    return value;
}

DraftScalar random_scalar(DeterministicRandom& random) {
    switch (random.bounded(6U)) {
        case 0U:
            return (random.next() & 1U) != 0U;
        case 1U:
            return static_cast<std::int64_t>(random.next());
        case 2U:
            return std::bit_cast<double>(random.next());
        case 3U:
            return random_bytes(random, 2048U);
        case 4U: {
            std::vector<std::string> values;
            const auto count = random.bounded(280U);
            values.reserve(count);
            for (std::size_t index = 0U; index < count; ++index) {
                values.push_back(random_bytes(random, 160U));
            }
            return values;
        }
        default: {
            std::vector<std::int64_t> values;
            const auto count = random.bounded(280U);
            values.reserve(count);
            for (std::size_t index = 0U; index < count; ++index) {
                values.push_back(static_cast<std::int64_t>(random.next()));
            }
            return values;
        }
    }
}

void exercise_json_parsers(const std::string_view payload) {
    constexpr std::string_view revision{
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"};
    static_cast<void>(parse_listener_metrics(payload));
    static_cast<void>(parse_tls_cache_metrics(payload));
    static_cast<void>(parse_neighbor_metrics(payload));
    static_cast<void>(parse_live_sessions(payload));
    static_cast<void>(parse_config_snapshot(payload, payload, payload, payload));
    static_cast<void>(parse_config_profiles(payload, "tls_profiles", "tls"));
    static_cast<void>(parse_config_settings(payload));
    static_cast<void>(parse_config_debug(payload));
    static_cast<void>(parse_config_captures(payload));
    static_cast<void>(parse_config_security_assets(payload, payload, payload));
    static_cast<void>(parse_transaction_capabilities(payload, reviewed_transaction_schemas()));
    static_cast<void>(parse_transaction_response(
        200L, payload, TransactionMode::Validate, revision, 0U));
    static_cast<void>(parse_transaction_response(
        409L, payload, TransactionMode::Commit, revision, 1U));
}

void require(const bool condition, const std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

} // namespace

int main() {
    try {
        DeterministicRandom random;
        constexpr std::array<std::string_view, 8U> json_seeds{
            "{}",
            R"({"success":{}})",
            R"({"success":{"listeners":[]}})",
            R"({"success":{"policy":[]}})",
            R"({"success":{"settings":{}}})",
            R"({"success":{"tls_profiles":{}}})",
            R"({"success":{"sessions":[]}})",
            R"({"success":{"neighbors":[]}})",
        };
        for (std::size_t iteration = 0U; iteration < 5000U; ++iteration) {
            const auto payload = iteration % 2U == 0U
                ? random_bytes(random, 2048U)
                : mutate(random, std::string(json_seeds[random.bounded(json_seeds.size())]));
            exercise_json_parsers(payload);
        }

        constexpr std::array<std::string_view, 12U> path_seeds{
            "policy.[0].action",
            "policy.[4095].disabled",
            "address_objects.[0].value",
            "tls_profiles.[3].client_hello_timeout",
            "content_profiles.[2].content_rules.[4].match",
            "detection_signatures.[8].flow.[2].signature",
            "settings.accept_api",
            "settings.http_api.allowed_ips",
            "debug.log.tls",
            "captures.remote.tun_ttl",
            "tls_ca.[0].path",
            "auth_profiles.[0].resolve",
        };
        DraftStore store{"robustness"};
        for (std::size_t iteration = 0U; iteration < 20000U; ++iteration) {
            const auto path = iteration % 2U == 0U
                ? random_bytes(random, 512U)
                : mutate(random, std::string(path_seeds[random.bounded(path_seeds.size())]));
            const DraftChange change{path, random_scalar(random)};
            const auto schema_result = validate_draft_schema(change);
            require(schema_result == DraftSchemaResult::Valid ||
                        schema_result == DraftSchemaResult::UnknownPath ||
                        schema_result == DraftSchemaResult::InvalidValue,
                    "draft schema returned an unknown result");

            const auto before = store.snapshot();
            const auto result = store.upsert(before.version, change);
            const auto after = store.snapshot();
            if (result == DraftMutationResult::Applied) {
                require(after.version == before.version + 1U,
                        "accepted draft mutation did not increment the version");
            } else {
                require(after.version == before.version,
                        "rejected draft mutation changed the version");
                require(after.changes.size() == before.changes.size(),
                        "rejected draft mutation changed the stored path count");
            }
        }
    } catch (const std::exception& error) {
        std::cerr << "Robustness corpus raised an exception: " << error.what() << '\n';
        return 1;
    } catch (...) {
        std::cerr << "Robustness corpus raised a non-standard exception\n";
        return 1;
    }
    return 0;
}
