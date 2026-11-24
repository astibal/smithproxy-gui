#include "password.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <array>
#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace smithproxy::gui {
namespace {

constexpr std::size_t salt_size = 16U;
constexpr std::size_t verifier_size = 32U;
constexpr std::uint64_t default_cost = 32768U;
constexpr std::uint32_t default_block_size = 8U;
constexpr std::uint32_t default_parallelism = 1U;
constexpr std::uint64_t maximum_memory = 64U * 1024U * 1024U;

std::string hexadecimal(const std::span<const unsigned char> bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string encoded(bytes.size() * 2U, '0');
    for(std::size_t index = 0U; index < bytes.size(); ++index) {
        encoded[index * 2U] = digits[bytes[index] >> 4U];
        encoded[index * 2U + 1U] = digits[bytes[index] & 0x0fU];
    }
    return encoded;
}

std::optional<std::vector<unsigned char>> decode_hexadecimal(
    const std::string_view value, const std::size_t expected_size) {
    if(value.size() != expected_size * 2U) return std::nullopt;
    std::vector<unsigned char> decoded(expected_size);
    const auto nibble = [](const char character) -> std::optional<unsigned char> {
        if(character >= '0' && character <= '9')
            return static_cast<unsigned char>(character - '0');
        if(character >= 'a' && character <= 'f')
            return static_cast<unsigned char>(character - 'a' + 10);
        return std::nullopt;
    };
    for(std::size_t index = 0U; index < expected_size; ++index) {
        const auto high = nibble(value[index * 2U]);
        const auto low = nibble(value[index * 2U + 1U]);
        if(!high || !low) return std::nullopt;
        decoded[index] = static_cast<unsigned char>((*high << 4U) | *low);
    }
    return decoded;
}

bool valid_parameters(const GuiAdministratorConfig& administrator) {
    const bool power_of_two = administrator.cost >= 16384U &&
        (administrator.cost & (administrator.cost - 1U)) == 0U;
    return power_of_two && administrator.cost <= 1048576U &&
           administrator.block_size >= 8U && administrator.block_size <= 32U &&
           administrator.parallelism >= 1U && administrator.parallelism <= 16U;
}

std::optional<std::array<unsigned char, verifier_size>> derive(
    const GuiAdministratorConfig& administrator, const std::string_view password) {
    if(!valid_parameters(administrator) || password.size() < 14U || password.size() > 1024U)
        return std::nullopt;
    const auto salt = decode_hexadecimal(administrator.salt, salt_size);
    if(!salt) return std::nullopt;
    std::array<unsigned char, verifier_size> result{};
    const int status = EVP_PBE_scrypt(
        password.data(), password.size(), salt->data(), salt->size(),
        administrator.cost, administrator.block_size, administrator.parallelism,
        maximum_memory, result.data(), result.size());
    if(status != 1) return std::nullopt;
    return result;
}

} // namespace

std::optional<GuiAdministratorConfig> create_password_verifier(
    std::string administrator, const std::string_view password) {
    const bool valid_name = !administrator.empty() && administrator.size() <= 64U &&
        std::all_of(administrator.begin(), administrator.end(), [](const unsigned char character) {
            return (character >= 'a' && character <= 'z') ||
                   (character >= 'A' && character <= 'Z') ||
                   (character >= '0' && character <= '9') || character == '.' ||
                   character == '_' || character == '-' || character == '@';
        });
    if(!valid_name || password.size() < 14U ||
       password.size() > 1024U) return std::nullopt;
    GuiAdministratorConfig result{
        .name = std::move(administrator),
        .salt = {},
        .verifier = {},
        .cost = default_cost,
        .block_size = default_block_size,
        .parallelism = default_parallelism,
    };
    std::array<unsigned char, salt_size> salt{};
    if(RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) return std::nullopt;
    result.salt = hexadecimal(salt);
    const auto verifier = derive(result, password);
    if(!verifier) return std::nullopt;
    result.verifier = hexadecimal(*verifier);
    return result;
}

bool verify_password(
    const GuiAdministratorConfig& administrator, const std::string_view password) {
    const auto expected = decode_hexadecimal(administrator.verifier, verifier_size);
    const auto actual = derive(administrator, password);
    if(!expected || !actual) return false;
    return CRYPTO_memcmp(expected->data(), actual->data(), verifier_size) == 0;
}

} // namespace smithproxy::gui
