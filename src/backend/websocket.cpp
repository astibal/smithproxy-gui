#include "websocket.hpp"

#include <openssl/evp.h>

#include <array>
#include <limits>

namespace smithproxy::gui {
namespace {

constexpr std::string_view websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

bool valid_opcode(const std::uint8_t value) {
    return value == static_cast<std::uint8_t>(WebSocketOpcode::Text) ||
           value == static_cast<std::uint8_t>(WebSocketOpcode::Binary) ||
           value == static_cast<std::uint8_t>(WebSocketOpcode::Close) ||
           value == static_cast<std::uint8_t>(WebSocketOpcode::Ping) ||
           value == static_cast<std::uint8_t>(WebSocketOpcode::Pong);
}

bool control_opcode(const std::uint8_t value) { return (value & 0x08U) != 0U; }

WebSocketDecodeResult protocol_error(std::string message) {
    return {WebSocketDecodeState::ProtocolError, {}, std::move(message)};
}

} // namespace

std::string websocket_accept(const std::string_view client_key) {
    // A browser sends a base64 encoding of exactly sixteen random bytes.
    if (client_key.size() != 24U || !client_key.ends_with("==")) return {};
    std::array<unsigned char, 18> decoded{};
    const auto decoded_size = EVP_DecodeBlock(
        decoded.data(), reinterpret_cast<const unsigned char*>(client_key.data()),
        static_cast<int>(client_key.size()));
    if (decoded_size != 18) return {};

    std::string source(client_key);
    source += websocket_guid;
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned digest_size{};
    if (EVP_Digest(source.data(), source.size(), digest.data(), &digest_size, EVP_sha1(), nullptr) != 1 ||
        digest_size != 20U) {
        return {};
    }
    std::array<unsigned char, 32> encoded{};
    const auto encoded_size = EVP_EncodeBlock(encoded.data(), digest.data(), static_cast<int>(digest_size));
    if (encoded_size != 28) return {};
    return {reinterpret_cast<const char*>(encoded.data()), static_cast<std::size_t>(encoded_size)};
}

WebSocketDecodeResult decode_websocket_client_frame(
    const std::string_view bytes, const std::size_t maximum_payload) {
    if (bytes.size() < 2U) return {};
    const auto first = static_cast<std::uint8_t>(bytes[0]);
    const auto second = static_cast<std::uint8_t>(bytes[1]);
    const bool final = (first & 0x80U) != 0U;
    const auto reserved = first & 0x70U;
    const auto opcode = static_cast<std::uint8_t>(first & 0x0fU);
    const bool masked = (second & 0x80U) != 0U;
    const auto length_marker = second & 0x7fU;
    if (!final) return protocol_error("fragmented frames are not supported");
    if (reserved != 0U) return protocol_error("WebSocket extensions are not enabled");
    if (!valid_opcode(opcode)) return protocol_error("unsupported WebSocket opcode");
    if (!masked) return protocol_error("browser frames must be masked");
    if (control_opcode(opcode) && length_marker > 125U) {
        return protocol_error("invalid control frame length");
    }

    std::size_t offset = 2U;
    std::uint64_t payload_size = length_marker;
    if (length_marker == 126U) {
        if (bytes.size() < offset + 2U) return {};
        payload_size = (static_cast<std::uint64_t>(static_cast<std::uint8_t>(bytes[offset])) << 8U) |
                       static_cast<std::uint8_t>(bytes[offset + 1U]);
        offset += 2U;
        if (payload_size < 126U) return protocol_error("non-canonical frame length");
    } else if (length_marker == 127U) {
        if (bytes.size() < offset + 8U) return {};
        payload_size = 0U;
        for (std::size_t index = 0; index < 8U; ++index) {
            payload_size = (payload_size << 8U) |
                           static_cast<std::uint8_t>(bytes[offset + index]);
        }
        offset += 8U;
        if (payload_size < 65536U || (payload_size & (std::uint64_t{1} << 63U)) != 0U) {
            return protocol_error("non-canonical frame length");
        }
    }
    if (payload_size > maximum_payload ||
        payload_size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        return protocol_error("WebSocket frame exceeds the configured limit");
    }
    constexpr std::size_t mask_size = 4U;
    if (bytes.size() < offset + mask_size) return {};
    const auto payload_offset = offset + mask_size;
    const auto native_size = static_cast<std::size_t>(payload_size);
    if (bytes.size() - payload_offset < native_size) return {};

    WebSocketFrame frame;
    frame.opcode = static_cast<WebSocketOpcode>(opcode);
    frame.payload.resize(native_size);
    for (std::size_t index = 0; index < native_size; ++index) {
        frame.payload[index] = static_cast<char>(
            static_cast<std::uint8_t>(bytes[payload_offset + index]) ^
            static_cast<std::uint8_t>(bytes[offset + (index % mask_size)]));
    }
    frame.consumed = payload_offset + native_size;
    return {WebSocketDecodeState::Frame, std::move(frame), {}};
}

std::string encode_websocket_server_frame(
    const WebSocketOpcode opcode, const std::string_view payload) {
    std::string frame;
    frame.reserve(payload.size() + 10U);
    frame.push_back(static_cast<char>(0x80U | static_cast<std::uint8_t>(opcode)));
    if (payload.size() <= 125U) {
        frame.push_back(static_cast<char>(payload.size()));
    } else if (payload.size() <= 65535U) {
        frame.push_back(static_cast<char>(126U));
        frame.push_back(static_cast<char>((payload.size() >> 8U) & 0xffU));
        frame.push_back(static_cast<char>(payload.size() & 0xffU));
    } else {
        frame.push_back(static_cast<char>(127U));
        const auto length = static_cast<std::uint64_t>(payload.size());
        for (int shift = 56; shift >= 0; shift -= 8) {
            frame.push_back(static_cast<char>((length >> static_cast<unsigned>(shift)) & 0xffU));
        }
    }
    frame.append(payload);
    return frame;
}

} // namespace smithproxy::gui
