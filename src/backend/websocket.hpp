#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace smithproxy::gui {

// WebSocket operations accepted by the terminal bridge. Continuation frames
// are intentionally excluded because terminal input never needs fragmentation.
enum class WebSocketOpcode : std::uint8_t {
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xa,
};

enum class WebSocketDecodeState {
    Incomplete,
    Frame,
    ProtocolError,
};

struct WebSocketFrame {
    WebSocketOpcode opcode{WebSocketOpcode::Binary};
    std::string payload;
    std::size_t consumed{};
};

struct WebSocketDecodeResult {
    WebSocketDecodeState state{WebSocketDecodeState::Incomplete};
    WebSocketFrame frame;
    std::string error;
};

// Build the RFC 6455 handshake value returned for a syntactically valid key.
// Invalid or non-canonical browser keys are rejected before protocol upgrade.
std::string websocket_accept(std::string_view client_key);

// Decode one complete, masked browser frame without retaining caller-owned data.
// Oversized, fragmented and extension-dependent frames are rejected explicitly.
WebSocketDecodeResult decode_websocket_client_frame(
    std::string_view bytes, std::size_t maximum_payload);

// Encode one unmasked server frame suitable for writing to the upgraded socket.
std::string encode_websocket_server_frame(WebSocketOpcode opcode, std::string_view payload);

} // namespace smithproxy::gui
