#!/usr/bin/env python3
"""Exercise the real HTTP upgrade and byte bridge against a local fake libcli2 broker."""

import base64
import hashlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_ready(port, process):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"GUI exited early: {process.stderr.read()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2) as client:
                client.sendall(b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                if b"200 OK" in client.recv(4096):
                    return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("GUI did not become ready")


def handshake(port, *, origin=True, protocol="smithproxy-cli-v1", gateway=True):
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    key = base64.b64encode(b"integration-key!").decode()
    headers = [
        "GET /api/v1/console HTTP/1.1",
        f"Host: 127.0.0.1:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {key}",
        f"Sec-WebSocket-Protocol: {protocol}",
        "Sec-Fetch-Site: same-origin",
    ]
    if origin:
        headers.append(f"Origin: http://127.0.0.1:{port}")
    if gateway:
        headers.append("X-Smithproxy-GUI-Gateway: 0123456789abcdef0123456789abcdef")
    client.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
    response = b""
    while b"\r\n\r\n" not in response:
        response += client.recv(4096)
    head, extra = response.split(b"\r\n\r\n", 1)
    return client, key, head, extra


def masked_frame(payload, opcode=2):
    mask = b"\x12\x34\x56\x78"
    assert len(payload) <= 125
    encoded = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return bytes((0x80 | opcode, 0x80 | len(payload))) + mask + encoded


def read_server_frame(client, initial=b""):
    data = bytearray(initial)
    while len(data) < 2:
        data.extend(client.recv(4096))
    length = data[1] & 0x7F
    offset = 2
    if length == 126:
        while len(data) < 4:
            data.extend(client.recv(4096))
        length = struct.unpack("!H", data[2:4])[0]
        offset = 4
    while len(data) < offset + length:
        data.extend(client.recv(4096))
    return data[0] & 0x0F, bytes(data[offset:offset + length])


def main():
    executable, assets = sys.argv[1:3]
    gui_port = free_port()
    broker_port = free_port()
    broker_received = []
    broker_ready = threading.Event()

    def broker():
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", broker_port))
            listener.listen(2)
            broker_ready.set()
            for _ in range(2):
                connection, _ = listener.accept()
                with connection:
                    connection.sendall(b"Username: ")
                    broker_received.append(connection.recv(4096))
                    connection.sendall(b"Password: ")
                    # Keep the broker side alive until the browser closes the
                    # session or the GUI shuts down its active bridge.
                    while connection.recv(4096):
                        pass

    worker = threading.Thread(target=broker, daemon=True)
    worker.start()
    broker_ready.wait(2)
    environment = os.environ.copy()
    for name in ("SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT",
                 "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS"):
        environment.pop(name, None)
    environment["SMITHPROXY_CLI"] = f"127.0.0.1:{broker_port}"
    environment["SMITHPROXY_GUI_GATEWAY_SECRET"] = "0123456789abcdef0123456789abcdef"
    process = subprocess.Popen(
        [executable, "--port", str(gui_port), "--assets", assets],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment)
    try:
        wait_ready(gui_port, process)

        rejected, _, rejected_head, _ = handshake(gui_port, gateway=False)
        assert b"401 Unauthorized" in rejected_head
        rejected.close()
        rejected, _, rejected_head, _ = handshake(gui_port, origin=False)
        assert b"401 Unauthorized" in rejected_head
        rejected.close()
        rejected, _, rejected_head, _ = handshake(gui_port, protocol="wrong")
        assert b"400 Bad Request" in rejected_head
        rejected.close()

        client, key, head, extra = handshake(gui_port)
        expected = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert b"101 Switching Protocols" in head
        assert b"Sec-WebSocket-Protocol: smithproxy-cli-v1" in head
        assert b"Sec-WebSocket-Accept: " + expected in head
        opcode, payload = read_server_frame(client, extra)
        assert opcode == 2 and payload == b"Username: "
        client.sendall(masked_frame(b"admin\n"))
        opcode, payload = read_server_frame(client)
        assert opcode == 2 and payload == b"Password: "
        client.sendall(masked_frame(b"", opcode=8))
        client.close()

        # An upgraded request may still be active when the HTTP server receives
        # SIGTERM. The bridge must observe shutdown without retaining a pointer
        # to caller-owned state or delaying process termination.
        active, _, active_head, active_extra = handshake(gui_port)
        assert b"101 Switching Protocols" in active_head
        opcode, payload = read_server_frame(active, active_extra)
        assert opcode == 2 and payload == b"Username: "
        active.sendall(masked_frame(b"operator\n"))
        opcode, payload = read_server_frame(active)
        assert opcode == 2 and payload == b"Password: "
        process.terminate()
        process.wait(timeout=5)
        active.close()
        worker.join(2)
        assert broker_received == [b"admin\n", b"operator\n"]
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    main()
