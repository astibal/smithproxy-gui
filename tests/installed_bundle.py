#!/usr/bin/env python3

import http.client
import os
import pathlib
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def request(port: int, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    connection.request("GET", path)
    response = connection.getresponse()
    body = response.read()
    status = response.status
    connection.close()
    return status, body


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit("usage: installed_bundle.py CMAKE BUILD_DIR BINARY_REL ASSET_REL")
    cmake, build_dir, binary_relative, asset_relative = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="smithproxy-gui-install-") as directory:
        prefix = pathlib.Path(directory)
        subprocess.run(
            [cmake, "--install", build_dir, "--prefix", str(prefix)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        binary = prefix / binary_relative
        assets = prefix / asset_relative
        if not binary.is_file() or not (assets / "index.html").is_file():
            raise AssertionError("installed bundle is incomplete")

        environment = os.environ.copy()
        for key in (
            "SMITHPROXY_API_URL", "SMITHPROXY_API_KEY", "SMITHPROXY_CA_CERT",
            "SMITHPROXY_GUI_GATEWAY_SECRET", "SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS",
        ):
            environment.pop(key, None)
        port = free_port()
        process = subprocess.Popen(
            [str(binary), "--port", str(port), "--bind", "127.0.0.1",
             "--base-path", "/ws001/smithproxy-gui/"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(80):
                try:
                    if request(port, "/healthz")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("installed server did not become ready")

            status, entrypoint = request(port, "/ws001/smithproxy-gui/")
            if status != 200:
                raise AssertionError(f"installed entry point returned HTTP {status}")
            asset = re.search(rb'(?:src|href)="\./(assets/[^"]+)"', entrypoint)
            if asset is None:
                raise AssertionError("installed entry point has no fingerprinted asset")
            asset_path = "/ws001/smithproxy-gui/" + asset.group(1).decode("ascii")
            if request(port, asset_path)[0] != 200:
                raise AssertionError("installed frontend asset is unavailable")
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if process.returncode != 0:
            raise AssertionError(process.stderr.read())


if __name__ == "__main__":
    main()
