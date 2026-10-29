#!/usr/bin/env python3

import json
import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    require(len(sys.argv) == 8, "expected SBOM path, five versions, and source path")
    sbom_path = Path(sys.argv[1])
    project_version, lmhpp_revision, curl_version, microhttpd_version, json_version = sys.argv[2:7]
    source_path = sys.argv[7]

    raw = sbom_path.read_text(encoding="utf-8")
    payload = json.loads(raw)

    require(payload.get("bomFormat") == "CycloneDX", "unexpected SBOM format")
    require(payload.get("specVersion") == "1.5", "unexpected CycloneDX version")
    require(payload.get("version") == 1, "unexpected SBOM document version")
    application = payload.get("metadata", {}).get("component", {})
    require(application.get("version") == project_version,
            "application version is inaccurate")
    require(application.get("bom-ref") == f"smithproxy-gui:{project_version}",
            "application reference is inaccurate")
    require(re.fullmatch(r"[0-9a-f]{40}", lmhpp_revision) is not None,
            "lmhpp revision must be a full Git commit")

    expected = {
        "lmhpp": (lmhpp_revision, "BSD-3-Clause", "pkg:github/astibal/lmhpp"),
        "libcurl": (curl_version, "curl", "pkg:generic/libcurl"),
        "libmicrohttpd": (microhttpd_version, "LGPL-2.1-or-later",
                           "pkg:generic/libmicrohttpd"),
        "nlohmann-json": (json_version, "MIT", "pkg:generic/nlohmann-json"),
    }
    components = payload.get("components")
    require(isinstance(components, list), "components must be an array")
    require(len(components) == len(expected), "backend dependency inventory changed unexpectedly")

    by_name = {component.get("name"): component for component in components}
    require(set(by_name) == set(expected), "backend dependency names do not match policy")
    for name, (version, license_id, purl_base) in expected.items():
        component = by_name[name]
        require(component.get("type") == "library", f"{name} has an unexpected type")
        require(component.get("version") == version, f"{name} version is inaccurate")
        require(component.get("bom-ref") == f"{name}:{version}",
                f"{name} reference is inaccurate")
        require(component.get("purl") == f"{purl_base}@{version}",
                f"{name} package URL is inaccurate")
        licenses = component.get("licenses")
        require(licenses == [{"license": {"id": license_id}}],
                f"{name} license does not match policy")

    require(source_path not in raw, "SBOM leaks the source checkout path")
    require("/home/" not in raw, "SBOM contains a local home path")


if __name__ == "__main__":
    main()
