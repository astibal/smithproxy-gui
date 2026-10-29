# Dependency policy

Smithproxy GUI keeps every direct dependency at an exact version and commits the
pnpm lockfile. CI installs only that lockfile and rejects production advisories
at high or critical severity.

The license gate inventories the complete installed frontend toolchain and
accepts only these SPDX identifiers:

- Apache-2.0
- BSD-3-Clause
- ISC
- MIT
- MPL-2.0

MPL-2.0 is accepted for unmodified build and test tooling and does not change the
license of Smithproxy GUI sources. A new or ambiguous identifier fails CI and
requires an explicit policy review; the gate never silently treats an unknown
license as permissive.

Every CI run emits a deterministic CycloneDX 1.5 JSON frontend inventory as the
`dependency-sbom` artifact. It excludes local installation paths and uses a
content-derived serial number, so identical installed dependency inputs produce
identical output.

The CMake configure step also emits `backend-sbom.cdx.json`. It records the full
lmhpp Git revision plus the libcurl, libmicrohttpd, and nlohmann-json versions
detected for that exact build, with their reviewed SPDX licenses. CI validates
the inventory and publishes it as the separate `backend-sbom` artifact. System
packages remain controlled by the build environment rather than the pnpm
lockfile; the backend inventory records their resolved versions instead of
claiming that they are source-pinned.
