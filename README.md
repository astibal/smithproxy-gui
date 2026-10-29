# Smithproxy GUI

Modern administration and monitoring interface for Smithproxy.

The GUI communicates with Smithproxy exclusively through a versioned API. It
does not read configuration files or runtime data directly.

[Czech version](README_CZ.md)

## Approved principles

- responsive, accessible, and themeable UI;
- compatibility with the Saslik appearance contract v1;
- primary navigation on the left, a contextual top bar, and a bottom status bar;
- editors open from the right and cover 75–80% of the workspace;
- nested edits form an overlapping chain of editor cards;
- all related changes belong to one shared draft;
- server-side validation, impact preview, and atomic commits;
- full Smithproxy configuration coverage, including persistent and effective
  values and augments;
- first-class monitoring, security, and extensive automated testing.

## Documentation

The detailed design documents are currently maintained as internal Czech
documentation:

- [Architecture](docs/ARCHITECTURE.md)
- [UX and information architecture](docs/UX.md)
- [Configuration, drafts, and augments](docs/CONFIG_AND_AUGMENTS.md)
- [Machine-readable configuration coverage](docs/CONFIG_COVERAGE.json)
- [API contract](docs/API_CONTRACT.md)
- [Security](docs/SECURITY.md)
- [Testing strategy](docs/TESTING.md)
- [Change and review process](docs/CHANGE_PROCESS.md)

## Development

Every push and pull request runs the frontend unit suite and the complete
Chromium, Firefox, and WebKit end-to-end matrix, a production TypeScript build,
a production dependency audit, and the C++ unit/integration suite under
AddressSanitizer and UndefinedBehaviorSanitizer. Compiler warnings fail the
backend quality gate.

Node.js 22.12 or newer and pnpm 11.25 are required.

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
pnpm test:unit
pnpm test:e2e
```

The local end-to-end command defaults to Chromium for a fast development loop.
After installing all Playwright browsers, run the same matrix as CI with:

```sh
PLAYWRIGHT_ALL_BROWSERS=1 pnpm test:e2e
```

The backend requires C++23, CMake, pkg-config, libcurl, libmicrohttpd, and
nlohmann-json 3.11 or newer. Initialize the repository and build the production
frontend and backend with:

```sh
git submodule update --init
pnpm build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target smithproxy-gui
ctest --test-dir build --output-on-failure
./build/smithproxy-gui --help
```

The backend reads Smithproxy access exclusively from its process environment:

```text
SMITHPROXY_API_URL=https://127.0.0.1:55555
SMITHPROXY_API_KEY=...
SMITHPROXY_CA_CERT=/path/to/ca-cert.pem
SMITHPROXY_GUI_GATEWAY_SECRET=at-least-32-random-characters
SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS=optional-overlap-during-rotation
```

The variables must be provided together. The API key is never accepted through
command-line arguments, exposed to the browser, or written to logs. For a
deployment behind the Saslik gateway, use a base path such as
`--base-path /ws001/smithproxy-gui/`.

Runtime configuration reads are fail-closed. They are enabled only when
`SMITHPROXY_GUI_GATEWAY_SECRET` is configured and the trusted reverse proxy
overwrites `X-Smithproxy-GUI-Gateway` with that secret on authenticated
requests. The secret must never be exposed to browser code or forwarded from a
client-supplied header. Missing or invalid handoff authentication returns HTTP
401 and keeps `config_read` disabled in the capability response.

Non-loopback listeners require the same gateway secret at process startup.
When gateway mode is active, status snapshots, metrics, session aggregates,
neighborhood summaries, events, alerts, and drafts all reject requests that did
not pass the trusted proxy handoff. Only the bounded health and capability
surfaces remain available for orchestration and authentication discovery.
During rotation, the optional previous secret is accepted alongside the current
secret. It is rejected when the current secret is absent or identical and should
be removed after the ingress has switched to the new value.

The C++ backend can now retrieve a bounded, validated runtime configuration
snapshot through the authenticated Smithproxy API. Frontend activation remains
capability-gated until the trusted gateway handoff is configured. Configuration
writes remain disabled while the atomic upstream commit contract is being
completed. Policies, objects, system settings, profiles, certificate authorities,
and protocol signatures have typed draft editors. Sensitive paths, credentials,
filters, and matcher expressions use write-only controls. Control-plane health
and listener monitoring use the production C++ backend. A bounded five-minute
runtime history visualizes active sessions and aggregate throughput. Live session
monitoring is aggregated by transport inside the GUI core;
endpoint addresses, ports, session identifiers, and policy names are never sent
to the browser. TLS monitoring exposes cache size, capacity, and freshness only;
certificate subjects and domain names remain behind the GUI core boundary. The
Network neighborhood monitoring follows the same rule: only endpoint counts,
activity windows, observations, and traffic totals reach the browser; hostnames,
tags, labels, and individual timelines do not. Structured active alerts are
derived inside the GUI core from reachability,
rolling availability, collector freshness, and TLS cache capacity. They use a
bounded fixed vocabulary and never forward arbitrary upstream log text. The root
web component supports integration into Saslik Tools:

```html
<smithproxy-gui
  mode="embedded"
  base-path="/tools/smithproxy"
  api-base="/tools/smithproxy/api/v1">
</smithproxy-gui>
```

Configuration coverage and the remaining monitoring surfaces are delivered as
independently tested vertical slices.

The proposed atomic Smithproxy write contract is documented in
[`docs/SMITHPROXY_WRITE_API_PROPOSAL.md`](docs/SMITHPROXY_WRITE_API_PROPOSAL.md).
The GUI intentionally does not emulate a transaction by issuing multiple legacy
configuration writes.

The privacy-preserving interface-monitor contract required for future netlink
health monitoring is documented in
[`docs/SMITHPROXY_INTERFACE_API_PROPOSAL.md`](docs/SMITHPROXY_INTERFACE_API_PROPOSAL.md).
The GUI does not invoke or parse the privileged administrative CLI.

When served behind Saslik, the page loads the canonical `/saslik-theme.css` and
`/saslik-theme.js` assets with the `smithproxy-gui` application scope. Standalone
deployments retain the built-in Petroleum fallback when those shared assets are
not available.
