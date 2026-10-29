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
- [Machine-readable implemented API surface](docs/API_SURFACE.json)
- [Security](docs/SECURITY.md)
- [Testing strategy](docs/TESTING.md)
- [Change and review process](docs/CHANGE_PROCESS.md)

## Development

Every push and pull request runs the frontend unit suite and the complete
Chromium, Firefox, and WebKit end-to-end matrix, a production TypeScript build,
automated WCAG A/AA checks across primary, nested, and mobile views, a production
dependency audit, and the C++ unit/integration suite under AddressSanitizer and
UndefinedBehaviorSanitizer. Compiler warnings fail the backend quality gate.

Node.js 22.12 or newer and pnpm 11.25 are required.

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
pnpm test:unit
pnpm test:coverage
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

The browser establishes no management poll or event stream until capability
discovery has completed. It requests only the monitoring surfaces advertised for
the current gateway session. Losing a capability disconnects its stream, stops
the corresponding requests, and clears previously retained aggregates from the
browser state. Responses already in flight are fenced by the capability epoch
that authorized them and cannot restore data after access is withdrawn. The
browser also aborts their underlying fetches instead of waiting for timeouts.
Losing configuration access removes the live snapshot, shared draft state, and
open editors from the browser; losing only the draft capability preserves the
read-only live snapshot while clearing draft and editor state.

Capability bootstrap accepts only API contract `v1`, a canonical base path that
exactly matches the application mount, and a coherent feature dependency graph.
Contradictory transaction, draft, or event flags fail closed before any protected
request is issued. The System view distinguishes a valid restricted contract
from bootstrap failure and shows the last check, last valid contract, enabled
surface count, and refresh cadence without exposing capability payloads.

All browser JSON clients enforce streaming byte limits even when a response omits
`Content-Length`: 4 MiB for configuration and 8 MiB for draft and system data.
The reader cancels a chunked body immediately after the boundary is crossed.
Browser-visible system diagnostics are additionally limited to short,
control-character-free text.

Without gateway mode, every management API request must carry a canonical
loopback `Host` authority. This keeps local standalone monitoring inaccessible
through DNS rebinding while leaving the bounded orchestration health probe
host-agnostic.

The C++ backend can now retrieve a bounded, validated runtime configuration
snapshot through the authenticated Smithproxy API. When Smithproxy exposes its
canonical revision endpoint, the core brackets the multi-section read and binds
an empty workspace draft only to an unchanged lowercase SHA-256 revision.
Frontend activation remains
capability-gated until the trusted gateway handoff is configured. Configuration
writes remain fail-closed until Smithproxy advertises the exact reviewed atomic
transaction contract. The server-side draft boundary accepts only pinned typed
schema paths and rejects an entire batch when any path, type, enum, range, or
collection is invalid. The draft review includes a value-free server preflight
with affected sections and write-only counts. It exposes an explicit Smithproxy
validation action only after the reviewed transaction capability and canonical draft
revision are available. Atomic commit additionally requires a matching bound
validation and explicit operator confirmation.
Editor saves include only fields changed since that editor opened. When a
pending value is restored to its persistent origin, the GUI core atomically
removes that path while applying any sibling updates under the same optimistic
draft-version check.
System and Captures summary cards use the same pending values as their editors,
show a pending badge, and state explicitly that Smithproxy runtime remains
unchanged until a validated atomic commit.
Policies, objects, system settings, profiles, certificate authorities,
and protocol signatures have typed draft editors. Sensitive paths, credentials,
filters, and matcher expressions use write-only controls.
Policy and routing reference fields preview the value being typed. Known objects
open directly in the next nested editor. Objects and profiles created earlier in
the same workspace draft are marked as pending and reopen their structural create
drawer from the reference chain. Pending renames resolve by their current
draft-visible name while retaining the live entity's stable ID. Literals and
unresolved names remain marked for review without blocking Smithproxy-specific
expressions.
The global configuration search covers policies, reusable objects, profiles,
content rules, certificate authorities, protocol signatures, system settings,
and capture settings. Results use pending draft values and open the matching
nested editor directly. Pending structural creates are searchable by their safe
names, types, and non-sensitive metadata and reopen their create drawer.
Write-only values and redaction sentinels never enter the search index.
Augment provenance preserves both scalar and homogeneous string or integer list
values, so reference collections are not flattened when upstream support arrives.

The GUI core now discovers the proposed authenticated Smithproxy transaction
capability and strictly validates its versions, operation set, bounded limits,
collection identities, and schema hashes. Unreviewed schemas are visible as a
fixed `review-required` diagnostic state but cannot enable configuration writes.
The internal transaction envelope and response parser are also implemented:
they bind typed changes to a canonical revision and OS-generated idempotency
UUID while discarding free-form upstream response text. No browser draft values
or upstream credential cross the same-origin commit boundary: the endpoint
accepts only the expected draft version. The internal commit transport requires
a caller-owned stable idempotency UUID. A move-only commit coordinator retains
that key across an uncertain retry, rejects local mutations while an attempt is
in flight, and releases its gate through RAII. Draft finalization atomically
verifies the draft version, clears changes, and advances the canonical base
revision only after a bound success response. A local monotonic observation
barrier prevents a configuration fetch started before that success from later restoring the stale
base revision. It also requests an immediate monitored configuration refresh.
Draft preflight reports fixed blocker categories instead of collapsing missing
advertisement, schema review, compatibility, revision, and transport readiness
into one generic error.
The CSRF-protected validation endpoint is present as well and sends no draft
values from the browser. The review UI binds a successful result to the exact
draft version, base revision, and operation count and invalidates it on the next
draft change. Validation remains fail-closed until the reviewed capability and
canonical revision are available.
The versioned workspace draft also models schema-validated create, delete, and
move operations and exposes them through the same authenticated, CSRF-protected
browser boundary. Structural writes remain disabled for the current legacy
snapshot reader because its display IDs are index-derived; activation requires
an exact reviewed collection schema and opaque stable entity IDs bound to the
draft revision. The review surface already counts, displays, removes, validates,
and commits scalar and structural operations as one transaction.
When the core advertises `structural_drafts`, the Objects and Policy views enable
typed right-side creation drawers for address, port, protocol, policy, routing,
TLS, detection, DNS ALG, authentication, content, SSH, and script entries.
They reject duplicate identities and invalid ranges locally, store ordered create
operations under optimistic draft concurrency, and reopen pending items from draft
review. A policy can be placed first, last, or immediately before an existing stable
policy and can open referenced objects in another nested drawer. Existing policies
can also be reordered first, last, or before another stable policy. Reordering updates
one optimistic move operation, while restoring the original position removes that
operation. Existing policies and unreferenced reusable objects can be placed into the
same draft as confirmed delete operations; active references and conflicting pending
field edits block the delete locally before the authoritative Smithproxy validation.
References introduced by pending policy or routing edits and structural creates are
included in that blocker, so an internally contradictory draft is not offered as a
valid local workflow. Draft review applies the same dependency ordering to pending
create operations: dependent policy or routing operations must be removed before
the object or profile they reference. A pending object/profile rename is similarly
protected until every cascaded draft reference to its new name has been removed.
Stable routing, TLS, detection, content, SSH, DNS, script, and authentication
profiles use the same confirmed deletion path and cannot be deleted while referenced.
New routing, TLS, detection, DNS ALG, authentication, content, SSH, and script profiles
submit complete typed payloads, reject duplicate names and invalid bounded values
locally, and reopen from draft review under stable optimistic identifiers. Sensitive
session filters, host-key paths, and script paths are cleared after acceptance and
redacted from every draft response. Updating such a pending create requires explicit
write-only re-entry. Authentication identity mappings remain outside this editor and
are never inferred from redacted posture data.
Content profiles expose nested creation, confirmed deletion, and first/before/last
ordering for stable content rules. New write-only match and replacement expressions
are cleared from the editor after the GUI core accepts them and must be re-entered
before a pending create operation can be updated.
Certificate authorities support structural creation and confirmed deletion. New CA
paths are write-only, cleared after acceptance, redacted from draft review, and must
be re-entered before a pending authority can be updated.
STARTTLS and detection signatures support atomic structural creation: the parent
metadata and required first flow step are validated and retained with one draft
version increment, and removing either pending row removes the complete linked
group. Existing signatures support confirmed deletion, while their flow steps
provide nested create, confirmed delete, and ordered move workflows. Write-only
matcher expressions are redacted by the GUI core, cleared from the editor after
acceptance, and never shown in draft review.
Current legacy deployments keep the controls disabled because their snapshot IDs
are not stable.

Control-plane health and listener monitoring use the production C++ backend. A
bounded five-minute runtime history visualizes active sessions and aggregate
throughput. Live session monitoring is aggregated by transport inside the GUI core;
endpoint addresses, ports, session identifiers, and policy names are never sent
to the browser. TLS monitoring exposes cache size, capacity, and freshness only;
certificate subjects and domain names remain behind the GUI core boundary. The
Network neighborhood monitoring follows the same rule: only endpoint counts,
activity windows, observations, and traffic totals reach the browser; hostnames,
tags, labels, and individual timelines do not. The Network view also consumes
the proposed bounded interface-summary API when Smithproxy advertises it. It
shows synchronization health and aggregate interface/address counts while names,
indexes, addresses, namespaces, routes, and raw kernel errors remain server-side.
Every aggregate surface combines collector state with interval-aware freshness;
delayed values are marked stale
and rendered as last-known data instead of appearing live. Monitoring and
operational timelines also reject excessive future clock skew and contradictory
sample ordering. A unified collector matrix shows reported state, freshness,
expected cadence, and last-success age for runtime, session, TLS, and network
collectors. Structured active alerts are
derived inside the GUI core from reachability, rolling availability, collector
freshness, TLS cache capacity, and the latest terminal configuration-refresh
result. They use a bounded fixed vocabulary and never forward arbitrary upstream
log text. The
dashboard groups consecutive non-ready control-plane probes into a bounded
incident timeline with observed states and recovery boundaries. It is derived
only from the validated five-minute probe window. The monitoring feed uses a
same-origin, authenticated SSE endpoint backed by a
bounded unified event ring. Its monotonic revisions merge control-plane state
changes with redacted terminal job results, support `Last-Event-ID` replay, and
issue an explicit snapshot reset when a client falls behind. Every event carries
a reviewed category and code whose severity and fixed message are validated as
one tuple in the browser; the Logs view can filter control-plane and backend-job
events without parsing text. Configuration-refresh jobs follow the same rule:
the browser accepts only the current fixed lifecycle tuples and rejects unknown
phases, arbitrary result text, contradictory progress, and future-dated list
entries. The periodic snapshot remains a recovery path for older deployments
and interrupted streams. The Monitoring view exposes the SSE connection time, last validated payload,
interruption time, reconnect count, and REST recovery posture. Invalid payloads
close the stream and require an explicit retry; arbitrary event text is never
rendered or included in diagnostics.
The root web component supports integration into Saslik Tools:

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

The System view can download a local, versioned diagnostics report containing
only allowlisted states, timestamps, capability flags, aggregate counters, and
the bounded capability-bootstrap posture.
It never includes configuration values, revisions, paths, event text, audit
targets, listener names, protocol names, credentials, or tokens.

The privacy-preserving interface-monitor contract required for future netlink
health monitoring is documented in
[`docs/SMITHPROXY_INTERFACE_API_PROPOSAL.md`](docs/SMITHPROXY_INTERFACE_API_PROPOSAL.md).
The GUI does not invoke or parse the privileged administrative CLI.

When served behind Saslik, the page loads the canonical `/saslik-theme.css` and
`/saslik-theme.js` assets with the `smithproxy-gui` application scope. Standalone
deployments retain the built-in Petroleum fallback when those shared assets are
not available.
