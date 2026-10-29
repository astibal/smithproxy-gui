# Bezpečnostní model

## Výchozí postoj

Management rozhraní je privilegovaný bezpečnostní povrch. Výchozí konfigurace
musí být uzavřená a vzdálený přístup se povoluje explicitně.

## Síť a transport

- loopback nebo Unix socket jako výchozí bind;
- TLS pro každý vzdálený TCP přístup;
- podpora mTLS mezi management backendem a Smithproxy API;
- přesná kontrola upstream identity, žádné tiché vypnutí TLS ověřování;
- omezené timeouty, velikosti requestů a souběžnost.

## Uživatelská session

- náhodný serverový session identifikátor;
- cookie `Secure`, `HttpOnly` a `SameSite=Strict`;
- žádné bearer tokeny v `localStorage`;
- ochrana proti CSRF a kontrola `Origin` u mutací;
- rotace session po autentizaci a změně oprávnění;
- krátká neaktivní i absolutní expirace pro privilegované role.

Konkrétní autentizační mechanismus bude zvolen podle deployment modelu. Podpora
externího identity proxy nesmí automaticky znamenat důvěru libovolným hlavičkám.

## Trusted gateway handoff

Sensitive browser-facing APIs are disabled unless
`SMITHPROXY_GUI_GATEWAY_SECRET` contains 32–256 safe header characters. A
trusted reverse proxy must remove every client-supplied
`X-Smithproxy-GUI-Gateway` header and inject the per-instance secret only after
successful user authentication. The secret is compared without an early exit,
is never returned to the browser, and must not be logged.

Missing or incorrect handoff credentials return HTTP 401 from every management
snapshot, event, alert, and draft endpoint when gateway mode is configured.
Capability discovery reports those feature flags as unavailable unless the
current request passed the same boundary. The minimal health endpoint remains
available for orchestration. A non-loopback listener is rejected at startup
unless gateway authentication is configured. Configuration reads and mutations
always require an authenticated gateway, including on loopback.

The bounded session diagnostic reveals only whether gateway mode is configured
and whether the current request passed it. Browser code cross-checks that result
with every privileged configuration capability refresh and disables all config
and draft actions on a missing, malformed, or contradictory response. It polls
at a bounded interval and rechecks immediately after connectivity or visibility
recovery so a reviewed secret rotation can recover without a page reload.

Monitoring follows the same bootstrap boundary. The frontend opens no protected
poll or event stream until the current capability response enables it. Capability
loss closes SSE and replaces retained aggregate snapshots with zeroed unavailable
states, preventing data observed under an earlier gateway session from remaining
visible after authorization is withdrawn. It also clears connection timestamps
and reconnect counters. Epoch fencing rejects callbacks and HTTP responses that
were valid when requested but completed after the
session changed, while client-owned abort controllers cancel the pending network
operations. Configuration revocation removes the live snapshot, shared
draft state, validation results, open drawers, and their form controls; slower
configuration or draft responses cannot repopulate them.

The public bootstrap response is treated as untrusted input. Its API version,
canonical mount path, gateway-session relationship, and feature dependency graph
must agree before the browser enables a protected request. A response for a
different workspace mount cannot redirect or rebind the client and fails closed.

Every JSON response crosses a streaming byte boundary before `JSON.parse`.
Declared oversize responses are rejected without reading the body; undeclared
chunked responses are counted by bytes and actively cancelled at the limit.
This prevents monitoring and audit endpoints from becoming a browser-memory DoS
path. Short diagnostic text limits also prevent control-character injection and
unbounded DOM content.

Gateway-secret rotation uses a bounded two-value overlap. The current value is
mandatory; `SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS` is optional, independently
validated, and must differ. Both comparisons use the constant-time helper. A
deployment writes `current=new, previous=old`, restarts the GUI core, switches
the ingress to `new`, and then removes `previous` at the next restart.

Draft mutations additionally fail closed unless `Origin` exactly matches the
request host and the request carries JSON content type plus the custom
`X-Smithproxy-GUI-CSRF: 1` header. Optional Fetch Metadata must report
`same-origin`. The GUI core does not emit permissive CORS headers. These checks
are enforced independently of trusted-gateway authentication. Individual
requests are limited to 64 KiB, accumulated draft values to 1 MiB, and browser
responses to 8 MiB before parsing. Removing one draft path, an atomic bounded
path group, or the complete draft uses the same authentication, CSRF, and
optimistic-concurrency checks as an upsert. Group removal rejects duplicates or
missing paths without partially changing the draft.

Draft responses preserve the write-only browser boundary as well as draft
requests. The browser accepts sensitive scalar and structural fields only as
bounded GUI-core redaction sentinels; a raw value or an invalid list-count
sentinel rejects the complete snapshot before it reaches application state.
Global search indexes pending structural creates through an explicit safe-field
allowlist and never indexes redaction sentinels.

Browser validation is never authoritative. The core accepts only pinned schema
paths emitted by the typed editors and independently checks canonical indexes,
types, enums, ranges, bounded unique collections, and opaque secret limits.
Unknown fields and partially invalid batches fail closed before any draft state
is changed. The same validator is a mandatory boundary for the future upstream
transaction adapter; a syntactically safe arbitrary libconfig path is not enough.

Transaction capability discovery is fail-closed. The core clamps upstream
limits to 4,096 operations and 1 MiB, rejects unknown contract versions,
missing or duplicate operations and collections, malformed schema hashes, and
unreviewed collection revisions. `config_write` becomes true only when the
complete validate, commit, idempotency, rollback, and audit path is available
under an exact reviewed capability.

Structural drafts add a second fail-closed identity boundary. Create fields are
validated through the pinned configuration schema, JSON objects reject unknown
members, and delete or move operations use only opaque entity IDs. A ready
transaction capability is insufficient by itself: the current snapshot must
explicitly attest stable entity IDs and carry the same canonical revision as the
workspace draft. The legacy multi-section reader synthesizes display IDs from
indexes and therefore can never enable structural writes. Removing a retained
structural operation remains available after capability loss so an operator can
always recover or discard the draft.
The browser consumes one explicit `structural_drafts` feature bit and rejects it
unless configuration writes and drafts are also enabled. The GUI core computes
the bit only for an authenticated gateway request after safely binding an empty
draft; an unauthenticated capability request cannot mutate the draft version.

Canonical revision acquisition is also fail-closed. The core accepts only an
exact `sha256:` prefix followed by 64 lowercase hexadecimal characters in a
strict bounded response envelope. It reads the revision before and after the
legacy multi-section snapshot and binds a draft only if the values match. A
revision change on an empty draft increments its optimistic version; a non-empty
draft is never rebound.

The transaction envelope builder accepts only the already pinned draft schema,
requires a canonical `sha256:` base revision and a reviewed ready capability,
and rechecks operation and encoded-request limits. Idempotency keys are UUIDv4
values generated inside the GUI core directly from the operating-system CSPRNG.
The response parser discards upstream messages and warning contents; it retains
only a fixed terminal state, validated revisions, operation and warning counts,
and a bounded restart enum. The adapter serves both explicit browser validation
and the capability-gated atomic commit endpoint. Commit mode does not generate a
fresh key implicitly. The coordinator retains and reuses one validated UUID for
every uncertain retry of the same draft
version and base revision. Its move-only RAII lease keeps at most one attempt in
flight and rejects local draft mutations until the attempt terminates.
Successful finalization also establishes a GUI-local monotonic revision barrier.
Configuration observations started before that point cannot overwrite the
committed base revision even if their requests complete later. The barrier is
process-local metadata and cannot be supplied by either untrusted peer.
The monitor marks its configuration snapshot as refreshing after finalization,
wakes an immediate read, and rejects any sampled read whose local monotonic start
predates the commit barrier.

The explicit draft-validation endpoint accepts only an optimistic draft version;
it obtains every value from the server-side snapshot after gateway and CSRF
checks. It uses a 10-second upstream deadline, a 1 MiB response ceiling, strict
TLS verification, disabled redirects and proxies, and value-free audit metadata.
It remains fail-closed until capability review and canonical revision binding are
both available.

The browser treats validation as a versioned, ephemeral result rather than an
authorization token. It requires an exact match on draft version, base revision,
and operation count, and discards the result whenever the draft version changes.
Commit must repeat authoritative validation inside the upstream transaction.
The browser sends only `expected_version`, requires an exact bound validation,
and requires a second operator action before issuing commit.

After a successful commit response, draft finalization compares the optimistic
version again under the draft lock and requires a different canonical revision.
If another local writer changed the draft while the request was in flight, the
newer draft is preserved rather than cleared.

Draft preflight serializes only bounded aggregate counts and stable blocker
codes. It does not return paths, values, diffs, or validation payloads and uses
the same trusted-gateway authentication as the draft itself. The browser rejects
a preflight whose version/counts do not match its current draft, preventing a
stale summary from authorizing or visually blessing a newer change set.
The preflight returns exactly one fixed transaction-availability blocker, so an
operator can distinguish missing advertisement, incompatible versions,
unreviewed schema hashes, missing revision binding, and a disabled transport
without receiving any free-form upstream detail.

## Oprávnění

Minimální role:

```text
viewer
operator
policy-editor
administrator
```

API kontroluje oprávnění na každém endpointu a citlivé operaci. Skrytí tlačítka
ve frontendu není bezpečnostní kontrola.

## Frontend

- scripts are restricted to same-origin resources without `unsafe-inline` or
  `unsafe-eval`; component styles currently require `style-src 'unsafe-inline'`;
- žádné vykreslování neověřeného HTML;
- bezpečné odkazy a downloady;
- ochrana proti clickjackingu;
- immutable cache pro fingerprinted assets, `no-store` pro citlivá data;
- dependency pinning, lockfile, SBOM a kontrola licencí.

Frontend CI creates a deterministic CycloneDX inventory from the installed
lockfile and rejects every license outside the reviewed allowlist. CMake creates
a separate CycloneDX inventory from the exact backend dependencies resolved for
the build, including the full lmhpp revision. CI validates and publishes both as
bounded build artifacts. The exact allowlist and review rules are documented in
`DEPENDENCY_POLICY.md`.

Saslik theme runtime musí zůstat kompatibilní se striktní CSP. Import palet je
omezen velikostí, schema validací a pouze hex barevnými hodnotami.

Every response carries `nosniff`, `no-referrer`, same-origin framing and resource
and opener policy, origin-agent isolation, a deny-by-default browser Permissions
Policy, and a CSP that blocks objects, foreign connections, foreign frames, and
base-URL rewriting. API responses and the HTML entry point use `no-store`;
fingerprinted static assets are immutable. Production builds do not publish
JavaScript source maps. HSTS remains the responsibility of the Saslik TLS
terminator because the GUI core itself serves internal HTTP.

Standalone mode additionally accepts API requests only when the HTTP `Host`
authority is a canonical loopback literal or `localhost`, with an optional valid
port. This closes DNS-rebinding access to local monitoring while keeping the
unauthenticated health probe host-agnostic. Gateway mode accepts the public
Saslik authority because the trusted proxy secret authenticates that boundary.

## Config a secrets

- secrets jsou write-only/redigované;
- write-only náhrady zůstávají pouze v serverovém draftu a draft API vrací jen
  redigovaný záměr `clear`/`replace`, případně bezpečný počet položek;
- audit nesmí obsahovat secrets, tokeny ani citlivé payloady;
- export diagnostiky používá explicitní allowlist;
- validace cest a identifikátorů neumožní filesystem traversal;
- commit vyžaduje aktuální revision a kontrolu oprávnění v okamžiku commitu.

The System view creates the diagnostics report locally. Its versioned allowlist
contains state enums, timestamps, capability flags, aggregate counters, and item
counts only. Capability bootstrap contributes only its fixed state, sanitized
timestamps, and a count capped to the known feature vocabulary; its error text
is never exported. The report excludes configuration values and revisions, paths, workspace
and base-path identifiers, free-form upstream details, listener and protocol
names, event and alert text, audit targets and request IDs, credentials, and
tokens.

Event transport diagnostics add only browser-generated timestamps, a reconnect
counter, and fixed states. Stream error text and event payloads are excluded.

Augment provenance accepts only bounded scalar or homogeneous string/integer
list values. List length, item length, control characters, numeric safety, layer
type agreement, and deep equality of the active and effective values are checked
before any provenance reaches an editor. Secret-bearing values remain
write-only and are never valid provenance payloads. A pinned non-secret path
allowlist also rejects unknown future fields until they receive explicit review.

Interface monitoring follows a stricter topology boundary. Only synchronization
state, bounded counters, generation, address-family totals, and a validated
stable error code are accepted. Interface names and indexes, IP and link-layer
addresses, namespaces, routes, raw netlink flags, and kernel error text are
rejected upstream of the browser and omitted from diagnostics.

## Audit

Všechny současné HTTP odpovědi dostávají korelační `X-Request-ID`; error envelope
obsahuje stejnou hodnotu a stabilní strojový kód. ID neobsahuje uživatelský vstup
a browser ho reflektuje jen po striktní syntaktické validaci. To poskytuje
bezpečnou korelaci provozních chyb.

GUI core nyní udržuje nejvýše 256 in-memory záznamů pokusů o management
mutaci. Záznam obsahuje čas, request ID, typ operace, výsledek, mechanismus
autentizace a nejvýše 32 validovaných konfiguračních cest. Neobsahuje hodnoty,
request body, credentials ani secrets a po restartu core se ztratí. Endpoint
vyžaduje stejné gateway ověření jako ostatní management monitoring.

Tělo každého HTTP requestu je omezené na 128 KiB. Hranice ponechává prostor pro
největší povolený 65 536znakový write-only matcher v atomické strukturální JSON
obálce; první byte za hranicí vede k HTTP 413 ještě před parsováním dokumentu.

Současný Saslik handoff neposkytuje prověřenou identitu uživatele. Core proto
explicitně vrací nedostupnou actor attribution a nedůvěřuje klientem dodaným
identity hlavičkám. Persistentní audit po schválení identity kontraktu musí pro
každou mutaci zaznamenat:

- identitu uživatele a session;
- čas a request ID;
- typ operace a cílové stabilní identifikátory;
- redigovaný normalizovaný diff;
- validační, commit a apply výsledek;
- související job a audit ID.

Auditní záznam nesmí být měnitelný přes běžné GUI API.

## Bezpečnostní testování

- threat model před prvním produkčním releasem;
- testy autorizace pro každý endpoint a roli;
- fuzzing parserů, patch operací a importovaných palet;
- negativní testy velikostí, timeoutů a vyčerpání zdrojů;
- SAST, dependency audit a secret scanning v CI;
- pravidelné manuální review management boundary.
