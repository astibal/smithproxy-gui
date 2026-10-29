# Návrh API kontraktu

Toto je návrh povrchů, nikoli schválená implementace Smithproxy API.

## Zásady

- verzování pod `/api/v1`;
- JSON odpovědi s explicitní schema verzí;
- ETag/revision pro konkurenční změny;
- jednotný strukturovaný error envelope;
- stránkování a pevné limity všech kolekcí;
- request ID, audit ID a idempotency key;
- SSE události jsou obnovitelné pomocí event ID.

## Capability discovery

```http
GET /api/v1/capabilities
GET /api/v1/config/schema
```

## Authenticated runtime snapshot

```text
GET /api/v1/auth/session
GET /api/v1/config/snapshot
```

The session endpoint reveals only whether trusted gateway authentication is
enabled and valid for the current request. The snapshot endpoint requires the
trusted gateway handoff described in `SECURITY.md`; missing or invalid
credentials return HTTP 401. The response contains a bounded and validated
runtime view of policies and address, port, and protocol objects. It does not
contain Smithproxy API credentials, gateway secrets, or filesystem data.

The snapshot also includes typed, bounded views of detection, content, TLS,
SSH, DNS, script, legacy authentication, and routing profiles. Filesystem paths,
SNI bypass entries, content-rule expressions, session filters, and identity
mappings are reduced to explicit configured flags or counts before crossing the
browser boundary. Stable IDs and derived reverse references support nested drawers.

The system-settings posture covers listener admission and ports, fail-open
behavior, worker pools, certificate-status cache TTLs, TLS autodetection, kernel
TLS, payload retention, logging, syslog posture, HTTP API access, and webhooks.
API keys, webhook URLs, filesystem paths, syslog targets,
certificate and CLI passwords, web-rating keys, and identity values are never
serialized; only bounded counts and configured flags are exposed.

Debug posture includes the five global diagnostic logging flags and a bounded,
typed list of current per-module overrides. Boolean, 32-bit integer, and bounded
string values are editable; module identifiers must be safe configuration-path
segments.

Capture posture includes local format and quota, remote tunnel mode and TTL,
and checksum behavior. Capture directories, filename components, tunnel
destinations, and bind interfaces are exposed as configured flags and edited
through write-only replace/clear controls.

Trust and signature posture covers configured TLS certificate-authority entries,
STARTTLS signatures, detection signatures, and their ordered flow steps.
Signature names, categories, sides, groups, engines, matcher types, and byte
windows are typed. Certificate paths and matcher expressions remain inside the
GUI core and use explicit write-only replacement controls.

The snapshot carries `augment_support` and a bounded `value_origins` collection.
Each origin identifies a stable schema path, persistent and effective scalar
values, editability, and an ordered augment layer chain. Every layer carries its
scalar value, optional priority, and an explicit active flag. Exactly one active
layer terminates the chain and its value must equal the effective value.
The GUI renders effective values but preserves the persistent value and layer
ownership in the editor. Until Smithproxy exposes this data through its HTTP API,
the live GUI core returns `augment_support: false` with an empty origin collection.

GUI nesmí odhadovat podporu funkce pouze z čísla verze. Capability odpověď určuje
dostupné endpointy, limity a feature flags.

## Config

```http
GET    /api/v1/config?view=persistent
GET    /api/v1/config?view=effective
GET    /api/v1/config/augments
GET    /api/v1/config/references/{object-id}

POST   /api/v1/config/drafts
GET    /api/v1/config/drafts/{draft-id}
PATCH  /api/v1/config/drafts/{draft-id}
DELETE /api/v1/config/drafts/{draft-id}

POST   /api/v1/config/drafts/{draft-id}/validate
GET    /api/v1/config/drafts/{draft-id}/impact
POST   /api/v1/config/drafts/{draft-id}/commit
```

Mutace draftu používá stabilní schema identifikátory a typované operace. Formát
nebude uzavřen před prověřením JSON Patch, Merge Patch a doménových operací pro
pojmenované objekty a seřazené kolekce.

The GUI core currently exposes one workspace-scoped foundation draft at
`GET /api/v1/config/draft` and accepts typed atomic batches at
`POST /api/v1/config/draft/changes`. The complete draft can be discarded with
`POST /api/v1/config/draft/clear`. A batch carries one expected version and a
bounded `changes` array; it is rejected without partial application when any
path or value is invalid. Supported foundation values are booleans, finite
numbers, strings, and bounded homogeneous string or integer arrays. Every
mutation requires the trusted gateway handoff, an exact same-origin `Origin`,
`Sec-Fetch-Site: same-origin` when the browser supplies it, JSON content type,
and `X-Smithproxy-GUI-CSRF: 1`. The
custom header and absent CORS support prevent cross-origin form submission.
Requests are limited to 64 KiB, the accumulated draft payload is limited to
1 MiB, paths and values are bounded, and an expected draft version is mandatory;
stale writers receive HTTP 409. The browser also rejects draft responses above
8 MiB before JSON parsing, leaving room for worst-case JSON escaping of the
bounded raw draft. This store is not yet a commit path and cannot mutate
Smithproxy configuration.

The GUI core applies an authoritative schema allowlist before storing a batch.
Every path must map to an editor field in the pinned configuration inventory;
collection indexes must be canonical and below the snapshot limit. JSON types,
enums, integer ranges, collection sizes, uniqueness, and sensitive opaque-value
limits are checked independently of browser validation. An unknown or invalid
member rejects the complete batch without changing its version or retaining any
of its otherwise valid members.

`GET /api/v1/config/draft/preflight` returns a value-free impact summary for the
current workspace draft. It includes the matching draft version, total and
write-only change counts, and bounded per-section counts. It reports the local
schema result independently from upstream Smithproxy validation and commit
availability. Until the reviewed transaction API is advertised, the response
must say `upstream_validation: "unavailable"`, `commit_available: false`, and
include the stable `upstream.transaction_unavailable` blocker. The endpoint
never returns draft values, normalized diffs, paths, or secret material.

Write-only paths accept explicit `unchanged`, `replace`, or `clear` intent in
the frontend. The core retains a replacement only inside the server draft.
Every draft response substitutes an intent-only redaction marker that preserves
clear or replace intent and a bounded collection count; the review UI never
renders the submitted path, credential, endpoint, or key value.

The policy editor atomically persists the name, enabled state, protocol, source
and destination address and port collections, features, action, NAT mode, and
all routing and profile references through this endpoint. Nested editors use the
same draft and version to persist the mapped
name, type, value, range, and numeric identifier fields of address, port, and
protocol objects. Routing profile batches cover their name, destination address
and port references, load-balancing method, and paired SNI rewrite values while
preserving nested links to the referenced objects. Detection and DNS ALG profile
batches cover their names and all currently exposed typed mode/boolean fields.
TLS profile batches cover all fields saved by the current Smithproxy runtime:
directional PFS and session reuse, trust validation, OCSP, certificate lookup,
failure replacement and override policy, SNI/DNS matching, bounded warning ports,
timeouts, client certificates, alerts, and diagnostics. Redacted SNI bypass
collections support write-only replacement and clearing. Content profile
batches cover capture, webhook, JA4 controls, write-only session-filter
replacement, and nested content-rule fill-length/interval actions plus
write-only match/replacement rotation. SSH profile batches cover the host-key
policy and channel, forwarding, X11, agent actions, and write-only private
host-key path rotation.
Script profile batches cover the runtime and write-only module-path rotation.
Certificate-authority batches cover names and write-only path rotation.
Deprecated authentication profile batches cover authentication
and identity resolution while redacted identity mappings remain unchanged.
System-setting batches cover listener admission, all listener ports, fail-open
behavior, worker pools, TLS detection, SOCKS IP-version behavior, thread-pool
task logging, HTTP API token lifetime/refresh, listener port, access
posture, and webhook switches. HTTP API bind address/interface values remain
write-only. Webhook and Sift endpoints, identities, and bound interfaces are
also write-only; payload limits, control-plane intervals, and task diagnostics
are typed. Capture batches cover enablement, formats, quota, tunnel TTL, and
checksum behavior. Nameservers, API credentials, webhook URLs, capture paths,
remote destinations, and bound interfaces use explicit write-only replacement
or clearing. Allowed addresses and other non-secret lists use bounded typed
editors. The active settings set emitted by the current Smithproxy saver is
covered in full, including performance tuning, certificate transparency and CA
bundle files, local explicit-proxy destination protection, Sift LoreD policy,
URL-disclosure consent, and the write-only administration group. Deprecated ignored
tuning keys are deliberately omitted from the editor.
The current detection, capture, SSH, routing, and script schemas are also
covered in full. Their coverage manifest entries are pinned to exact active
field inventories so a schema drift cannot silently retain a `full` claim.
Signature reads cover severity as well as category, side, engine selection, and
ordered matcher flows. Expression bodies remain redacted and write-only.
The frontend keeps the server draft version, reports conflicts instead of
silently overwriting, and refreshes the shared draft after a failed write.
Other live fields remain read-only until they have an explicit typed path mapping.

## Runtime a monitoring

```http
GET /api/v1/status
GET /api/v1/health
GET /api/v1/metrics/summary
GET /api/v1/listeners
GET /api/v1/sessions/activity
GET /api/v1/tls/cache/summary
GET /api/v1/network/neighbors/summary
GET /api/v1/events/recent
GET /api/v1/alerts
GET /api/v1/audit/recent
GET /api/v1/logs
GET /api/v1/events
```

`/sessions/activity` is intentionally aggregate-only. The GUI core groups live
sessions by transport and exposes counts, throughput, and byte counters. Endpoint
addresses, ports, session identifiers, and matched policy names do not cross the
browser boundary. A future detailed session surface requires an explicit privacy
and authorization design.

`/metrics/summary` includes at most 60 ordered runtime samples. Each sample
contains only state, timestamp, active-session count, and cumulative upstream
and downstream byte counters. The frontend derives short-window throughput from
counter deltas and treats counter resets or unavailable samples as chart gaps.

`/tls/cache/summary` exposes cache occupancy, capacity, and sample freshness. It
must not expose certificate subjects, SAN values, domain names, or cache keys.

`/network/neighbors/summary` exposes bounded 30-day aggregate counts, activity
windows, observations, and byte totals. Hostnames, tags, labels, and per-endpoint
timelines are consumed only inside the GUI core and are never serialized to the
browser response.

`/events/recent` currently exposes at most 60 structured GUI-core control-plane
state transitions. Messages are generated from a fixed vocabulary and validated
for length and control characters in the browser client. The capability response
distinguishes these events from the unavailable Smithproxy event ring. Smithproxy
event text must only be added through a bounded authenticated HTTP API; the GUI
core does not parse the administrative CLI.

`/alerts` exposes at most 16 active, structured GUI-core conditions. Alert IDs,
severity, titles, and details come from a fixed server vocabulary; arbitrary
upstream log text is never forwarded. The current rules cover control-plane
reachability and rolling availability, collector health and freshness, and TLS
cache capacity. Disabling local explicit-proxy destination protection emits a
configuration-posture warning. A control-plane outage suppresses derivative collector alerts
to avoid an alert storm.

`/audit/recent` exposes at most 256 in-memory GUI-core records for management
mutation attempts. Each record contains a monotonic audit ID, time, request ID,
operation, outcome, authentication mechanism, and at most 32 validated
configuration paths. Values, request bodies, credentials, and secrets are never
included. The history is reset when the GUI core restarts.

The current Saslik gateway handoff proves that a request crossed the trusted
authentication boundary but does not provide a reviewed user identity. The
response therefore reports `actor_available: false` and `actor: null` rather
than inferring identity from an untrusted header. Persistent, actor-attributed
audit remains part of the production API design.

`/events` používá autentizované same-origin SSE. První odpověď nese událost
`snapshot`; další požadavky posílají `Last-Event-ID` a dostanou pouze novější
události typu `operational`. Event ID i `source_revision` vycházejí z monotónního
počítadla probe, takže nejsou závislé na systémovém čase. Pokud ID již není v
omezeném šedesátipoložkovém okně nebo core mezitím restartoval, server pošle
událost `reset` s autoritativním snapshotem. Prázdná kontinuita vrací SSE
keepalive. Klient každý payload znovu validuje stejnými limity jako REST snapshot
a při nevalidním payloadu stream uzavře.

Server vrací `retry: 2500`, `Cache-Control: no-store` a `X-Accel-Buffering: no`.
Spojení je po každé dávce uzavřeno; standardní `EventSource` jej obnoví bez
držení backendového workeru pro neaktivní záložku. Periodický `/events/recent`
zůstává recovery snapshotem a cestou kompatibility pro starší core. Cursor má
nejvýše 96 bytů; delší `Last-Event-ID` je odmítnuto před porovnáváním.

## Úlohy

```http
GET  /api/v1/jobs
GET  /api/v1/jobs/{job-id}
POST /api/v1/jobs/{job-id}/cancel
```

Stavy minimálně:

```text
queued → running → succeeded
                 ├→ failed
                 └→ cancelling → cancelled
```

Cancel je capability, ne automatický příslib. Úloha musí uvádět, zda je bezpečně
zrušitelná, její fázi, progress, deadline, vlastníka a redigovaný výsledek.

## Error envelope

```json
{
  "error": {
    "code": "config.revision_conflict",
    "message": "Configuration changed since the draft was created.",
    "request_id": "...",
    "retryable": false,
    "fields": [],
    "details": {}
  }
}
```

Lokalizace textu je odpovědnost GUI; stabilní `code` je součástí API kontraktu.
Každá odpověď zároveň nese stejné opaque ID v hlavičce `X-Request-ID`. Core
generuje nový identifikátor pro každý request a nikdy do něj nevkládá uživatelská
data. Frontend zobrazí referenci v diagnostické chybě pouze tehdy, když odpovídá
omezenému formátu `<hex-instance>-<decimal-sequence>`; nevalidní hlavičku
nereflektuje.

Aktuální stabilní kódy pokrývají `auth.required`, `auth.csrf_failed`,
`request.body_too_large`, `request.method_not_allowed`, `request.not_found`,
`request.invalid_path`, `events.invalid_cursor`, `draft.version_conflict`,
`draft.change_rejected` a `draft.invalid_request`. Neznámá bezpečně zpracovaná
chyba používá `request.failed`. `fields` a `details` zůstávají prázdné, dokud
konkrétní endpoint nemá schválené strukturované detaily.
