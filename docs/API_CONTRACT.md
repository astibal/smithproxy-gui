# Návrh API kontraktu

Toto je návrh povrchů, nikoli schválená implementace Smithproxy API.

Aktuálně implementovaný GUI-core povrch, jeho metody, autentizační hranice a
capability vazby jsou strojově evidovány v `API_SURFACE.json`. CI porovnává tento
manifest přímo s C++ routerem; tento dokument navíc obsahuje budoucí návrhy,
které ještě implementované být nemusí.

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

The implemented capability response includes a normalized
`config_transaction_state`. The GUI core probes the authenticated upstream
`/api/config/v2/capabilities` endpoint, validates contract versions, operation
coverage, limits, collection identities, and schema hashes, and reports only a
fixed state vocabulary. Missing gateway authentication reports `unavailable`.
An advertised schema that is not pinned by the GUI core reports
`review-required` and does not enable writes.

Frontend polling is capability-driven. The browser does not call `/status`, any
aggregate monitoring endpoint, jobs, alerts, audit, or the SSE feed before the
bootstrap response enables the corresponding management feature for the current
request. A subsequent capability loss stops those requests, closes SSE, and
zeroes retained browser aggregates. In gateway mode, management capabilities
combined with an explicitly rejected gateway session are treated as an
inconsistent fail-closed response. Capability discovery is not blocked by
slower monitoring, configuration, or draft requests. Every such request is
bound to the browser's current access epoch; a response from an earlier epoch is
discarded, and pending fetches are actively aborted. Revoking configuration
access clears the live snapshot, shared draft metadata, validation and commit
state, dirty editor chain, and any entered write-only values. A narrower draft
capability loss clears the same mutation state without discarding the still
authorized live configuration snapshot.

The browser accepts only `api_version: v1` and a canonical `base_path` identical
to the mount used to construct its API client. Feature dependencies are strict:
write requires read, drafts, preflight, and a ready transaction contract;
preflight requires drafts; Smithproxy events require the event surface. An
incoherent graph disables every protected frontend request.

System diagnostika eviduje stav bootstrapu, čas posledního pokusu a posledního
platného kontraktu a počet povolených surfaces. Platný kontrakt s nulovým nebo
omezeným oprávněním zůstává `ready`; `unavailable` znamená chybu transportu nebo
odmítnutý kontrakt. Obnova běží po 30 sekundách a při změně konektivity.

The internal transaction adapter already builds the reviewed `validate` and
`commit` envelopes from typed workspace-draft changes. It binds every request
to the canonical base revision and a core-generated idempotency UUID and rejects
the encoded body when the negotiated or hard 1 MiB limit is exceeded. Upstream
responses are reduced to fixed outcome states and aggregate metadata before any
browser-facing endpoint can consume them. The explicit validation endpoint uses
this adapter. The internal commit transport accepts an idempotency UUID supplied
by its coordinator so an uncertain attempt can be retried with the same key.
The move-only coordinator lease rejects a second commit and local draft
mutations while an attempt is in flight and releases the gate on every exit;
commit still has no browser-facing endpoint.

Every configuration snapshot carries a GUI-local monotonic observation start.
After a successful commit, the draft rejects revision binding from observations
started before the commit completed. This ordering value is never accepted from
the browser or Smithproxy and is not serialized outside the GUI core.

A validation success must echo the canonical base revision as both `revision`
and `previous_revision`. A commit success must echo that base as
`previous_revision` and return a different canonical `revision`; the GUI core
rejects any response that does not preserve this binding.

The GUI core obtains the persistent revision from the authenticated upstream
`GET /api/config/v2/revision` endpoint. It brackets the current multi-section
configuration read with two bounded revision requests and exposes a revision
only when both exact lowercase SHA-256 values match. Legacy Smithproxy versions
without the endpoint remain readable but cannot produce a revision-bound draft.

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
Each origin identifies a stable schema path, persistent and effective typed
values, editability, and an ordered augment layer chain. Values may be scalars
or homogeneous string/integer lists capped at 256 items. Strings are bounded and
control-character-free; numbers are safe integers. Every layer carries its value,
optional priority, and an explicit active flag. Exactly one active
layer terminates the chain and its value must equal the effective value. A chain
either omits every priority and relies on its explicit array order, or assigns a
strictly increasing non-negative priority to every layer. Layer identifiers use
bounded schema-safe ASCII identifiers; mixed, duplicate, or descending priority
metadata fails closed.
Provenance paths use a pinned allowlist of non-secret fields already present in
the browser snapshot. Unknown fields and every write-only credential, path,
matcher, identity, or endpoint field reject the entire snapshot.
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
`POST /api/v1/config/draft/clear`; one pending path or a bounded unique path
group can be removed atomically with `POST /api/v1/config/draft/changes/remove`.
Reviewed create, delete, and move operations use
`POST /api/v1/config/draft/operations`. A non-empty bounded group of related
operations can be retained with one version increment through
`POST /api/v1/config/draft/operations/batch`; validation or capacity failure
rejects the complete group. One operation is removed by its bounded
client-local identifier through `POST /api/v1/config/draft/operations/remove`.
Removing either operation from a pending signature-plus-first-flow group removes
the complete group with one version increment, so draft review cannot leave an
orphan signature or flow step.
The core accepts structural writes only while Smithproxy advertises the exact
reviewed collection schema and compatible nesting and ordering semantics, and
the current configuration snapshot carries opaque stable entity IDs bound to
the draft base revision. IDs synthesized by the legacy multi-section reader are
never accepted for structural operations. A capability loss blocks new
structural writes but never blocks removing or discarding an already retained
operation. Draft snapshots
return structural operations with the same write-only redaction rules as scalar
changes, and preflight counts each structural operation exactly once.
Capability discovery exposes this complete conjunction as
`features.structural_drafts`; the browser never infers structural readiness from
`config_write` alone.
An editor can atomically reconcile one bounded `changes` batch with a disjoint
`remove_paths` array through `POST /api/v1/config/draft/changes`. This keeps a
field restored to its persistent value from passing through a transient set
operation and applies one optimistic version check to the complete editor save.
All removal operations require the current
draft version, so one operator cannot silently erase a concurrent operator's
work. Removing a structural create is rejected while a retained ordered operation
uses its client ID as a position anchor; linked signature/flow cascades apply this
check to the complete removed group. An explicit
`POST /api/v1/config/draft/validate` sends the current immutable draft snapshot
through the reviewed upstream transaction transport when that capability and a
canonical base revision are available. A batch carries one expected version and a
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
bounded raw draft. Sensitive change paths and structural fields must contain a
bounded `[redacted:clear]`, `[redacted:replace]`, or
`[redacted:replace:N]` sentinel in every draft response. The browser rejects the
entire response if raw sensitive material or an invalid sentinel is present.
For redacted authentication identity replacements, the same response carries a
bounded `private_profile_references` array containing only opaque live profile
IDs and aggregate source counts. It never carries identity names or binding
values. The browser uses this value-free reverse index to keep deletion guards
correct after reload; malformed, duplicate, or unbounded entries reject the
complete draft response.
This store cannot mutate Smithproxy configuration by itself;
mutation is possible only through the separate capability-gated atomic commit
endpoint.

When the draft is empty, the core binds it to the latest verified configuration
revision. Changing that binding increments the draft version, so a browser that
loaded an older or unbound draft cannot submit changes under a new revision.
Once the draft contains a change, its base revision is immutable until discard
or a future successful atomic commit; live revision changes are never silently
rebased.

The draft store has a separate atomic commit-finalization operation. It requires
the exact draft version, a non-empty draft, a canonical new revision different
from the base, and then clears the changes, advances the base, and increments
the version under one lock. A concurrent local edit therefore cannot be erased
by a delayed upstream response.

Validation accepts only `expected_version`; draft values are loaded inside the
GUI core and are never echoed by the browser. The mutation requires the same
gateway and CSRF boundary as draft writes. Its successful response contains only
the bound revision, validated operation count, warning count, and restart enum.
Upstream authorization failures, messages, paths, warnings, and values are not
forwarded. Every attempt receives a value-free management audit entry.

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
availability. `validation_available` becomes true only when the reviewed
transaction capability and canonical base revision are both present;
`commit_available` additionally requires a non-empty draft and the enabled
atomic commit transport. Stable blockers distinguish an empty draft,
unadvertised endpoint, incompatible contract, unreviewed schema set, or missing
canonical base revision. A ready non-empty draft has no blockers. The endpoint
never returns draft values, normalized diffs, paths, or secret material.

The review UI sends only the current draft version when the operator explicitly
requests Smithproxy validation. It accepts success only when the response
matches the current version, canonical base revision, and complete operation
count. Any draft mutation invalidates the displayed result.

`POST /api/v1/config/draft/commit` accepts only `expected_version` under the
trusted-gateway and same-origin CSRF boundary. The browser enables it only for a
validation bound to the same draft version, base revision, and operation count,
then requires a second explicit confirmation. The GUI core repeats authoritative
validation inside the upstream atomic transaction. Its response contains only
the previous and committed canonical revisions, committed operation count,
warning count, restart enum, and finalized draft version.

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
bundle files, and the write-only administration group. Deprecated ignored
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

Every aggregate monitoring panel combines the latest collector state with the
freshness of its last successful sample at that collector's expected interval.
`ready` alone therefore does not prove that browser-visible data is current:
aging or stale values change the visual state and are explicitly labeled as the
last known sample. A listener backed by stale data is never presented as
currently `Running`.

The Monitoring view also presents a single collector health matrix. It keeps
the server-reported state separate from interval-aware freshness and shows the
expected cadence plus the age of the last successful sample for runtime metrics,
session activity, TLS cache, network-neighbor aggregates, and the interface
synchronization monitor.

`GET /api/v1/network/interfaces/summary` publishes only the validated aggregate
contract from `SMITHPROXY_INTERFACE_API_PROPOSAL.md`: generation, synchronization
counters, event-datagram counters, address-family totals, and an optional stable
diagnostic code. The core accepts schema version 1, exact bounded objects,
JavaScript-safe non-negative integers, coherent counters, and at most five
minutes of positive clock skew. Unknown schemas, oversized responses, raw error
text, and incoherent totals fail closed. Interface names, indexes, IP and link
addresses, routes, namespaces, and raw kernel errors never reach the browser.

Browser validation permits at most five minutes of positive clock skew. It
rejects health, collector, event, alert, audit, and job snapshots beyond that
tolerance; `last_success` after `checked`; non-monotonic histories; and a history
tail whose state or timestamp contradicts its enclosing snapshot. A remote
timestamp can therefore never remain artificially fresh by being far in the
future.

System JSON responses have an 8 MiB browser-side streaming limit, including
chunked responses without a declared length. The same shared reader enforces
4 MiB for live configuration and 8 MiB for draft responses. Crossing a limit
cancels the response stream before parsing. Health and collector diagnostic
details contain 1–256 characters and reject ASCII controls.

`/events/recent` currently exposes at most 60 structured GUI-core control-plane
and backend-job state transitions. Messages are generated from a fixed vocabulary and validated
for length and control characters in the browser client. The capability response
distinguishes these events from the unavailable Smithproxy event ring. Smithproxy
event text must only be added through a bounded authenticated HTTP API; the GUI
core does not parse the administrative CLI.

`/alerts` exposes at most 16 active, structured GUI-core conditions. Alert IDs,
severity, titles, and details come from a fixed server vocabulary; arbitrary
upstream log text is never forwarded. The current rules cover control-plane
reachability and rolling availability, collector health and freshness, and TLS
cache capacity. Disabling local explicit-proxy destination protection emits a
configuration-posture warning. A latest configuration-refresh timeout emits a
warning until a newer refresh succeeds. A control-plane outage suppresses
derivative collector alerts to avoid an alert storm.

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
události typu `operational`. Event ID i `source_revision` přiděluje jednotný
monotónní ring GUI core, takže nejsou závislé na systémovém čase ani na pořadí
jednotlivých collectorů. Ring slučuje změny control-plane stavu a terminální
stavy redigovaných backend úloh; nevkládá job ID, revize ani konfigurační hodnoty
do zprávy. Pokud ID již není v omezeném šedesátipoložkovém okně nebo core mezitím
restartoval, server pošle událost `reset` s autoritativním snapshotem. Prázdná
kontinuita vrací SSE keepalive. Klient každý payload znovu validuje stejnými
limity jako REST snapshot a při nevalidním payloadu stream uzavře.

Každý event obsahuje strukturované `category` (`control-plane` nebo
`backend-job`) a stabilní `code`. Browser přijme pouze reviewovaný trojčlenný
vztah `code` → category/severity/message; libovolný nebo vzájemně rozporný text
odmítne. Logs proto může bezpečně filtrovat zdroje bez heuristik nad message.

Server vrací `retry: 2500`, `Cache-Control: no-store` a `X-Accel-Buffering: no`.
Spojení je po každé dávce uzavřeno; standardní `EventSource` jej obnoví bez
držení backendového workeru pro neaktivní záložku. Periodický `/events/recent`
zůstává recovery snapshotem a cestou kompatibility pro starší core. Cursor má
nejvýše 96 bytů; delší `Last-Event-ID` je odmítnuto před porovnáváním.

Monitoring eviduje čas posledního otevření EventSource, posledního validovaného
payloadu, posledního přerušení a počet reconnect pokusů. Stav `live` vznikne až
po přijetí validního snapshotu nebo eventu, nikoliv samotným otevřením TCP/SSE.
Nevalidní payload stream uzavře a přejde do terminálního stavu `invalid`; další
pokus vyžaduje explicitní akci operátora. REST recovery snapshot zůstává
diagnostikován odděleně, takže jeho úspěch nemůže zamaskovat vadný stream.

## Úlohy

```http
GET  /api/v1/jobs
GET  /api/v1/jobs/{job-id}
```

Aktuální implementace publikuje omezenou in-memory historii nejvýše 128 úloh
`config-refresh`. Úloha vznikne až po úspěšném atomickém commitu a skončí teprve,
když monitorovaný autoritativní snapshot dosáhne revize z commit receipt; po
deadline skončí jako `failed`. Seznam ani detail neobsahuje cílovou revizi,
konfigurační hodnoty nebo credentials. Vlastník je zatím poctivě `null`, protože
gateway kontrakt neposkytuje reviewovanou identitu uživatele.

Terminální stav vstupuje také do jednotného operational event ringu. Poslední
neúspěšný `config-refresh` aktivuje strukturovaný warning; warning se uzavře až
novějším úspěšným refreshem, nikoli pouhým zahájením retry.

Aktuální `config-refresh` používá uzavřený stavový automat. Browser přijme pouze
reviewované kombinace state/phase/progress/result a pevné výsledky
`Configuration snapshot synchronized` nebo
`Configuration refresh deadline exceeded`. Volný upstream text, neznámou fázi,
budoucí timestamp a předčasně inzerovaný lifecycle stav odmítne celý snapshot.
Průběh ani fáze běžící úlohy při dočasném zhoršení monitoru neregresují.

`POST /api/v1/jobs/{job-id}/cancel` zůstává rezervovanou budoucí capability.
`config-refresh` bezpečné zrušení nepodporuje a proto vždy vrací
`cancelable: false`; neimplementovaný endpoint není inzerován v API surface.

Budoucí obecný job kontrakt počítá minimálně se stavy:

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
`request.invalid_path`, `request.invalid_host`, `events.invalid_cursor`, `draft.version_conflict`,
`draft.change_rejected` a `draft.invalid_request`. Neznámá bezpečně zpracovaná
chyba používá `request.failed`. `fields` a `details` zůstávají prázdné, dokud
konkrétní endpoint nemá schválené strukturované detaily.
