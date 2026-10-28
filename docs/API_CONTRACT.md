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
SNI bypass entries, content rules, session filters, and identity mappings are
reduced to explicit configured flags or counts before crossing the browser
boundary. Stable IDs and derived reverse references support nested drawers.

The system-settings posture covers listener admission, fail-open behavior,
worker pools, TLS autodetection, kernel TLS, HTTP API access, and webhooks. API
keys, addresses, nameservers, webhook URLs, and identity values are never
serialized; only bounded counts and configured flags are exposed.

Capture posture includes local format and quota, remote tunnel mode and TTL,
and checksum behavior. Capture directories, filename components, tunnel
destinations, and bind interfaces are reduced to configured flags.

Trust and signature posture covers configured TLS certificate-authority entries,
STARTTLS signatures, detection signatures, and their aggregate flow-step counts.
Certificate paths, signature names, categories, groups, engines, expressions,
and match windows remain inside the GUI core and are never serialized.

The snapshot carries `augment_support` and a bounded `value_origins` collection.
Each origin identifies a stable schema path, persistent and effective scalar
values, editability, and an ordered augment layer chain with optional priorities.
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
numbers, strings, and bounded string arrays. Every mutation requires the trusted
gateway handoff, an exact same-origin `Origin`, `Sec-Fetch-Site: same-origin` when the
browser supplies it, JSON content type, and `X-Smithproxy-GUI-CSRF: 1`. The
custom header and absent CORS support prevent cross-origin form submission.
Requests are limited to 64 KiB, the accumulated draft payload is limited to
1 MiB, paths and values are bounded, and an expected draft version is mandatory;
stale writers receive HTTP 409. The browser also rejects draft responses above
8 MiB before JSON parsing, leaving room for worst-case JSON escaping of the
bounded raw draft. This store is not yet a commit path and cannot mutate
Smithproxy configuration.

The first browser integration atomically persists `policy.[n].name`,
`policy.[n].disabled`, `policy.[n].dst`, and `policy.[n].action` through this
endpoint. Nested editors use the same draft and version to persist the mapped
name, type, value, range, and numeric identifier fields of address, port, and
protocol objects. Routing profile batches cover their name, destination address
and port references, load-balancing method, and paired SNI rewrite values while
preserving nested links to the referenced objects. Detection and DNS ALG profile
batches cover their names and all currently exposed typed mode/boolean fields.
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
GET /api/v1/logs
GET /api/v1/events
```

`/sessions/activity` is intentionally aggregate-only. The GUI core groups live
sessions by transport and exposes counts, throughput, and byte counters. Endpoint
addresses, ports, session identifiers, and matched policy names do not cross the
browser boundary. A future detailed session surface requires an explicit privacy
and authorization design.

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

`/events` používá SSE. Každá událost obsahuje typ, čas serveru, monotónní event ID,
source revision a minimální payload. Po ztrátě kontinuity si klient vyžádá nový
snapshot místo domýšlení chybějícího stavu.

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
