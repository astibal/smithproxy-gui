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

## Runtime a monitoring

```http
GET /api/v1/status
GET /api/v1/health
GET /api/v1/metrics/summary
GET /api/v1/listeners
GET /api/v1/sessions/activity
GET /api/v1/alerts
GET /api/v1/logs
GET /api/v1/events
```

`/sessions/activity` is intentionally aggregate-only. The GUI core groups live
sessions by transport and exposes counts, throughput, and byte counters. Endpoint
addresses, ports, session identifiers, and matched policy names do not cross the
browser boundary. A future detailed session surface requires an explicit privacy
and authorization design.

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
