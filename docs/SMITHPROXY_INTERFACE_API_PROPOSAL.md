# Smithproxy interface diagnostics API

Status: implemented.

## Context

Smithproxy exposes its immutable interface snapshot through the authenticated
diagnostic API. GUI core validates and bounds that response before publishing an
administrator-facing same-origin representation. It never invokes or parses
privileged CLI output.

## Endpoint

```http
GET /api/diag/network/interfaces
Authorization: existing Smithproxy API authentication
Accept: application/json
```

The endpoint is read-only and returns one coherent monitor snapshot:

```json
{
  "schema_version": 1,
  "state": "ready",
  "generation": 42,
  "sampled_at_unix_ms": 1793239515319,
  "synchronization": {
    "running": true,
    "attempts": 2,
    "successes": 2,
    "errors": 0,
    "event_datagrams": 15,
    "changed_event_datagrams": 4
  },
  "totals": {
    "interfaces": 1,
    "addresses": 1,
    "ipv4_addresses": 1,
    "ipv6_addresses": 0
  },
  "snapshot_valid": true,
  "roles_valid": true,
  "route_generation": 8,
  "role_generation": 3,
  "route_changed_at": "2026-11-12T10:00:00Z",
  "role_changed_at": "2026-11-12T10:00:01Z",
  "interfaces": [
    {
      "ifindex": 2,
      "name": "lan0",
      "role": "Inside",
      "flags": 69699,
      "uplink": false,
      "addresses": [{
        "family": "IPv4",
        "address": "192.0.2.10",
        "prefix_length": 24,
        "scope": 0,
        "flags": 128
      }]
    }
  ],
  "last_error": "",
  "last_error_code": null
}
```

`state` is one of `starting`, `ready`, `degraded`, or `unavailable`.
`last_error_code` is a bounded stable diagnostic code while `last_error` retains
the concrete administrator-facing diagnostic. Counters are unsigned 64-bit values serialized as JSON integers while
they remain within the exact JSON integer range; an implementation must return
an explicit overflow error rather than a rounded value.

## Administrator boundary

Interface names, indexes, roles, addresses, flags, generations, and diagnostics
are intentionally available to authenticated administrators. GUI core exposes
only fields supplied by the typed Smithproxy snapshot; it does not augment them
from the host filesystem, operating-system commands, DNS, or CLI output.

## Operational guarantees

1. Authentication and authorization match the other Smithproxy management API
   endpoints and fail closed.
2. The response is generated from a single immutable `InterfaceSnapshot` plus
   one statistics sample. It must not combine values collected across a retry.
3. GUI core bounds the detailed response to 256 KiB and serves its browser API
   with `Cache-Control: no-store`.
4. The handler does not initiate a netlink synchronization, block on the monitor
   thread, or expose administrative CLI output.
5. Malformed or incoherent inventory data is rejected as unavailable rather than
   partially displayed.

## GUI-core integration

The browser calls only GUI core at `/api/v1/network/interfaces/summary`. GUI core
polls Smithproxy with its existing server-side credential, validates every field
and bound, and publishes the aggregate counters plus concrete inventory. If the
Smithproxy endpoint is absent, GUI core reports `not-advertised`; there is no CLI
or filesystem fallback.
