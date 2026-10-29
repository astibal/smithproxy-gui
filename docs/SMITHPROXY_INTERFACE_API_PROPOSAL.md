# Smithproxy interface diagnostics API proposal

Status: proposal for review. This document does not authorize or contain changes
to the Smithproxy repository.

## Context

Smithproxy revision `e545e616d1172fa1a4715a36fc7b31e7f88dd771` exposes
interface-monitor state through the privileged administrative command
`diag system netlink info`. The GUI must not invoke or parse that command. A
bounded authenticated HTTP endpoint is required before interface health can
become a live monitoring surface.

## Endpoint

```http
GET /api/v1/network/interfaces/summary
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
    "interfaces": 3,
    "addresses": 5,
    "ipv4_addresses": 3,
    "ipv6_addresses": 2
  },
  "last_error": null
}
```

`state` is one of `starting`, `ready`, `degraded`, or `unavailable`.
`last_error` is a bounded stable diagnostic code, not raw kernel or exception
text. Counters are unsigned 64-bit values serialized as JSON integers while
they remain within the exact JSON integer range; an implementation must return
an explicit overflow error rather than a rounded value.

## Privacy boundary

The summary endpoint intentionally omits:

- interface names and indexes;
- IP and link-layer addresses;
- network namespaces;
- route, neighbor, and DNS data;
- raw netlink flags or kernel error text.

These values are unnecessary for health monitoring and can disclose deployment
topology. A future administrator-only inventory endpoint needs separate review,
authorization, pagination, and address-redaction rules.

## Operational guarantees

1. Authentication and authorization match the other Smithproxy management API
   endpoints and fail closed.
2. The response is generated from a single immutable `InterfaceSnapshot` plus
   one statistics sample. It must not combine values collected across a retry.
3. The response body is bounded to 8 KiB and uses `Cache-Control: no-store`.
4. The handler does not initiate a netlink synchronization, block on the monitor
   thread, or expose administrative CLI output.
5. `503` represents an unavailable snapshot; malformed internal state returns a
   stable `500` error envelope and emits an audit event.
6. Capability discovery advertises the exact endpoint and schema version. The
   GUI does not infer support from the Smithproxy version.

## GUI-core integration

The browser continues to call only the same-origin GUI core. When Smithproxy
advertises this capability, the core polls it with the existing server-side
credential, validates every field and bound, and publishes a privacy-preserving
same-origin summary. Until then, the same-origin summary reports
`not-advertised` and no CLI or filesystem fallback is permitted.

The GUI-core parser, bounded same-origin endpoint, diagnostics allowlist, and
management-authenticated browser surface implement this proposed schema. Existing
Smithproxy deployments return `not-advertised`; the GUI retains no fallback and
does not interpret administrative command output.
