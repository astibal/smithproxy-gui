# Smithproxy transactional configuration API proposal

Status: proposal for review. This document does not authorize or contain changes
to the Smithproxy repository.

## Why the existing endpoint is insufficient

`POST /api/config/uni/set` is useful for a single existing libconfig group, but
the GUI draft can span policies, objects, profiles, settings, and captures. A
sequence of calls would expose partially applied configuration and cannot safely
detect that another administrator changed the base configuration in between.

The GUI therefore must not implement commit as a loop over the existing endpoint.

## Endpoint

```text
POST /api/config/v2/transaction
Authorization: existing Smithproxy API authentication
Content-Type: application/json
```

The endpoint accepts both validation and commit requests:

```json
{
  "mode": "validate",
  "base_revision": "sha256:...",
  "idempotency_key": "018f...",
  "changes": [
    {"path": "policy.[0].action", "value": "reject"},
    {"path": "tls_profiles.[0].inspect", "value": true}
  ]
}
```

`mode` is either `validate` or `commit`. A validation request performs every
parse, schema, reference, and runtime preflight check without changing persistent
or effective state. A commit request repeats validation under the configuration
lock; a previous validation result is advisory only.

## Required guarantees

1. Compare `base_revision` under the configuration lock. Return `409` before any
   mutation if it differs from the current persistent revision.
2. Apply every change to a complete private configuration clone. Paths and values
   are schema-validated and type-checked; arbitrary libconfig traversal is not
   accepted.
3. Validate cross-section references and the complete resulting configuration.
4. Persist with the existing atomic write and backup mechanism before publishing
   the new revision.
5. Apply the validated snapshot to runtime as one logical operation. If runtime
   activation fails, restore the prior persistent snapshot and runtime state.
6. Return the same terminal result for repeated requests with the same
   `idempotency_key`; reject reuse with different content.
7. Never include configured secrets in requests generated from read snapshots,
   responses, diagnostics, or logs. Write-only secret changes require a separate
   opaque-value contract.
8. Bound the request to 4,096 changes, 1 MiB decoded content, 256 array members,
   and the existing per-value schema limits.

## Success response

```json
{
  "success": {
    "revision": "sha256:...",
    "previous_revision": "sha256:...",
    "validated_changes": 2,
    "restart": "not-required",
    "warnings": []
  }
}
```

The revision is derived from the canonical persistent configuration, not a
process-local counter. The GUI core compares it with the revision used to build
its draft and clears the draft only after a successful commit response.

## Error model

Errors use a stable machine code and a bounded human-readable message:

```json
{
  "error": {
    "code": "reference_missing",
    "message": "Policy 4 references missing TLS profile 'inspect'.",
    "path": "policy.[3].tls_profile",
    "current_revision": "sha256:..."
  }
}
```

Required status mappings include:

- `400`: malformed request, invalid path, type, value, or dependency;
- `401`/`403`: authentication or authorization failure;
- `409`: base revision conflict or idempotency conflict;
- `413`: request or value limit exceeded;
- `422`: valid syntax but configuration or runtime preflight failure;
- `500`: persistence, activation, or rollback failure.

Rollback failure is a distinct error code and must emit a high-severity audit
event. It must never be represented as success.

## Augment semantics

The transaction changes persistent values only. A response may describe that an
augment currently overrides the committed value, but it must not silently write
to an augment layer. Future augment editing uses an explicit target layer and its
own revision. Overlay chains remain ordered and expose persistent, effective,
and per-layer values without flattening provenance.

## GUI core integration

The browser continues to communicate only with the same-origin GUI core. The GUI
core owns the Smithproxy credential, generates the idempotency key, forwards the
bounded transaction, and redacts upstream details before returning a result.
The commit button remains unavailable until Smithproxy advertises this capability.

