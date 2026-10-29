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

Smithproxy advertises the contract through a separate authenticated endpoint:

```text
GET /api/config/v2/capabilities
```

```json
{
  "success": {
    "transaction_version": 1,
    "operation_version": 1,
    "stable_entity_ids": true,
    "operations": ["set", "create", "delete", "move"],
    "maximum_operations": 4096,
    "maximum_request_bytes": 1048576,
    "collections": [
      {"id": "policy", "ordered": true, "nested": false, "schema_revision": "sha256:..."},
      {"id": "address_objects", "ordered": false, "nested": false, "schema_revision": "sha256:..."},
      {"id": "content_profiles.content_rules", "ordered": true, "nested": true, "schema_revision": "sha256:..."}
    ]
  }
}
```

The GUI core treats missing fields, unknown versions, duplicated collection IDs,
zero limits, or an unrecognized schema revision as no transaction capability.
Advertised maxima are always clamped to the GUI core's lower hard bounds. The
browser receives only normalized GUI-core feature flags; it never calls this
Smithproxy endpoint or sees the Smithproxy credential. Capability discovery is
advisory and every transaction request is still checked again under the
configuration lock.

## Canonical snapshot revision

The GUI must obtain the same canonical persistent revision used by the
transaction lock. The proposed authenticated endpoint is:

```text
GET /api/config/v2/revision
```

```json
{
  "success": {
    "revision": "sha256:..."
  }
}
```

The response contains exactly one lowercase SHA-256 revision and no
configuration values. While the legacy configuration reader still retrieves
multiple sections, the GUI reads this endpoint immediately before and after
the section batch. It accepts a revision-bound snapshot only when both values
are identical. A missing endpoint permits a read-only legacy snapshot with no
revision; a malformed, oversized, or changing advertised revision fails the
snapshot closed. A future single-request snapshot endpoint may replace this
bracketing protocol while preserving the same revision semantics.

The endpoint accepts both validation and commit requests:

```json
{
  "mode": "validate",
  "base_revision": "sha256:...",
  "idempotency_key": "018f...",
  "operations": [
    {"op": "set", "path": "policy.[0].action", "value": "reject"},
    {"op": "set", "path": "tls_profiles.[0].inspect", "value": true}
  ]
}
```

`mode` is either `validate` or `commit`. A validation request performs every
parse, schema, reference, and runtime preflight check without changing persistent
or effective state. A commit request repeats validation under the configuration
lock; a previous validation result is advisory only.

## Operation model

The first reviewed version supports four explicit operations. It does not infer
creation or deletion from magic scalar values and does not accept arbitrary JSON
Patch pointers.

### Scalar update

```json
{"op": "set", "path": "policy.[0].action", "value": "reject"}
```

The path is one of the schema identifiers advertised for the exact Smithproxy
version. The value must match that node's type, limits, sensitivity, and augment
rules. A set operation always targets persistent configuration; it never writes
an augment layer implicitly. Every set path is resolved and bound against the
locked base snapshot before structural operations run, so an earlier create,
delete, or move cannot silently retarget a later index-based path.

### Create an entity

```json
{
  "op": "create",
  "collection": "address_objects",
  "client_id": "new-office-network",
  "position": {"last": true},
  "fields": {"name": "office-net", "type": "cidr", "value": "192.0.2.0/24"}
}
```

`collection` is a stable collection schema identifier, not a libconfig path.
`client_id` is unique inside one request and allows later operations in the same
transaction to refer to the new entity as `client:new-office-network`. `fields`
must contain the complete required typed payload for that collection; unknown,
missing, read-only, or duplicate fields reject the entire transaction.
Client IDs contain 1–64 ASCII alphanumeric, dot, underscore, or hyphen
characters, begin with an alphanumeric character, and never become persistent
entity IDs.

Nested collections additionally require an opaque `parent_id`. For example a
new content rule names `content_profiles.content_rules` as its collection and
the containing content profile as its parent. The server never guesses a parent
from an array index.

### Delete an entity

```json
{
  "op": "delete",
  "collection": "address_objects",
  "entity_id": "cfg:address:7f2a...",
  "if_referenced": "reject"
}
```

The initial contract supports only `reject`; implicit cascade and dangling
references are forbidden. A rejection returns bounded dependency identifiers
and schema paths, never secret values. Deleting a parent and its children still
requires explicit delete operations so the audit record is complete.

### Reorder an entity

```json
{
  "op": "move",
  "collection": "policy",
  "entity_id": "cfg:policy:91bd...",
  "position": {"before": "cfg:policy:130a..."}
}
```

Only collections advertised as ordered accept `move`. A position contains
exactly one of `first`, `last`, `before`, or `after`. The target must belong to
the same collection and parent and cannot be the entity being moved.

## Stable identity and ordering

Every entity returned by the configuration snapshot receives an opaque,
snapshot-scoped ID. The transaction capability must explicitly advertise
`stable_entity_ids: true`; the GUI must not enable create, delete, or move from
its current index-derived display IDs. An entity ID is valid only with the
`base_revision` that produced it and must not encode a secret, filesystem path,
or mutable display name.

The server resolves all existing entity IDs against the locked base snapshot
before applying any operation. It then applies operations in request order to
one private clone. Client IDs become addressable immediately after their create
operation. Duplicate mutation of the same structural target, use-before-create,
ambiguous placement, deletion followed by use, and cyclic placement all reject
the complete transaction.

Creation, deletion, and movement participate in the same reference validation,
impact preview, idempotency, persistence, activation, and rollback guarantees as
scalar updates. No structural operation is committed separately.

The GUI core already models these operations in its versioned workspace draft
and serializes them into the same atomic transaction envelope as scalar updates.
It keeps the HTTP and UI entry points disabled until Smithproxy advertises a
reviewed schema for the affected collection and stable entity IDs for the base
revision. This prevents an index-derived or partially validated structural edit
from reaching the control plane.

## Required guarantees

1. Compare `base_revision` under the configuration lock. Return `409` before any
   mutation if it differs from the current persistent revision.
2. Apply every operation to a complete private configuration clone. Paths,
   collections, identities, positions, fields, and values are schema-validated
   and type-checked; arbitrary libconfig traversal is not accepted.
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
8. Bound the request to 4,096 operations, 1 MiB decoded content, 256 fields or
   array members per operation, 128 create client IDs per transaction, and the
   existing per-value schema limits.

## Success response

```json
{
  "success": {
    "revision": "sha256:...",
    "previous_revision": "sha256:...",
    "validated_operations": 2,
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
    "operation": 3,
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
A commit coordinator retains the same key across an uncertain retry; the
transport never silently substitutes a new key. Its move-only RAII lease rejects
parallel commits and local mutations while an attempt is in flight. Draft
finalization checks the version again and advances its base revision under one
lock, so a concurrent local edit is never erased by a delayed response. The
GUI additionally records a local monotonic barrier at successful finalization;
a configuration read started before that barrier cannot restore the old base
revision when it completes. The commit button remains unavailable until
Smithproxy advertises this capability.
Structural controls additionally remain unavailable until the capability reports
the matching operation version, stable entity IDs, and the relevant collection
schema. A generic `config_write` boolean is not sufficient evidence.
