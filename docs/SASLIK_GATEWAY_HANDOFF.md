# Saslik trusted gateway handoff proposal

## Current gap

Saslik authenticates the `/wsNNN/smithproxy-gui/` nginx location, but the
workspace proxy currently forwards no backend-verifiable identity. The GUI
environment allowlist contains only the Smithproxy URL, API key, and CA path.
Consequently, a strict non-loopback GUI core correctly refuses to start when
pulled into the current workspace deployment.

## Minimal reviewed change

The proposed Saslik patch is deliberately limited to `gateway.py`,
`components.py`, and their tests:

1. Generate a dedicated random Smithproxy GUI gateway secret. Do not reuse the
   Saslik control-plane `X-Saslik-Gateway` value.
2. Store it in the Saslik gateway runtime directory with mode `0600`, using an
   atomic replacement and strict length/character validation.
3. In the authenticated Smithproxy GUI nginx location, overwrite
   `X-Smithproxy-GUI-Gateway` with that secret. Client input with the same header
   must never pass through.
4. Add `SMITHPROXY_GUI_GATEWAY_SECRET` to the root-owned, mode-`0600`
   `smithproxy-gui.env` allowlist. Values must not appear in argv, logs, status
   output, diagnostics, or bundles.
5. Preserve the secret across ordinary Saslik and nginx restarts. Rotation is an
   explicit operation, not a side effect of reload.

## Rotation sequence

The GUI accepts one optional previous secret so ingress and backend do not need
to switch in the same instant:

```text
GUI env: current=new, previous=old
               │ restart GUI
               ▼
nginx header: old ───────────────► new
                                      │ verified traffic
                                      ▼
GUI env: current=new, previous removed
```

The overlap is bounded to exactly two validated values. Rollback reverses the
same sequence. Health remains unauthenticated and contains only bounded
orchestration state; all management endpoints remain fail-closed.

## Browser diagnostics

The bounded `/api/v1/auth/session` response reports only `gateway` or `disabled`
mode and whether the current request passed the handoff. It never returns a
secret, identity, header value, or reason derived from credentials. The System
view shows disabled, rejected, and verified states and refreshes the result every
30 seconds and immediately after browser connectivity or visibility recovery.

The browser accepts privileged configuration and draft capabilities only when
the same refresh also reports an authenticated gateway session. A contradictory
or malformed pair of responses disables every privileged capability. This is a
defense-in-depth UI boundary; the GUI core remains authoritative on every
request.

## Required review evidence

- unit tests prove the secret file is `0600`, narrow, atomically replaced, and
  absent from commands and logs;
- nginx tests prove the GUI location overwrites the header after successful
  `auth_request` and no other upstream receives it;
- component tests prove the GUI environment contains current and, only during
  rotation, previous values;
- an integration test proves missing, incorrect, current, and previous secrets
  produce `401`, `401`, `200`, and `200` respectively;
- restart and rotation tests prove no persistent unauthenticated interval.
