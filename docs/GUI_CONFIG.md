# GUI bootstrap configuration

`gui.cfg` uses the GUI bootstrap schema but remains a Smithproxy-core-owned
resource in the active CFtar. In a native deployment Smithproxy reads the
resource, exposes a read-only runtime copy for the GUI backend, and starts it
with:

```text
smithproxy-gui --config /run/smithproxy-gui/gui.cfg
```

The GUI never modifies this file or the archive directly. An administrator
changes it through Smithproxy's CFG API; Smithproxy validates and publishes the
new archive atomically.

The **System → Access & integrations → GUI service** editor reads this resource
through the authenticated Smithproxy archive API. Publishing from that editor
uses the running revision and current archive SHA-256 as atomic preconditions;
administrator verifier changes are activated in the running GUI immediately;
other boot settings take effect only after a controlled service restart.
The Smithproxy connection and trusted browser-gateway groups are independently
optional and can be explicitly enabled or removed. Opening the editor preserves
an absent group instead of silently materializing deployment credentials.
When `gui.cfg` does not exist yet, a core-bootstrapped loopback GUI can create the
first resource through this same core API. The initial document contains no
administrator verifier; the first privilege-15 CLI enrollment is enabled only
after the resource is published and can be read back authoritatively.

```libconfig
gui = {
  schema_version = 3;

  backend = {
    bind_address = "127.0.0.1";
    port = 18082;
    base_path = "/smithproxy-gui";
  };

  # Optional. Omit to use assets installed beside the executable.
  frontend = {
    asset_root = "/usr/share/smithproxy-gui";
  };

  smithproxy = {
    api_url = "https://127.0.0.1:55555";
    ca_cert = "/run/smithproxy-gui/api-ca.pem";
    api_token_file = "/run/credentials/smithproxy-gui.api-token";
    cli_endpoint = "127.0.0.1:50000";
  };

  gateway = {
    secret_file = "/run/credentials/smithproxy-gui.gateway";
    # Optional bounded overlap while a trusted gateway rotates its credential.
    previous_secret_file = "/run/credentials/smithproxy-gui.gateway.previous";
  };

  # Passwords are never stored. Each entry contains only a bounded scrypt
  # verifier created after a one-time CLI enrollment token is accepted.
  administrators = (
    {
      name = "security-admin";
      algorithm = "scrypt";
      salt = "0123456789abcdef0123456789abcdef";
      verifier = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      cost = 32768L;
      block_size = 8;
      parallelism = 1;
    }
  );
};
```

Version 1 remains readable for installations without persistent administrators;
the administrator list requires version 2 and the optional frontend asset override
requires version 3. Unknown settings and unsupported
schema versions are rejected. This prevents
an older GUI from publishing a replacement that silently drops fields owned by
a newer GUI schema. A legacy file without `schema_version` is read as version 1;
the next typed publication writes the version explicitly.

The referenced credential files are boot-time material, must be owned by the
GUI service account, and must have mode `0600`. A trailing newline is accepted.
The persistent archive contains only their locations. This layout permits a
dedicated GUI API token to be replaced for every boot without rewriting CFtar.

At native startup Smithproxy generates one high-entropy credential, registers
it as a runtime-only archive-capable API key, and writes the same value into two
separately owned `0600` runtime files. It resolves the GUI file location from
`smithproxy.api_token_file`, loads its own copy without adding the value to a
persistent API-key snapshot, and only then starts the GUI backend. Both files
are replaced at the next Smithproxy start and the old credential is absent from
the new runtime authorization set. A token from an earlier boot therefore
cannot authorize a new Smithproxy process.

The two-file handoff is intentional: Smithproxy and the GUI may run under
different service accounts, and neither process needs permission to read the
other account's credential file. A deployment must not place the token itself
in `gui.cfg`, a command-line option, or a shared environment file.
The API-token file and both trusted-gateway credential files must also be
distinct. They authenticate different trust boundaries and are rejected when a
single configured path attempts to collapse those identities.

Command-line options remain explicit deployment overrides. Existing environment
variables and an external service launcher remain available for compatibility;
their secret values are removed from the process environment immediately after
bootstrap. The native owner is Smithproxy core: it materializes `gui.cfg`, issues
the boot credential, and starts the GUI. The GUI is never a sibling service that
independently owns persistent startup state.

Administrator passwords and enrollment tokens are never represented here. The
CLI creates a single-use token valid for ten minutes. After Smithproxy consumes
it atomically, the GUI derives and publishes only the salted scrypt verifier
through the core archive API. Successful authentication produces an eight-hour
HttpOnly, Secure, SameSite=Strict runtime session; it never turns the password or
enrollment token into a persistent API key. A logged-in standalone administrator
may consume another named CLI enrollment token from the GUI service card to add
a peer or rotate an existing peer's password. The token's administrator identity
selects create or rotation; arbitrary browser-supplied names are never trusted.
This publishes and activates the new verifier immediately, then revokes every
older session for that identity. A self-rotation receives one replacement
browser session; a peer rotation leaves the acting administrator's session
unchanged. Restart only reconciles the already-active verifier with persistent
startup state.
The service card also supports a confirmed removal of a peer administrator.
The active account and the final remaining account cannot be removed; this
prevents both immediate self-lockout and an administrator-free next boot.
Successful removal immediately revokes that identity's runtime sessions and
blocks new logins for the rest of the current boot. A controlled restart then
loads the reduced persistent administrator set from `gui.cfg`.

Before consuming an enrollment token, the GUI verifies that `gui.cfg`, the
archive inventory, and the running configuration revision are all available.
A failed readiness check therefore leaves the one-time token usable. Failures
after consumption require a new token; making consumption and publication one
cross-process atomic operation requires a future reserve/commit capability in
the Smithproxy core API.
