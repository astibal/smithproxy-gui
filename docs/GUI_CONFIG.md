# GUI bootstrap configuration

`gui.cfg` is a GUI-owned resource in the active Smithproxy CFtar. Smithproxy (or
its service launcher) exposes a read-only copy for the GUI backend and starts it
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

A deployment that rotates the credential per boot generates one high-entropy
token before starting either process and writes the same value into two
separately owned `0600` runtime files. Smithproxy receives the path to its copy through
`SMITHPROXY_GUI_API_KEY_FILE`; the GUI receives the path to its copy through the
`smithproxy.api_token_file` setting above. Smithproxy loads this credential as
an archive-capable API key because the GUI publishes `gui.cfg`, removes the
environment variable immediately, and never adds the value to persistent API
key snapshots. The files are replaced on the next coordinated start, so a token
from an earlier boot no longer authorizes the new Smithproxy process.

The two-file handoff is intentional: Smithproxy and the GUI may run under
different service accounts, and neither process needs permission to read the
other account's credential file. A deployment must not place the token itself
in `gui.cfg`, a command-line option, or a shared environment file.

Command-line options remain explicit deployment overrides. Existing environment
variables remain available for compatibility, but a native installation should
prefer `gui.cfg` plus protected runtime credential files.

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
