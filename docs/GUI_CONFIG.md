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

```libconfig
gui = {
  backend = {
    bind_address = "127.0.0.1";
    port = 18082;
    base_path = "/smithproxy-gui";
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
};
```

The referenced credential files are boot-time material, must be owned by the
GUI service account, and must have mode `0600`. A trailing newline is accepted.
The persistent archive contains only their locations. This permits Smithproxy to
mint a new dedicated GUI API token for every boot without rewriting CFtar.

Command-line options remain explicit deployment overrides. Existing environment
variables remain available for compatibility, but a native installation should
prefer `gui.cfg` plus protected runtime credential files.

Administrator identities and initial-token enrollment are intentionally not
represented as plaintext secrets here. Their final schema must be coupled to the
Smithproxy CLI issuer and the GUI session verifier: the CLI creates a single-use,
short-lived enrollment token, Smithproxy stores only its verifier through CFG
API, and the GUI exchanges it for an HttpOnly, Secure, SameSite=Strict session.
Until that complete path exists, `gui.cfg` must not contain administrator tokens.
