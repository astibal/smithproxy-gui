# Smithproxy GUI

Modern administration and monitoring interface for Smithproxy.

The GUI communicates with Smithproxy exclusively through a versioned API. It
does not read configuration files or runtime data directly.

[Czech version](README_CZ.md)

## Approved principles

- responsive, accessible, and themeable UI;
- compatibility with the Saslik appearance contract v1;
- primary navigation on the left, a contextual top bar, and a bottom status bar;
- editors open from the right and cover 75–80% of the workspace;
- nested edits form an overlapping chain of editor cards;
- all related changes belong to one shared draft;
- server-side validation, impact preview, and atomic commits;
- full Smithproxy configuration coverage, including persistent and effective
  values and augments;
- first-class monitoring, security, and extensive automated testing.

## Documentation

The detailed design documents are currently maintained as internal Czech
documentation:

- [Architecture](docs/ARCHITECTURE.md)
- [UX and information architecture](docs/UX.md)
- [Configuration, drafts, and augments](docs/CONFIG_AND_AUGMENTS.md)
- [API contract](docs/API_CONTRACT.md)
- [Security](docs/SECURITY.md)
- [Testing strategy](docs/TESTING.md)
- [Change and review process](docs/CHANGE_PROCESS.md)

## Development

Node.js 22.12 or newer and pnpm 11.25 are required.

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
pnpm test:unit
pnpm test:e2e
```

The backend requires C++23, CMake, pkg-config, libcurl, libmicrohttpd, and
nlohmann-json 3.11 or newer. Initialize the repository and build the production
frontend and backend with:

```sh
git submodule update --init
pnpm build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target smithproxy-gui
ctest --test-dir build --output-on-failure
./build/smithproxy-gui --help
```

The backend reads Smithproxy access exclusively from its process environment:

```text
SMITHPROXY_API_URL=https://127.0.0.1:55555
SMITHPROXY_API_KEY=...
SMITHPROXY_CA_CERT=/path/to/ca-cert.pem
```

The variables must be provided together. The API key is never accepted through
command-line arguments, exposed to the browser, or written to logs. For a
deployment behind the Saslik gateway, use a base path such as
`--base-path /ws001/smithproxy-gui/`.

The configuration editor currently uses a fake API while the versioned
Smithproxy configuration contract is being completed. Control-plane health and
listener monitoring already use the production C++ backend and the authenticated
Smithproxy API. Live session monitoring is aggregated by transport inside the GUI
core; endpoint addresses, ports, session identifiers, and policy names are never
sent to the browser. The root web component supports integration into Saslik Tools:

```html
<smithproxy-gui
  mode="embedded"
  base-path="/tools/smithproxy"
  api-base="/tools/smithproxy/api/v1">
</smithproxy-gui>
```

Configuration drafts, authentication adapters, and the remaining monitoring
surfaces are delivered as independently tested vertical slices.

When served behind Saslik, the page loads the canonical `/saslik-theme.css` and
`/saslik-theme.js` assets with the `smithproxy-gui` application scope. Standalone
deployments retain the built-in Petroleum fallback when those shared assets are
not available.
