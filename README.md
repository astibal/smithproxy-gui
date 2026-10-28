# Smithproxy GUI

Moderní administrační a monitorovací rozhraní pro Smithproxy.

GUI komunikuje se Smithproxy výhradně přes verzované API; konfigurační soubory
ani runtime data nečte napřímo.

## Schválené principy

- responzivní, přístupné a themovatelné UI;
- kompatibilita se Saslik appearance contract v1;
- levá hlavní navigace, kontextový horní panel a spodní stavová lišta;
- editace v kartách vysouvaných zprava přes 75–80 % pracovní plochy;
- vnořené editace tvoří překrývající se řetěz karet;
- všechny související změny patří do společného draftu;
- serverová validace, impact preview a atomický commit;
- celý Smithproxy config včetně persistentních a efektivních hodnot a augmentů;
- prvotřídní monitoring, bezpečnost a rozsáhlé automatické testování.

## Dokumentace

- [Architektura](docs/ARCHITECTURE.md)
- [UX a informační architektura](docs/UX.md)
- [Config, drafty a augments](docs/CONFIG_AND_AUGMENTS.md)
- [Návrh API](docs/API_CONTRACT.md)
- [Bezpečnost](docs/SECURITY.md)
- [Testovací strategie](docs/TESTING.md)
- [Proces změn a review](docs/CHANGE_PROCESS.md)

## Vývoj

Požadován je Node.js 22.12 nebo novější a pnpm 11.25.

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
pnpm test:unit
pnpm test:e2e
```

Backend vyžaduje C++23, CMake, pkg-config, libmicrohttpd a libcurl. Výchozí
CMake build vytvoří frontend i výsledný proces:

```sh
git submodule update --init
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/smithproxy-gui --help
```

Proces čte přístup ke Smithproxy pouze z prostředí:

```text
SMITHPROXY_API_URL=https://127.0.0.1:55555
SMITHPROXY_API_KEY=...
SMITHPROXY_CA_CERT=/path/to/ca-cert.pem
```

Proměnné se nastavují společně. Klíč se nepředává přes argumenty, neposílá se
do prohlížeče a neloguje se. Pro nasazení za Saslik gateway použij například
`--base-path /ws001/smithproxy-gui/`.

První vertikální řez používá fake config API a ukazuje standalone i embeddable
aplikační shell. Kořenová web componenta podporuje integraci do Saslik Tools:

```html
<smithproxy-gui
  mode="embedded"
  base-path="/tools/smithproxy"
  api-base="/tools/smithproxy/api/v1">
</smithproxy-gui>
```

Produkční API klient, autentizační adapter a distribuce Saslik theme assetů budou
samostatné reviewované řezy.
