# Smithproxy GUI

Moderní administrační a monitorovací rozhraní pro Smithproxy.

Prohlížeč komunikuje pouze s backendem GUI stejného originu. Backend může při
startu načíst GUI vlastní `gui.cfg` vystavený z aktivního CFtaru; všechny zápisy
konfigurace i runtime data nadále procházejí verzovaným API Smithproxy.

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

Produkční frontend a C++ backend se sestaví společně takto:

```sh
pnpm build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target smithproxy-gui
```

Při nativním nasazení zpřístupní Smithproxy core aktivní `gui.cfg` pouze pro
čtení a spustí backend s `--config`. V CFtaru jsou jen stabilní parametry služby
a cesty k chráněným runtime credentials; nikdy samotný živý API klíč nebo
gateway secret. Jediným zapisovatelem CFtaru zůstává Smithproxy core, i když
administrátor odešle typovanou změnu `gui.cfg` z GUI přes CFG/archive API.

Runtime credentials patří jednomu bootu. Launcher může pro každý společný start
Smithproxy a GUI vytvořit nový GUI API klíč, oběma procesům předat vlastní
owner-only kopii a restartem Smithproxy zneplatnit klíč z minulého bootu. GUI
svou kopii přečte právě jednou při startu a odvozenou upstream session drží jen
v paměti.

Backend vyžaduje C++23, CMake, pkg-config, libmicrohttpd a libcurl. Výchozí
CMake build vytvoří frontend i výsledný proces:

```sh
git submodule update --init
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
./build/smithproxy-gui --help
```

Následující proměnné zůstávají kompatibilním bootstrapem pro starší deploymenty
bez `gui.cfg`:

```text
SMITHPROXY_API_URL=https://127.0.0.1:55555
SMITHPROXY_API_KEY=...
SMITHPROXY_CA_CERT=/path/to/ca-cert.pem
SMITHPROXY_CLI=127.0.0.1:55000
```

Tři Smithproxy proměnné se nastavují společně a tajné hodnoty se po bootstrapu
okamžitě odstraní z prostředí. Klíč se nepředává přes argumenty, neposílá se
do prohlížeče, GUI jej nepersistuje a neloguje se. Pro nasazení za Saslik gateway použij například
`--base-path /ws001/smithproxy-gui/`.

Volitelná proměnná `SMITHPROXY_CLI` zpřístupní omezený WebSocket bridge k
existujícímu libcli2 brokeru. GUI core nespouští systémový shell ani samo
neinterpretuje CLI příkazy.

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
