# Architektura

## Cíle

Smithproxy GUI je samostatná management aplikace. Má pokrýt celý config,
monitoring, logy a dlouhotrvající backendové operace bez přímého přístupu ke
konfiguračním souborům Smithproxy.

```text
┌────────────────────── Browser ──────────────────────┐
│ TypeScript UI                                        │
│ navigation │ workspace │ drawer chain │ status bar │
└──────────────────── HTTPS + SSE ────────────────────┘
                            │
┌────────────── smithproxy-gui management ────────────┐
│ C++23 + lmhpp                                        │
│ static assets │ auth │ API client │ jobs │ audit    │
└────────────────── Smithproxy API ───────────────────┘
                            │
┌────────────────────── Smithproxy ───────────────────┐
│ schema │ config │ augments │ runtime │ events       │
└─────────────────────────────────────────────────────┘
```

## Frontend

Navržený stack:

- TypeScript;
- Vite pouze pro build a vývoj;
- Lit/Web Components jako lehká komponentová vrstva;
- statické produkční HTML, CSS a JavaScript;
- žádný Node.js runtime v produkci;
- Saslik appearance contract v1 jako jediný barevný kontrakt.

Finální volba Lit bude potvrzena samostatným proof-of-conceptem. Alternativou je
čistý TypeScript bez komponentového frameworku.

## Management backend

Preferovaný produkční backend je C++23 s `lmhpp`. Jeho odpovědnosti jsou omezené:

- bezpečně obsloužit statický frontend;
- ukončit uživatelskou session a vynutit RBAC;
- komunikovat se Smithproxy pouze přes jeho API;
- agregovat stav pro GUI, nikoli duplikovat Smithproxy business logiku;
- spravovat stav a historii dlouhých úloh;
- vytvářet auditní záznamy management operací.

Python/Flask je přípustný pro fake backend a izolované prototypy, nikoli jako
automatická produkční závislost.

## Komunikační model

- REST pro snapshoty, dotazy, validace a příkazy;
- SSE pro jednosměrné živé události a stav úloh;
- revision/ETag pro optimistic concurrency;
- idempotency key pro opakovatelné mutace;
- jasné limity velikosti, času a počtu položek.

WebSocket se přidá jen tehdy, pokud se prokáže potřeba plně duplexního kanálu.

## Deploy

Výchozí nasazení poslouchá pouze na loopbacku nebo Unix socketu. Vzdálené
nasazení vyžaduje TLS a explicitní autentizační konfiguraci. GUI a API mají být
pokud možno pod stejným originem.

## Integrace do Saslik Tools

Stejný frontendový build podporuje samostatný i vložený režim:

```text
standalone Smithproxy GUI
Saslik → Tools → Smithproxy GUI
```

Kořenová komponenta `<smithproxy-gui>` přijímá `mode`, `base-path` a `api-base`.
Nesmí předpokládat vlastnictví celé stránky, root URL ani samostatnou autentizaci.
Vložený režim převezme hostitelský auth adapter a navigační kontext Saslíka.
Shadow DOM izoluje komponentové styly, zatímco CSS custom properties Saslik
appearance contractu přirozeně procházejí do komponent.

Produkční assety musí fungovat pod konfigurovatelným URL prefixem. Routování,
odkazy ani API klient nesmí obsahovat natvrdo zapsaný `/` jako deployment root.

## Hranice změn

Chybějící schopnost Smithproxy se řeší verzovaným rozšířením Smithproxy API.
GUI nesmí obcházet API čtením souborů, CLI automatizací ani přímým přístupem do
interní paměti procesu.
