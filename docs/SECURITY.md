# Bezpečnostní model

## Výchozí postoj

Management rozhraní je privilegovaný bezpečnostní povrch. Výchozí konfigurace
musí být uzavřená a vzdálený přístup se povoluje explicitně.

## Síť a transport

- loopback nebo Unix socket jako výchozí bind;
- TLS pro každý vzdálený TCP přístup;
- podpora mTLS mezi management backendem a Smithproxy API;
- přesná kontrola upstream identity, žádné tiché vypnutí TLS ověřování;
- omezené timeouty, velikosti requestů a souběžnost.

## Uživatelská session

- náhodný serverový session identifikátor;
- cookie `Secure`, `HttpOnly` a `SameSite=Strict`;
- žádné bearer tokeny v `localStorage`;
- ochrana proti CSRF a kontrola `Origin` u mutací;
- rotace session po autentizaci a změně oprávnění;
- krátká neaktivní i absolutní expirace pro privilegované role.

Konkrétní autentizační mechanismus bude zvolen podle deployment modelu. Podpora
externího identity proxy nesmí automaticky znamenat důvěru libovolným hlavičkám.

## Trusted gateway handoff

Sensitive browser-facing APIs are disabled unless
`SMITHPROXY_GUI_GATEWAY_SECRET` contains 32–256 safe header characters. A
trusted reverse proxy must remove every client-supplied
`X-Smithproxy-GUI-Gateway` header and inject the per-instance secret only after
successful user authentication. The secret is compared without an early exit,
is never returned to the browser, and must not be logged.

Missing or incorrect handoff credentials return HTTP 401 from every management
snapshot, event, alert, and draft endpoint when gateway mode is configured.
Capability discovery reports those feature flags as unavailable unless the
current request passed the same boundary. The minimal health endpoint remains
available for orchestration. A non-loopback listener is rejected at startup
unless gateway authentication is configured. Configuration reads and mutations
always require an authenticated gateway, including on loopback.

Gateway-secret rotation uses a bounded two-value overlap. The current value is
mandatory; `SMITHPROXY_GUI_GATEWAY_SECRET_PREVIOUS` is optional, independently
validated, and must differ. Both comparisons use the constant-time helper. A
deployment writes `current=new, previous=old`, restarts the GUI core, switches
the ingress to `new`, and then removes `previous` at the next restart.

Draft mutations additionally fail closed unless `Origin` exactly matches the
request host and the request carries JSON content type plus the custom
`X-Smithproxy-GUI-CSRF: 1` header. Optional Fetch Metadata must report
`same-origin`. The GUI core does not emit permissive CORS headers. These checks
are enforced independently of trusted-gateway authentication. Individual
requests are limited to 64 KiB, accumulated draft values to 1 MiB, and browser
responses to 8 MiB before parsing. Clearing a draft uses the same authentication,
CSRF, and optimistic-concurrency checks as an upsert.

## Oprávnění

Minimální role:

```text
viewer
operator
policy-editor
administrator
```

API kontroluje oprávnění na každém endpointu a citlivé operaci. Skrytí tlačítka
ve frontendu není bezpečnostní kontrola.

## Frontend

- scripts are restricted to same-origin resources without `unsafe-inline` or
  `unsafe-eval`; component styles currently require `style-src 'unsafe-inline'`;
- žádné vykreslování neověřeného HTML;
- bezpečné odkazy a downloady;
- ochrana proti clickjackingu;
- immutable cache pro fingerprinted assets, `no-store` pro citlivá data;
- dependency pinning, lockfile, SBOM a kontrola licencí.

Saslik theme runtime musí zůstat kompatibilní se striktní CSP. Import palet je
omezen velikostí, schema validací a pouze hex barevnými hodnotami.

Every response carries `nosniff`, `no-referrer`, same-origin framing and resource
and opener policy, origin-agent isolation, a deny-by-default browser Permissions
Policy, and a CSP that blocks objects, foreign connections, foreign frames, and
base-URL rewriting. API responses and the HTML entry point use `no-store`;
fingerprinted static assets are immutable. Production builds do not publish
JavaScript source maps. HSTS remains the responsibility of the Saslik TLS
terminator because the GUI core itself serves internal HTTP.

## Config a secrets

- secrets jsou write-only/redigované;
- write-only náhrady zůstávají pouze v serverovém draftu a draft API vrací jen
  redigovaný záměr `clear`/`replace`, případně bezpečný počet položek;
- audit nesmí obsahovat secrets, tokeny ani citlivé payloady;
- export diagnostiky používá explicitní allowlist;
- validace cest a identifikátorů neumožní filesystem traversal;
- commit vyžaduje aktuální revision a kontrolu oprávnění v okamžiku commitu.

## Audit

Všechny současné HTTP odpovědi dostávají korelační `X-Request-ID`; error envelope
obsahuje stejnou hodnotu a stabilní strojový kód. ID neobsahuje uživatelský vstup
a browser ho reflektuje jen po striktní syntaktické validaci. To poskytuje
bezpečnou korelaci provozních chyb ještě před zavedením persistentního audit logu.

Každá mutace zaznamená:

- identitu uživatele a session;
- čas a request ID;
- typ operace a cílové stabilní identifikátory;
- redigovaný normalizovaný diff;
- validační, commit a apply výsledek;
- související job a audit ID.

Auditní záznam nesmí být měnitelný přes běžné GUI API.

## Bezpečnostní testování

- threat model před prvním produkčním releasem;
- testy autorizace pro každý endpoint a roli;
- fuzzing parserů, patch operací a importovaných palet;
- negativní testy velikostí, timeoutů a vyčerpání zdrojů;
- SAST, dependency audit a secret scanning v CI;
- pravidelné manuální review management boundary.
