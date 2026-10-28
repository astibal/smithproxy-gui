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

- striktní CSP bez `unsafe-inline` a `unsafe-eval`;
- žádné vykreslování neověřeného HTML;
- bezpečné odkazy a downloady;
- ochrana proti clickjackingu;
- immutable cache pro fingerprinted assets, `no-store` pro citlivá data;
- dependency pinning, lockfile, SBOM a kontrola licencí.

Saslik theme runtime musí zůstat kompatibilní se striktní CSP. Import palet je
omezen velikostí, schema validací a pouze hex barevnými hodnotami.

## Config a secrets

- secrets jsou write-only/redigované;
- audit nesmí obsahovat secrets, tokeny ani citlivé payloady;
- export diagnostiky používá explicitní allowlist;
- validace cest a identifikátorů neumožní filesystem traversal;
- commit vyžaduje aktuální revision a kontrolu oprávnění v okamžiku commitu.

## Audit

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
