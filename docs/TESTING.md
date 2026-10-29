# Testovací strategie

## Cíl

Near-full coverage znamená měřit pokrytí kódu, API kontraktů, konfiguračního
schema, rolí, browserů a chybových stavů. Samotné procento line coverage nestačí.

## Testovací pyramida

```text
                    ┌──────────────┐
                    │ production   │
                    │ smoke/canary │
              ┌─────┴──────────────┴─────┐
              │ end-to-end + accessibility│
          ┌───┴───────────────────────────┴───┐
          │ API contract + component + visual │
      ┌───┴───────────────────────────────────┴───┐
      │ unit + property + fuzz + schema coverage │
      └───────────────────────────────────────────┘
```

## Frontend

- unit testy stavových modelů, validace a formátování;
- component testy drawer chainu, focusu a formulářů;
- Playwright pro Chromium, Firefox a WebKit;
- keyboard-only a accessibility testy;
- responsive testy definovaných breakpointů;
- visual regression pro Grill/Petroleum, dark/light a klíčové stavy;
- testy offline/stale SSE, konfliktů revision a obnovy draftu.

CI spouští celý Playwright scénář nad Chromium, Firefox a WebKit. Lokální
vývojový příkaz používá pro rychlost Chromium; shodný tříbrowserový matrix se
zapíná proměnnou `PLAYWRIGHT_ALL_BROWSERS=1`.

Unit coverage gate měří importovanou API, config, monitoring a state logiku přes
V8. Aktuální nepodkročitelné globální prahy jsou 83 % statements, 82 % branches,
94 % functions a 88 % lines. Prahy jsou baseline proti regresi, nikoliv tvrzení,
že samy o sobě dokazují near-full coverage; browser, C++ a schema matice zůstávají
samostatnými povinnými důkazy.

## Backend a API

- unit testy autentizace, autorizace, limitů a normalizace;
- contract testy proti OpenAPI/schema artefaktům;
- fake Smithproxy s deterministickými chybami a zpožděními;
- integrační testy se skutečným Smithproxy procesem;
- property testy patchů, diffů a referencí;
- fuzzing vstupních parserů a event streamu;
- restart/crash testy draftů, jobů a auditu.

## Config coverage

CI porovná aktuální Smithproxy schema manifest s registrem GUI editorů:

```text
schema node = specialized editor
           or approved generic editor
           or explicit unsupported failure
```

Tiché ignorování nového config uzlu je chyba buildu.

## Security matrix

Každý endpoint se testuje pro:

- nepřihlášeného klienta;
- každou roli;
- expirovanou a rotovanou session;
- chybějící/nesprávný CSRF údaj;
- nesprávný Origin;
- konfliktní revision;
- příliš velký, pomalý a syntakticky chybný request.

## Quality gates

Povinné jsou nepodkročení frontend coverage baseline, nulové ignorované schema
uzly, nulové známé kritické bezpečnostní nálezy, průchod contract testů a test
klíčové editace přes celý stack.
