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

Konkrétní procentní prahy se stanoví po prvním vertikálním řezu. Povinné od
začátku jsou nulové ignorované schema uzly, nulové známé kritické bezpečnostní
nálezy, průchod contract testů a test klíčové editace přes celý stack.
