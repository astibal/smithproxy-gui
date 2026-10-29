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
- testy SSE snapshot/replay/reset, konfliktů revision a obnovy draftu.

CI spouští celý Playwright scénář nad Chromium, Firefox a WebKit. Lokální
vývojový příkaz používá pro rychlost Chromium; shodný tříbrowserový matrix se
zapíná proměnnou `PLAYWRIGHT_ALL_BROWSERS=1`.
CI záměrně nepoužívá retry a zapisuje detail každého browserového pádu přímo do
GitHub check annotations, aby platformní rozdíl nemohl zůstat skrytý za obecným
exit kódem. Při pádu navíc na sedm dní uloží Playwright trace a případné
expected/actual/diff obrázky jako `playwright-diagnostics` artifact.

Chromium pixel gate drží deset baseline obrázků: dashboard a vnořený policy →
address editor pro Grill/Petroleum v dark/light režimu a mobilní policy layout
pro oba Petroleum režimy. Fixture používá tokeny canonical Saslik appearance
contractu v1, fixní UTC locale, device scale, reduced motion a deterministický
čas. Firefox a WebKit zůstávají behaviorální a WCAG gate; pixelové baseline jsou
záměrně vázané na jediný renderer a Linux runner.

Axe automaticky kontroluje WCAG A/AA pravidla na dashboardu, policy listu,
prvním i vnořeném editoru a mobilním layoutu. Nález se opravuje v UI; test
neobsahuje výjimky ani vypnutá pravidla.

Browser matrix také simuluje souběžného zapisujícího správce. Po `409` konfliktu
musí GUI načíst novou verzi sdíleného draftu, zachovat cizí změny a další pokus
odeslat s aktualizovanou optimistic-concurrency verzí.

Gateway rotační scénáře zpožďují monitoring a live config odpovědi přes okamžik
odebrání přístupu. Pozdní odpověď nesmí obnovit agregáty, snapshot, draft ani
otevřený editor z předchozí access epochy. Unit testy navíc dokazují abort všech
probíhajících requestů v system, config a draft klientech; samostatný browser
scénář ověřuje odebrání draft capability při zachování read-only live configu.
Capability contract testy odmítají nekanonický nebo cizí workspace mount,
neznámou API verzi a nemožné závislosti transaction, draft a event příznaků ještě
před prvním chráněným requestem. Browser testy zároveň rozlišují platný omezený
kontrakt ve stavu `ready` od nekonzistentního grafu ve stavu `unavailable` a
ověřují bezpečný obsah lokálního diagnostického exportu.
Augment contract testy pokrývají scalar i homogenní listové hodnoty, prázdné
listy, maximální délku, typovou shodu a hlubokou shodu aktivní a efektivní
hodnoty. Browser test navíc zkouší DOM tampering listového policy fieldu a
ověřuje, že nevznikne žádný draft request.

Shared bounded-JSON testy dělí vícebajtové UTF-8 mezi chunky, překračují limit
bez `Content-Length`, ověřují aktivní zrušení streamu a odmítají chybnou délku,
UTF-8 i JSON. System klient navíc testuje deklarovaný oversize payload a
neomezený nebo control-bearing diagnostický text.

Backend integration suite ověřuje SSE content type, zákaz proxy bufferingu,
management autentizaci, počáteční snapshot, `Last-Event-ID` replay bez duplikace
a reset expirované kontinuity. Frontend unit testy ověřují workspace prefix,
snapshot i jednotlivou událost a fail-closed chování při nevalidním JSON payloadu.
Browser scénář navíc podá strukturálně platný, ale nereviewovaný event, ověří
terminální stav `invalid`, absenci jeho textu v DOM a úspěšné obnovení až po
explicitním retry. Live cesta kontroluje čas posledního validovaného payloadu a
allowlisted transportní údaje v diagnostickém exportu.

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

Jednotlivé odebrání draft změny je testováno přes browser klienta, HTTP boundary
i workspace review UI včetně stale-version konfliktu a value-free auditu.

Deterministický robustness corpus mutuje validní JSON obálky, libovolné bajtové
payloady, schema cesty a všechny podporované varianty draft hodnot. Každý běh
prochází všemi produkčními snapshot parsery a draft validátorem. CI jej spouští
pod ASan/UBSan a navíc ověřuje, že odmítnutá draft mutace nezmění verzi ani počet
uložených změn. Seed je fixní, takže každý nález je reprodukovatelný.

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
