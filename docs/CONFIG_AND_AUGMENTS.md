# Config, drafty a augments

## Pohledy na konfiguraci

UI musí důsledně rozlišovat:

```text
persistent config
       │
       ├── augment layers
       ▼
effective config
```

U každé hodnoty musí být dostupné:

- persistentní hodnota;
- efektivní hodnota;
- původ efektivní hodnoty;
- aktivní augment a priorita vrstvy;
- informace, zda je hodnota editovatelná;
- validační pravidla a dokumentace;
- reference z ostatních objektů.

GUI nesmí ztratit informaci o původu tím, že efektivní config převede na obyčejný
anonymní JSON strom.

Aktuální frontend vykresluje obecnou provenance sekci ve všech typech editorů.
Podporuje seřazený řetěz více vrstev, hodnotu každé vrstvy, priority, explicitního
aktivního vlastníka, persistentní i efektivní hodnotu a příznak editovatelnosti.
Všechny typované scalar controls v policy, objektech, profilech, system/capture
nastavení a vnořených security/rule editorech se vážou přímo na persistentní
hodnotu a pole vlastněné aktivní vrstvou zobrazují pouze pro čtení. Centrální
draft pipeline navíc fail-closed odmítne změnu libovolné augment-owned cesty,
takže ochrana nezávisí na konkrétním rendereru ani na nezměněném DOM.

## Coverage model

Úplnost se měří proti strojově čitelnému schema manifestu Smithproxy. Každý uzel
má stabilní identifikátor, typ, omezení, citlivost, schopnosti a podporované akce.
Do doby, než upstream schema poskytne přímo Smithproxy API, je autoritativní
inventurou GUI soubor [`CONFIG_COVERAGE.json`](CONFIG_COVERAGE.json). Explicitně
rozlišuje plné, částečné, metadata-only a nepodporované sekce. Coverage test
hlídá, aby známá mezera nebyla omylem prezentována jako hotová podpora.

```text
schema node
├─ identity and path
├─ value type and constraints
├─ persistent/effective/augment capabilities
├─ secret and permission metadata
├─ references and reverse references
└─ documentation version
```

Generic schema editor může sloužit jako bezpečný fallback, ale důležité domény
dostanou specializované editory. Coverage test selže, pokud nový schema uzel nemá
ani specializovaný editor, ani explicitně schválený generic fallback.

## Společný draft

Všechny změny vzniklé v drawer chainu patří do jednoho serverem evidovaného draftu:

```text
open draft
   ↓
edit policy ── edit referenced address object
   ↓
validate draft
   ↓
impact preview + normalized diff
   ↓
atomic commit
   ↓
runtime apply/reload job
```

Draft obsahuje base revision. Pokud se persistentní config mezitím změní, server
commit odmítne jako konflikt a vrátí strukturovaný rozdíl. GUI nesmí změny tiše
rebasovat ani přepsat.

Aktuální foundation draft poskytuje serverový preflight bez hodnot: ověřenou
verzi draftu, počet změn, počet write-only změn a počty podle config sekcí.
Lokální schema validace je zobrazena odděleně od Smithproxy doménové validace.
Dokud upstream neposkytne schválené transaction API, preflight explicitně blokuje
commit; GUI nesmí lokální výsledek prezentovat jako validaci runtime aplikace.

## Validace

Validace má vrstvy:

1. okamžitá klientská validace podle schema;
2. autoritativní serverová strukturální a referenční validace;
3. doménová validace Smithproxy;
4. impact analýza;
5. preflight runtime schopností;
6. atomický commit a samostatně sledovaný apply job.

Neúspěšný apply nesmí být prezentován jako úspěšně dokončená změna. API musí
rozlišit persistentní commit, runtime apply a případný rollback/recovery stav.

## Tajné hodnoty

Secrets jsou write-only nebo redigované. API nikdy nevrací původní secret jako
běžnou hodnotu. Draft nese pouze informaci `unchanged`, `replace` nebo `remove`,
pokud je odstranění daným schema uzlem dovoleno.
