# UX a informační architektura

## Hlavní rozložení

```text
┌──────────────┬─────────────────────────────────────────────────────────┐
│ Smithproxy   │ kontext, filtry, hledání, globální akce                │
├──────────────┼─────────────────────────────────────────────────────────┤
│ Dashboard    │                                                         │
│ Network      │                    pracovní plocha                      │
│ Objects      │                                                         │
│ Policy       │                                                         │
│ Monitoring   │                                                         │
│ Logs         │                                                         │
│ System       │                                                         │
├──────────────┴─────────────────────────────────────────────────────────┤
│ core/proxy │ alerts │ probe freshness │ event stream │ config/draft │
└────────────────────────────────────────────────────────────────────────┘
```

Navigace je záměrně doménová, ne kopií struktury konfiguračního souboru.
Konkrétní položky se mohou během coverage mapování změnit.

Globální hledání pokrývá všechny čitelné konfigurační entity včetně policy,
objektů, profilů, content rules, certifikačních autorit, signatur, System a
Captures. Používá pending hodnoty ze sdíleného draftu a výsledek otevře přímo
ve správné kartě řetězce. Write-only hodnoty se neindexují ani nezobrazují.

Provozní položky ve stavové liště používají stejné severity barvy jako monitoring
a slouží jako zkratky do detailu. Na úzkém viewportu zůstává viditelný pouze
stav GUI core a Smithproxy; fronta úloh se zobrazí až s reálným backend API.

Monitoring rozlišuje stav SSE transportu od dostupnosti periodického recovery
snapshotu. Ukazuje poslední otevření spojení, poslední validovaný payload,
poslední přerušení a počet reconnectů. Nevalidní stream se sám bez vědomí
operátora znovu neaktivuje; explicitní retry je přímo v transportní kartě.

## Drawer chain

První editor se vysune zprava přes přibližně 75–80 % pracovní plochy. Seznam
zůstane částečně viditelný jako kontext. Editor využívá téměř celou výšku mezi
horním panelem a stavovou lištou.

```text
list
  └─ policy editor
       └─ address object editor
            └─ referenced object editor
```

Další editor překryje většinu předchozí karty. Předchozí karta zůstane viditelná
úzkým levým okrajem s názvem. Při hlubším řetězení se starší úrovně sloučí do
breadcrumbů, aby se aktivní editor nezmenšoval.

### Pravidla editoru

- sticky hlavička s typem, názvem, stavem draftu a zavřením;
- sticky patička s validací a akcemi;
- skupiny polí používají více sloupců tam, kde je to čitelné;
- dlouhé pokročilé sekce jsou sbalitelné;
- interní scroll vzniká až při skutečně delším obsahu;
- focus mode může editor roztáhnout přes celou pracovní plochu;
- znovu otevřený editor načte běžné pending hodnoty ze sdíleného draftu;
- write-only hodnoty zůstávají redigované a editor je nikdy nerehydratuje;
- každý známý řádek review otevře přímo odpovídající editor nebo vnořený editor;
- referenční pole průběžně rozlišují známé otevíratelné objekty od literálů nebo
  nerozpoznaných názvů; upozornění neblokuje legitimní Smithproxy výraz;
- editor umí po explicitním potvrzení atomicky odebrat všechny své draft změny;
- policy a object listy i globální hledání používají pending hodnoty; listy je
  označují výrazným `Pending` badge;
- `Esc` zavře aktuální úroveň až po vyřešení neuložených změn;
- browser Back a opuštění stránky používají stejnou ochranu rozepsaných změn;
- stav řetězce je reprezentován v URL a lze jej obnovit po reloadu.

## Sdílené objekty a dopad změny

Editor sdíleného objektu vždy ukáže známá použití a před uložením impact preview:

```text
⚠ address object office-net používají:
  3 policies · 1 routing rule

  [Zobrazit dopad]                         [Uložit do draftu]
```

## Responzivita

- desktop: levá navigace, pracovní plocha a překrývající se drawery;
- menší notebook: kompaktní navigace a větší relativní šířka editoru;
- tablet/mobil: editor jako celá obrazovka, breadcrumb místo viditelných hran;
- stavová lišta se na úzké obrazovce redukuje na nejdůležitější indikátory.

## Vložení do Saslik Tools

V embedded režimu Saslik vlastní globální navigaci, autentizaci a vnější stránku.
Smithproxy GUI si ponechá svou doménovou navigaci a drawer chain uvnitř přidělené
pracovní plochy. Samostatný a vložený režim používají stejné komponenty, stavové
modely a testovací scénáře; liší se pouze hostitelským adaptérem a rámcem stránky.

## Přístupnost

- ovládání celé aplikace z klávesnice;
- správný focus trap pouze v aktivním draweru;
- návrat focusu na prvek, který drawer otevřel;
- čitelné popisky, chybové souhrny a `aria-live` pro stav úloh;
- respektování `prefers-reduced-motion`;
- minimálně WCAG 2.2 AA pro kontrast a interakce.

## Saslik appearance contract v1

GUI používá přímo distribuované `saslik-theme.css`, `saslik-theme.js` a
`saslik-palettes.json` s `data-app="smithproxy-gui"`. Komponenty používají
kanonické proměnné `--st-*`, včetně stavových a grafových barev. Nevznikne druhý
paletový systém.

Typografie, rozměry, spacing a density zatím nejsou součástí Saslik palet a
zůstávají lokálními design tokeny GUI.
