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

Provozní položky ve stavové liště používají stejné severity barvy jako monitoring
a slouží jako zkratky do detailu. Na úzkém viewportu zůstává viditelný pouze
stav GUI core a Smithproxy; fronta úloh se zobrazí až s reálným backend API.

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
