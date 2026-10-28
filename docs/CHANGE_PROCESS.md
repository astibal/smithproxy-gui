# Proces změn a review

## Existující zdrojové kódy

Jakákoli změna existujícího zdrojového kódu Smithproxy, Saslik, Spider nebo jiné
navázané aplikace vyžaduje předem:

1. popis problému a zamýšlené změny;
2. schválení myšlenky;
3. implementaci v izolované větvi nebo worktree;
4. review konkrétního diffu;
5. teprve poté commit/merge podle pokynu.

Rozšíření Smithproxy API je podporovaná cesta, ale podléhá stejnému procesu.

## Smithproxy GUI

Práce bude dělena na malé vertikální řezy. Před každým řezem se schválí:

- uživatelský scénář;
- API a bezpečnostní hranice;
- soubory/repozitáře, kterých se změna dotkne;
- testovací a rollback plán.

## Jazyk

- zdrojový kód, komentáře, názvy symbolů a commit zprávy jsou anglicky;
- designové dokumenty a kontrakty mohou být česky;
- uživatelské texty se připravují na lokalizaci.

## Commit formát

```text
feature: short description

- lower-case detail
- another detail
- testing and documentation notes when applicable
```

## Stav návrhu

Tento dokumentační balík neautorizuje změny existujících projektů ani rozšíření
Smithproxy API. Každá taková změna dostane samostatný návrh a review.
