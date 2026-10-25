# PR #975 — Fix the integration picker's glued classes that lit every card's check

**Author:** timujinne · **Merged:** 2026-10-23 (6457fe4c9) · **Reviewer:** Claude

## Summary

`"w-5 h-5" <> "text-primary"` produced `w-5 h-5text-primary`, so neither colour class applied and the check inherited its colour for every card; the status
badge had the same missing space (`...hiddenbadge-success`). Both are now written as class lists / complete strings.

Verdict: correct; the test renders the picker and asserts the class tokens.

## Findings

- None. Looked for the same `"..." <> status_class` shape elsewhere under `lib/phoenix_kit_web/components`; no other glued class remains.
