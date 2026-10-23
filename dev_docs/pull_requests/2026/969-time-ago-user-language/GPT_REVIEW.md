# PR #969 — Translated relative times

**Author:** timujinne · **Merged:** 2026-10-22 (`4926ba5d8`) · **Reviewer:** GPT

Independent recheck of the merge and Claude's review at `a9fa57de0`.

## Findings

No additional defect found. The component renders through the core Gettext backend,
uses plural-aware entries for every relative-time unit, treats naive datetimes as
UTC and builds the tooltip with the cached site timezone. Removing the English-only
client hook prevents the connected browser from overwriting translated text.

Checked callers, datetime markup/id behavior, translated catalog entries and the
site-zone rollover tests. Render-time text and future timestamps clamped to zero
are explicit existing limitations, already documented by Claude and the PR. No new
timer or future-tense translation feature is introduced in this review.

## Validation

Validation results are recorded with the companion [gallery review](../965-gallery-mode/GPT_REVIEW.md).
