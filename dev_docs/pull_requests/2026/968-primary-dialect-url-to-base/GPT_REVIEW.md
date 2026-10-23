# PR #968 — Canonical dialect URLs

**Author:** timujinne · **Merged:** 2026-10-22 (`6cdb4e531`) · **Reviewer:** GPT

Independent recheck of the merge and Claude's review at `a9fa57de0`.

## Findings

- **BUG - MEDIUM (fixed):** Live navigation from a sibling dialect to its bare base
  retained the sibling: `/es-mx/blog` → `/es/blog` kept `current_locale: "es-MX"`
  rather than resolving the canonical base to `es-ES`. Returning to a prefixless
  primary URL had the same problem. The lifecycle compared only the base, which
  is identical for both dialects. A fresh HTTP request resolved correctly, so live
  navigation and a reload could show different per-language content at one URL.
  The base branch now resolves its full dialect, and the prefixless branch compares
  the full resolved dialect. Both update the request locale used by content.
  This is an adjacent pre-existing lifecycle defect exposed by checking the PR's
  new canonical URLs; the new full-dialect branch itself was correct.

Added integration regressions for sibling → base and sibling → prefixless primary
navigation. Both regressions fail against the original `Auth` module, each retaining
`es-MX` where `es-ES` is expected; both pass with the fix. Also checked the ownership
rule when core/content disagree, explicit
URL emission, disabled languages, case-insensitive sibling recognition, forwarded
mounts, query preservation and the method-preserving redirect for posted forms.

## Validation

Validation results are recorded with the companion [gallery review](../965-gallery-mode/GPT_REVIEW.md).
