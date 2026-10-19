# PR #927 — primary language and clean URLs

Reviewer: Codex · Date: 2026-10-13 · Status: reviewed and fixed, unreleased

Reviewed stored/fallback primary-language resolution, first enable, UI events,
URL helpers, HTTP and LiveView locale decisions, sitemap consumers, and Claude's
content-language-name fix.

## Findings

- **BUG - MEDIUM (fixed): full-dialect and invalid-locale POST redirects lost their bodies.**
  The new 307 path handled a recognized base code, but full dialects such as
  `en-US` reached the historical 302-to-base redirect first; invalid locales also
  took a 302 path. Single-language requests are now handled before dialect/base
  validation, redirect directly to the clean URL, and preserve every non-GET/HEAD
  method. Queries survive. Admin URLs with a recognized base or dialect render
  under the primary language as intended.
- **BUG - MEDIUM (fixed): the admin exemption used a literal segment anywhere in the path.**
  Renamed admin areas were redirected, while a public `/de/shop/admin/items`
  incorrectly bypassed canonicalization. The check now uses
  `Routes.admin_area_path?/1` on decoded, router-relative path segments. It keeps
  encoded admin segments and forwarded mounts compatible with route matching.

The three new integration tests failed against the reviewed commit. Coverage
includes POST/PUT/DELETE with dialect and invalid prefixes, preserved queries,
renamed/encoded admin paths, and public content containing an admin segment.
Existing multilingual redirect tests remain covered.

Claude's content-language fix preserves the unconfigured base code while finding
the full locale's display name. The compatibility distinction between configured
and assumed content-language codes is deliberate and tested.

## Follow-up — 2026-10-17

Simplified `process_locale/1`'s identical disabled-code and invalid-code
fallbacks into one branch. Both still call `redirect_invalid_locale/2`; the
enabled-code and single-language decisions retain their order. This reduces
the resolver's complexity without changing its redirect policy.

Validation: `mix precommit` passed, including 377 JavaScript tests. The full
PostgreSQL-backed repository run passed: 89 doctests, 11,270 tests, 0 failures,
10 skipped (1 excluded because the test role lacks `CREATEROLE`).
