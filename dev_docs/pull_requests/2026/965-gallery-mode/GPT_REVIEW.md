# PR #965 — Gallery mode

**Author:** alexdont · **Merged:** 2026-10-22 (`61abfef3f`) · **Reviewer:** GPT

Independent recheck of the merge and Claude's fixes at `a9fa57de0`. The existing
server-side sibling allowlist, library/viewer guards and duplicate navigation fix
remain sound. Additional problems below are fixed in this review.

## Findings

- **BUG - HIGH:** On a cold load, `ViewerGallery.mounted()` returned before the
  lazily fetched Fresco script arrived. It never retried. Once Fresco arrived,
  `ViewerSwipe` also stood down because the gallery hook element and library now
  existed, leaving swipe navigation inactive. The gallery now uses the shared
  `lazyHook`/Fresco loader, including its close-before-load protection. The swipe
  fallback yields only to an initialized gallery in its own modal.
- **BUG - MEDIUM:** Landing on a video, PDF or other file waited for a Fresco canvas
  that those previews never render. A filename card covered the real preview for
  eight seconds, with control copies potentially lingering another five seconds.
  The watcher now hands over as soon as LiveView's current file matches the settled
  non-image item, and immediately thaws its controls.
- **BUG - MEDIUM:** The queued image-paint animation callback could release the
  previous slide after another slide started, or restart a polling interval after
  the viewer was destroyed. It now checks that the same gallery still exists,
  remains shown and still displays the expected file before releasing or retrying.
- **IMPROVEMENT - MEDIUM:** Hidden controls remained keyboard-focusable, and cloned
  toolbar buttons added invisible, `aria-hidden` focus stops while a slide was up.
  Hidden controls now use `visibility: hidden`; visual copies are `inert`.

## Regression coverage

`test/js/viewer_gallery.test.cjs` drives the production hook and shared lazy wrapper
with a delayed loader and controllable timers: cold loading with updated data,
closing before load, settling only between gestures, video/PDF/file hand-off, and
stale paint callbacks after closure or another slide. The swipe hand-off tests now
distinguish an initialized gallery from markup awaiting initialization.

Chromium also exercised the production bundle with the real installed Fresco
gallery engine and delayed script loading: cold startup, arrow/button/pointer sliding,
sharp-image release, video hand-off, inert toolbar copies, hidden controls and
teardown. No browser errors. This harness simulates LiveView DOM patches; it does
not replace testing a deployed host's full upload/view/edit flow. The original
bundle reproduces the cold-start failure in the same browser harness.

## Validation

- `mix format` and `mix precommit`: passed (exit 0). Includes compilation with
  warnings as errors, test compilation, formatting, strict Credo, Dialyzer and all
  **473 JavaScript tests**.
- Eight focused Elixir suites against a separate PostgreSQL scratch database:
  **227 tests, 0 failures**, including the new locale regressions, approval gate,
  route helpers, relative times/site timezone, integration picker and gallery data/navigation.
- Chromium harness: passed as described above; original bundle fails cold startup.
- After fixing the additional #966 manifest hash finding: release-check suite
  **15 tests, 0 failures**; production-manifest integration suite **1 test, 0 failures**;
  restamping `--check` confirms the hash is current across all 86 migration files.
  `s7,s8` skip without the pre-squash generator artifact (see #966's review).
- Full repository suite at reviewed base `a9fa57de0`: **89 doctests, 12,390 tests,
  2 failures, 21 skipped, 1 excluded**. Both failures were the #966 manifest hash
  checks. After restamping, `PGPOOL=12 mix test --failed --max-cases 8` passes:
  **2 tests, 0 failures**. The full run started before editing; the focused suites
  above validate the final Elixir changes. PostgreSQL integration tests ran; the
  role's missing `CREATEROLE` privilege excludes its tagged test.
