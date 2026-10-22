# PR #965 — Gallery mode for the media viewer

**Author:** alexdont · **Merged:** 2026-10-22 (61abfef3f) · **Reviewer:** Claude

## Summary

`MediaBrowser` gains `gallery_mode` (on for the full-page media view): a `ViewerGallery` hook drives `Fresco.gallery` (swipe / drag / trackpad / arrow
keys slide between pictures, controls stay put, tap hides them), names the settled file back with a new `gallery_go` event, and the server opens it.
`gallery_items_json/2` feeds the hook a ±12 window of siblings. Bumps fresco 0.15, tessera 0.3.10, etcher 0.23; the Fresco canvas passes `pan_centre={:bounds}`.

Verdict: sound. `gallery_go` can only name a file of `viewer_siblings` (the list the viewer already steps through, already filtered for a restricted
viewer), and still passes the restricted-viewer / library guard clauses first, so it opens nothing `step_viewer` could not. No new URL is minted: the
window reuses the file's existing `urls`.

## Findings

- **BUG - MEDIUM (fixed):** `ViewerSwipe` stood down whenever a `ViewerGallery` element existed, but `ViewerGallery.mounted()` returns early when
  `Fresco.gallery` is missing (a host still serving an older `fresco.js` until `mix phoenix_kit.update`). On the media page the swipe then did
  nothing at all. The check now also requires `window.Fresco.gallery`. Locked in by `test/js/viewer_gallery_handoff.test.cjs`.
- **IMPROVEMENT - MEDIUM (fixed):** `gallery_go` re-announced the URL when it named the file already open. The hook deliberately re-asks every 2 s
  until the viewer follows, so a late re-ask produced a second `:navigate` echo. It is now a no-op for the open file.
- **IMPROVEMENT - MEDIUM (fixed):** no tests came with `gallery_go` or `gallery_items_json`. Added: `gallery_go` opens a sibling / ignores a stranger /
  ignores the open file (`media_browser_viewer_url_test.exs`), and the window, ends, large→medium→small fallback, burned copy, rotation and non-image card
  cases (`media_browser_gallery_items_test.exs`).
- **IMPROVEMENT - LOW (fixed):** the `mix.exs` comment block still said tessera 0.3.9 is the first to admit fresco 0.14 and gave no reason for the fresco
  0.15 / etcher 0.23 floors. Both now explain themselves (siblings' floors are load-bearing: an older one blocks resolving fresco 0.15).
- **NITPICK (not changed):** the tap-to-hide state sets `opacity: 0; pointer-events: none` on the close/sidebar/arrow buttons but leaves them focusable,
  so Tab lands on an invisible control. Esc / arrow keys still work; fixing it needs `visibility` handling inside the CSS the hook injects.
- **NITPICK (not changed):** the grid/controls CSS keys on `:has()`; a browser without it keeps the dot grid and the always-visible controls — a
  graceful degradation, not a failure.
- **Not covered:** the ~370 lines of `ViewerGallery` (settle timers, chrome freeze/thaw) are browser-timing code with no unit seam; only the hand-off
  guard is tested. Needs a real browser pass before relying on it.
