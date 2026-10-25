# PR #982 — Fix the avatar crop editor freezing after the first move of a drag

**Author:** alexdont · **Merged:** 2026-10-24 (fd1acec41) · **Reviewer:** Claude

## Summary

`AvatarCrop`'s `pointermove` replaced the drag state with `{x, y}`, dropping the
frame's `w`/`h` that the next move divides by: from the second move on the focal
point became `NaN` and the picture froze. The PR rewrites the hook's gestures
around two helpers, `_zoomAt(clientX, clientY, zoom)` and `_panBy(dx, dy, rect)`:
one pointer pans, two pinch about their midpoint, the wheel zooms toward the
cursor in proportion to its delta (`ctrlKey` = trackpad pinch), the slider zooms
about the frame's centre. Only `priv/static/assets/phoenix_kit.js` changes; the
stored/pushed crop (`x`, `y`, `zoom`, `ar`) and `avatarCropLayout` are untouched,
so saved avatars render as before.

Verdict: correct. No defects found; one coverage gap closed after merge.

Checked:

- **`_zoomAt` keeps the point under the cursor fixed.** With `u = (px − left) / width`
  taken before the zoom, the new focal is `(50 − (px − u·width')) / width'`, i.e.
  `left' = px − u·width'` — then `clampAvatarCropFocal` as everywhere else. At the
  frame centre this reduces to the old "zoom about the focal point".
- **Pointer bookkeeping.** `pointercancel` is wired to the up handler, so a
  cancelled touch is removed from `pointers`; `startGesture` is re-run on every
  down/up, so lifting one finger mid-pinch hands over to a one-pointer pan with a
  fresh `last` (no jump). Non-primary mouse buttons are ignored. The push happens
  once, when the last pointer lifts.
- **Touch.** The frame already carries `touch-none` (`user_settings.ex`), so the
  browser does not scroll or zoom the page during a pinch; `preventDefault` on
  `pointerdown` is consistent with that.
- **Wheel.** `deltaMode` 1/2 (lines/pages) are scaled to pixels; the debounced
  push and the Save-button flush are unchanged.
- **`setPointerCapture` in `try`.** It throws for a pointer that is no longer
  active (a synthetic or already-ended pointer); guarding it is right.

## Post-merge

- **IMPROVEMENT - MEDIUM (fixed):** nothing locked the regression in —
  `test/js/avatar_crop.test.cjs` only covered the pure layout helpers. Added three
  hook-level tests that mount the real hook on a stub frame: a three-move drag
  (each move pans by the expected 1/40 of the image, one push at the end), the
  wheel keeping the image point under the cursor fixed, and a pinch that doubles
  the zoom followed by a one-finger pan after the other lifts. All three fail on
  the pre-PR bundle (7e8106461) and pass on main.

## Not changed

- **NITPICK:** during a pinch `_panBy` and `_zoomAt` each call `_render`, two style
  writes per move. Harmless (same frame, no layout read between them); not worth
  splitting the helpers for.
