# PR #709 — Point the editor bundle at the leaf release we actually resolve

**Reviewed:** 2026-08-13 · **Author:** @alexdont · **Verdict:** merged unchanged.

## Summary

Bumps `LEAF_CDN` in `priv/static/assets/phoenix_kit.js` from `v0.3.2` to `v0.5.1`
and adds `test/phoenix_kit_web/leaf_bundle_pin_test.exs` to hold the tag and the
resolved hex version together.

Small, correct, and the test is the part that matters — the bump alone would drift
again on the next `mix deps.update`.

## Verified

- `mix.lock` resolves `leaf 0.5.1`; `mix.exs:183` pins `{:leaf, "~> 0.4.1 or ~> 0.5"}`.
  The new tag matches the lock, so the test passes on the merge commit.
- The stale comment the PR replaces did name `{:leaf, "~> 0.3"}` against a `mix.exs`
  that had already moved on — the drift it describes is real, not reconstructed.
- `mix deps.update --all` during this sweep produced **no lock change**, so leaf
  stayed at 0.5.1 and the new test still passes post-update.

## The test's design is the right one

Comparing against `Application.spec(:leaf, :vsn)` rather than a hardcoded string
makes the lock the source of truth, which is what stops this recurring. The
second assertion (exactly one pin) and third (the loader still probes
`LeafHooks`) guard the two ways the check could quietly stop guarding anything —
a second copy of the URL, or the mechanism moving out from under it.

The stated asymmetry is the strongest argument in the PR and it is correct:
leaf's own `data-leaf-js-version` mismatch warning arrived in 0.4.0, so a bundle
old enough to matter cannot fire it. A check at the point where the pin is
written is the only place that works.

## One consequence worth stating plainly

This test makes `mix deps.update --all` able to fail the suite: a leaf release
bumps the lock, and the CDN pin must then be updated by hand — including
verifying the new tag actually resolves on jsDelivr before pushing. That is the
intended trade and the right one, but it is now a step in the release flow rather
than an automatic bump. Noted here so the next sweep does not read the failure as
a regression.

## Not changed

Nothing. No findings.

The PR's "nothing else in core needs to catch up" section was spot-checked rather
than re-derived — `CommentsForwarding` does forward only `{:leaf_changed, _}`,
and `Settings.get_editor_mode/0` does return the four-atom set the component
accepts.
