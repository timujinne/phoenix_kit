# PR #715 — Adopt etcher 0.12.0 and hold every vendored CDN pin to its lock

- **Author:** Sasha Don (`alexdont`)
- **Merged:** 2026-08-14 as `ed72143d`
- **Reviewed:** 2026-08-14, post-merge, against `main`
- **Files:** `mix.lock`, `priv/static/assets/phoenix_kit.js`,
  `test/phoenix_kit_web/leaf_bundle_pin_test.exs` (deleted) →
  `test/phoenix_kit_web/vendored_cdn_pins_test.exs`

## Verdict: no findings. Nothing changed.

This is the right shape of fix for the class of bug it addresses. The previous round
(#709) fixed one instance — leaf's pin — and pinned it with a leaf-only test, leaving
the three sibling pins in the same file uncovered; all three had drifted. Generalizing
the test to every `gh/` pin, resolving the expected version from `Application.spec/2`
rather than a second hardcoded string, and adding a coverage assertion that fails when
a pin appears for a repo the test does not know about, closes the hole rather than the
instance. That last assertion is the part that matters: it is what stops #709 → #715
from happening a third time when a fifth sibling library is vendored.

Checked and found correct:

- **The three pin bumps match the lock.** `etcher` 0.11.0 → 0.12.0 in `mix.lock` with
  the pin moved to `v0.12.0`; `fresco` and `tessera` pins moved to versions the lock
  already resolved (`0.11.0`, `0.3.5`) — those two were pure pin drift, no dependency
  change, which is why `mix.lock` shows a single line changed.
- **`Application.spec(app, :vsn)` resolves at test time** for all four apps: each is a
  direct, non-optional dependency of this project, so it is loaded in `:test` and the
  spec is never `nil` (a `nil` would stringify to `""` and fail the assertion with a
  confusing `v` vs `v0.12.0` message rather than a missing-app one — worth knowing if a
  future sibling is ever added as `optional: true`).
- **The coverage test compares un-deduplicated sorted lists**, so a duplicated pin also
  fails it — and the per-app test independently asserts `[tag] = pins_for(app)`, i.e.
  exactly one pin per library. Both directions of drift (uncovered pin, removed pin)
  are named in the failure message.
- **The lazy-loader global probes** (`window.Etcher` &c.) are asserted, which is what
  makes the pins load-bearing: a loader that stopped probing would short-circuit and
  the pin would become dead text.
- **No `@version` or CHANGELOG change**, correctly — this ships as part of the next
  release, not as one.

Non-findings considered and rejected:

- The regexes escape `/` inside Elixir strings (`\/`), which is a no-op there. Harmless,
  and it keeps the four patterns visually identical to one another.
- The coverage test hardcodes the `alexdont` org when building the expected list. A
  sibling from another org would fail the assertion — which is the intended outcome
  (the test is meant to demand a decision when the pin set changes), and the failure
  message names the uncovered repo.
- Nothing verifies the pinned tag actually resolves on jsDelivr. Correct call: that is a
  network test and would be flaky. The PR body records the manual 200 + md5 check
  against each source repo, including the `v0.12.0` tag that had to be created for it.
