# PR #715 Phase 1 Review — phoenix_kit
**Title:** Adopt etcher 0.12.0 and hold every vendored CDN pin to its lock
**Author:** Sasha Don (alexdont)
**Verdict:** APPROVE

---

## Summary

This PR fixes a silent CDN drift bug that had been accumulating across three sibling libraries. The etcher hex dep sat at 0.11.0 in the lock (itself already one behind the top), while the CDN lazy-loader in `phoenix_kit.js` was still serving `v0.9.0` — three minor versions behind. Fresco and tessera had the same problem (pins at v0.10.0 and v0.3.1 respectively, while the lock had already pulled 0.11.0 and 0.3.5). Only leaf was clean from PR #709.

The fix is correct on all fronts: lock bumped, all four CDN pins aligned, and the single-library test (`leaf_bundle_pin_test.exs`) generalized into `vendored_cdn_pins_test.exs` which covers every `gh/` pin and adds a coverage enforcement test that fails if a future pin appears without a corresponding entry.

`mix.exs` has `{:etcher, "~> 0.9"}` — semver-compatible with 0.12.0, no constraint change needed.

---

## Findings

### Blockers
_None._

### Non-blockers

1. **No SRI integrity attributes on lazy-loader URLs** — The JS lazy-loaders pin by jsDelivr `@tag` rather than `integrity="sha384-..."`. This is the established pattern in this codebase (leaf, fresco, tessera all the same) and acceptable given the test enforcement. Worth noting for a future supply-chain hardening pass, but not a blocker here.

2. **Hardcoded `alexdont/` org prefix in `@pinned` regex** — If any of these libraries ever migrates to a different GitHub org, the regex in `vendored_cdn_pins_test.exs` silently stops matching and the pin test passes vacuously (because `pins_for/1` returns `[]` and the coverage test would catch it via the uncovered-pins assertion). The coverage test would catch a brand-new pin, but not a renamed one. Low risk given org stability; mention to Sasha.

3. **No CHANGELOG / user-facing release note** — PR description correctly omits `@version` (this is a dependency maintenance fix, not a phoenix_kit feature). However, the tldraw-parity round in etcher 0.12.0 (selection rework, born-selected shapes, click-to-place, shape clipboard) was silently absent from all hosts until this lands. If a release of phoenix_kit is cut after this merges, the release notes should surface these features as now working, not as new in that release.

### Nitpicks

- The updated comment on the ETCHER_CDN loader (`"This pin must name the release hex resolved — test/phoenix_kit_web/vendored_cdn_pins_test.exs holds every gh/ pin..."`) is accurate and better than the old comment. No change needed.
- Commit attribution line references Claude Code session URL — consistent with other PRs, fine.

---

## Stats

| Item | Detail |
|------|--------|
| Changed files | 4 |
| Additions | 118 |
| Deletions | 71 |
| Tests | `leaf_bundle_pin_test.exs` deleted (61 lines); `vendored_cdn_pins_test.exs` added (105 lines) — net +44 lines, +3 tests (4 per-pin tests + 2 structural vs. old 3) |
| Migrations | None |
| Version bump | No `@version` change in phoenix_kit; etcher bumped 0.11.0 → 0.12.0 in mix.lock |
| Dependency changes | `mix.lock`: etcher 0.11.0 → 0.12.0 (hash updated). mix.exs unchanged (`~> 0.9` covers it). fresco/tessera lock versions already correct — only CDN pins updated. |
| Suite | Green (`mix precommit` exits 0 per PR description) |
| CDN pins after merge | leaf v0.5.1 ✓, fresco v0.11.0 ✓, tessera v0.3.5 ✓, etcher v0.12.0 ✓ |

---

## Decision

Clean fix with solid test coverage. The generalization from leaf-only to all-pins is the right structural move and the coverage enforcement test closes the re-opening hole. Approve as-is; non-blockers can be addressed in follow-up or at release note time.
