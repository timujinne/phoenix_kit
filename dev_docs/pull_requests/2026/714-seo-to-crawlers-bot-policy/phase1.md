# PR #714 Phase 1 Review — phoenix_kit

**Title:** Rename the built-in SEO module to Crawlers, and grow it into the bot-policy page
**Author:** Max Don (mdon)
**Verdict:** APPROVE WITH NOTES

---

## Summary

Renames `PhoenixKit.Modules.SEO` → `PhoenixKit.Modules.Crawlers` (module key `seo` → `crawlers`, settings `seo_module_enabled`/`seo_no_index` → `crawlers_*`), fixes a silent long-standing bug where the noindex meta never reached host app root layouts, and adds: per-bot-group access toggles, a generated robots.txt preview, llms.txt serving, search-engine verification metas, `CrawlerBlocker` plug, and a "Crawler Visibility" doctor check.

The rename motivation is sound: everything in the old SEO module was bot policy, the name was blocking the external `phoenix_kit_seo` package from claiming the natural `seo` module key.

The diff is large (131 files, +13141/-6110) because the PR is opened from `mdon:main` and carries unrelated fork work: V167–V169 migrations, slug generation, country selects, GitHub/Bedrock integration providers. The Crawlers work is the six commits from `536c1648` through merge.

---

## Findings

### Blockers

None.

### Non-blockers

**N1 — `crawlers_verifications` assign is dead code (wasted reads per request)**

`auth.ex` (line ~984) sets `assign_new(:crawlers_verifications, fn -> Crawlers.verification_metas() end)` on every LiveView mount, and `LayoutWrapper` maps it forward — but `CrawlerMetas.crawler_metas/1` is intentionally self-contained and reads settings from ETS itself in `read_state/0`. The assign is never consumed in any template or component. This is one unnecessary ETS read per mounted LiveView, plus dead socket state. The fix is either to drop the assign from the on_mount hook or make the component consume it (preferred if the goal was to avoid duplicate reads in admin layouts where both paths fire).

Files: `lib/phoenix_kit_web/users/auth.ex`, `lib/phoenix_kit_web/components/layout_wrapper.ex`

**N2 — down/1 migration leaves new-feature settings orphaned**

V170 `down/1` correctly reverts `crawlers_module_enabled` and `crawlers_no_index`, and resets the module tag for pre-V170 operator rows. However, settings written by the new UI (`crawlers_allow_*`, `crawlers_block_at_app`, `crawlers_google_verification`, `crawlers_bing_verification`, `crawlers_llms_extra`) are not cleaned up on rollback — they remain in the DB with `module='crawlers'`. The PR explicitly notes this is intentional ("V166-era code reads none of them either way"), which is correct. The only risk is: if a host rolls back and re-runs V170, those orphaned rows could produce unexpected "already set" state. Worth noting as a cleanup item for the next manifest regeneration.

**N3 — No LiveView test for the new Crawlers settings page**

`lib/phoenix_kit_web/live/settings/crawlers.ex` handles group toggle events, verification saves, llms.txt saves, and module enable/disable — none of which have a `PhoenixLiveViewTest` test. The existing test suite exercises the rename (module registry, sitemap no_index, auth noindex contract) and the new pure-function modules (bots, robots_txt, llms_txt, crawler_blocker) well. The settings LiveView is the untested layer. Not a release blocker given the green precommit + manual verification on max-dev2.don.ee, but a gap worth filling.

### Nitpicks

**P1 — Compat shim doesn't cover `module_key/0` / `module_name/0`**

`seo_compat.ex` delegates the user-facing API (`module_enabled?`, `no_index_enabled?`, etc.) but not the framework callbacks (`module_key/0`, `module_name/0`, `permission_metadata/0`). These are not part of the host-app API so it's unlikely anyone calls them directly, but a comment in the shim would clarify the intentional omission.

**P2 — PR bundles unrelated fork work**

The 131-file diff includes V167–V169, slug generation, country selects, and two new integration providers — work that predates the Crawlers commits on the branch. This makes targeted review harder. A note for future branch hygiene: the "opened from `mdon:main`" pattern makes PRs significantly harder to review when the fork accumulates other work first.

**P3 — Doctor check `staging_label?/1` strips trailing digits to prevent "device" matching, but a host named `developer.com` would still false-positive**

`staging_host?` splits on `[".", "-"]`, so `developer.com` gives labels `["developer", "com"]`, and `"developer"` is in `@staging_labels`. This is pre-existing behavior risk from label-split design, not introduced here. Calling it out as a known approximation.

---

## Stats

- **Tests:** 4 new test files (`llms_txt_test.exs`, `robots_txt_test.exs`, `crawler_blocker_test.exs`, renamed `auth_crawlers_no_index_test.exs`); 5+ existing test files updated (module_registry, module, sitemap no_index, conformance, router test probe route)
- **Migrations:** V170 — settings key rename with dedupe guard, permission grant copy (`ON CONFLICT DO NOTHING`), down/1 present; `chain_hash` restamped in `expected_schema.ex`
- **Version bump:** 2.2.0 → 2.3.0 ✅ (correct — breaking rename with backward-compat shim)
- **Dependency changes:** `mdex_native` 0.2.7 → 0.2.8 (unrelated patch in mix.lock)
- **Backward compat:** `PhoenixKit.Modules.SEO` shim covers all 8 public API functions with `@deprecated defdelegate`; correctly NOT registered as a `PhoenixKit.Module`

---

## Migration Safety Assessment

The V170 migration is safe. The `rename_setting/4` helper handles all three partial states:
- Only old key → rename in place
- Both keys → overwrite new from old (old value wins), then delete old
- Only new key → no-op (both UPDATEs are no-ops, DELETE has nothing to find)

The permission copy uses `ON CONFLICT DO NOTHING`, making it idempotent. The decision to keep old `seo` permission rows is correctly explained by the `ExpectedSchema` manifest dependency. The down/1 migration is logically consistent with what up/1 does.

One observation: the retag `WHERE "module" = 'crawlers' AND "key" NOT LIKE 'crawlers%'` in `down/1` is a good defensive guard, but the scenario it protects (operator-created rows with non-prefixed keys tagged `crawlers`) is highly unlikely in practice.
