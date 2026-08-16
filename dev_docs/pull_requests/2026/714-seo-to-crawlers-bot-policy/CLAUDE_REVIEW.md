# PR #714 — Rename the built-in SEO module to Crawlers, and grow it into the bot-policy page

- **Author:** Max Don (`mdon`)
- **Merged:** 2026-08-14 as `10823b52` (from `mdon:main`)
- **Reviewed:** 2026-08-14, post-merge, against `main`
- **Scope reviewed:** the whole `d2d118c8..10823b52` range. The PR is opened from a
  fork's `main`, so it carries more than the Crawlers work: V171 (shop slug
  projection), the scheduled-jobs claim rework, the component-assigns conformance
  analyzer, the maintenance-hook halt, and the test-helper Owner seed all ride along
  and are reviewed here too.

Verdict: **the Crawlers rename itself is clean and well-argued.** The findings below
are concentrated in the work that rode along on the branch — one of them (F1) can
abort an operator's upgrade.

---

## BUG - HIGH

### F1. V171's dedup counts slug *entries*, not owner rows — a single row's own spellings read as a collision

`lib/phoenix_kit/migrations/postgres/shop_slug_projection.ex` → `dedupe_sql/3`

The projection's uniqueness bucket is `(base language, value)`, and the trigger that
fills it folds spellings with `SELECT DISTINCT`:

```sql
SELECT DISTINCT lower(split_part(e.key, '-', 1)), e.value, NEW.uuid
  FROM jsonb_each_text(COALESCE(NEW.slug, '{}'::jsonb)) e
```

So a product whose slug map is `{"en": "hat", "en-GB": "hat"}` projects to exactly
**one** row, `(en, hat)`. There is no constraint to satisfy.

The dedup that runs before the backfill did not fold them. It grouped raw jsonb
entries:

```sql
count(*) FILTER (WHERE t.status IN ('active')) AS live_n
...
HAVING count(*) > 1
```

which counts that one row **twice**. Two consequences, both on live data:

1. **The upgrade aborts.** With that row `active`, `live_n = 2` and the migration
   raises `Cannot apply V171: slug "hat" (en) is shared by 2 live rows` — naming a
   conflict that does not exist, and pointing the operator at a second row they will
   not find. `mix phoenix_kit.update` stops there.
2. **A live URL is silently rewritten.** With the row not live, `row_number()`
   partitioned the same two entries and gave the second `rn = 2`, so `en-GB` was
   rewritten to `hat-2` — the row now has two different public slugs where it had
   one, to satisfy a constraint that was never in danger.

This shape is ordinary wherever the Languages module has a base code and a dialect
enabled (`en` + `en-GB`) and the title is the same in both — which is exactly what
`DialectMapper` exists for. It was not a hypothetical: the branch's own test
**asserted** the rewrite as correct behaviour (`"one row carrying two spellings of a
language is self-deduped"`).

**Fixed.** Both loops now count owners, not entries: `count(DISTINCT t.uuid)` for the
raise and the `HAVING`, and the ranked set is grouped to one row per `(owner, bucket)`
with `array_agg(e.key)` collecting the spellings. When a row does lose a bucket, all of
its spellings move together to the one candidate (`FOREACH k IN ARRAY r.keys`) — they
share the bucket, so splitting them would invent a second URL for the loser too.

Tests rewritten and extended in `test/integration/v171_shop_slug_projection_test.exs`:
the spellings case now asserts the row is left alone, plus a new case pinning that an
ACTIVE row's own spellings never trip the raise, plus one pinning that a genuine
loser's spellings move together. The genuine two-row raise test is unchanged and still
passes.

---

## BUG - MEDIUM

### F2. `V172.down/1` deletes every `crawlers` grant, not the copies it made

`lib/phoenix_kit/migrations/postgres/v172.ex`

The comment states the intent precisely — *"going down only removes the copies this
version created"* — and the SQL does not implement it:

```sql
DELETE FROM phoenix_kit_role_permissions WHERE module_key = 'crawlers'
```

`up/1` copies `crawlers` onto every role holding `seo`, but after the upgrade the
Crawlers permission is a first-class key in the admin matrix and an operator can grant
it to a role that never held `seo`. A rollback silently discards those grants, and a
subsequent `up` does not restore them (there is no `seo` row to copy from).

**Fixed** — the delete is now qualified by an `EXISTS` on a surviving `seo` grant for
the same role, which is what the comment already promised.

Editing `v172.ex` invalidates `ExpectedSchema.@chain_hash`, so it is re-stamped
(`46a7f353…` → `e66e9d10…`). Re-stamping is normally the wrong reflex — it is how a
manifest that genuinely needs regenerating gets waved through — but it is right here:
the edit changes a data `DELETE` predicate on the rollback path and declares, drops or
alters no schema object, so the manifest's object set is unchanged and only the
freshness stamp is stale.

### F3. Three doc sites name V170 as the rename migration; it is V172

The migration was renumbered twice during development (V167 → V171 → V172, both
renumbers documented in the PR body), and three prose references were left at the
first renumber:

- `lib/modules/crawlers/crawlers.ex` moduledoc — *"(V170 migrates the stored settings…)"*
- `lib/modules/crawlers/seo_compat.ex` moduledoc — *"renamed in V170"*
- `lib/phoenix_kit/settings/settings.ex` — `# Crawlers (renamed from SEO in V170)`

V170 is a real, unrelated migration (notification collapsing indexes), so this is not a
harmless stale number — an operator debugging a half-renamed settings table is sent to
the wrong file. **Fixed** in all three.

---

## IMPROVEMENT - MEDIUM

### F4. `:crawlers_verifications` is assigned on every navigation and read by nothing

`lib/phoenix_kit_web/users/auth.ex`, `lib/phoenix_kit_web/components/layout_wrapper.ex`

The PR's own best idea is that `Core.CrawlerMetas` reads its settings itself, so it
renders in a *host* root layout where core's assigns never arrive. Having done that, it
also kept — and extended — the assign-based path the component replaced:

- `auth.ex`'s `:phoenix_kit_mount_current_scope` `handle_params` hook assigns both
  `:crawlers_no_index` and the new `:crawlers_verifications`;
- `LayoutWrapper` assigns both again and threads them through `normalize_content_assigns/1`.

Nothing in `lib/` reads either any more — both layouts now call the component. That is
two extra `Settings.get_setting/2` calls per LiveView navigation for a value with no
reader, on a hook that (unlike every other Crawlers read on a request path) has no
`rescue`/`catch :exit` guard.

**Fixed** — `:crawlers_verifications` removed from both sites. `:crawlers_no_index` is
kept deliberately: it is pinned by `auth_crawlers_no_index_test` and is a reasonable
published signal for host templates that want to branch on the directive. The comment
in `auth.ex` claimed the assign feeds `root.html.heex`'s meta tag, which stopped being
true in this PR; it now says what the assign is actually for.

### F5. The doctor's new check was spliced into the middle of another check's comment

`lib/mix/tasks/phoenix_kit.doctor.ex`

`check_crawler_visibility/1` was inserted directly above `check_sitemap_serving/0`,
between that function and its explanatory comment. The result read as one comment: the
sitemap's *"Which layer answers GET /sitemap.xml… Plug.Static runs before the router…
A host that reported 'the sitemap 404s' had simply never been told any of that"*
paragraph now introduced the crawler check, and `check_sitemap_serving/0` had none.

**Fixed** — the sitemap paragraph moved back onto `check_sitemap_serving/0`.

### F6. `LlmsTxt`'s moduledoc documents a summary blockquote the builder never emits

`lib/modules/crawlers/llms_txt.ex`

The moduledoc shows the generated document as `# title`, then `> summary line`, then
the operator's markdown. `build_for/2` emits only the title and the markdown; there is
no `>` line and no setting behind one. **Fixed** — the doc now shows what is built, and
records why there is no generated summary (core has no setting that says what the site
*is*, and a fabricated line is worse than none).

### F7. The projection's owner-column indexes are not in the repair manifest

`up_sql/2` creates `phoenix_kit_shop_product_slugs_product_uuid_idx` and
`phoenix_kit_shop_category_slugs_category_uuid_idx`, but `ExpectedSchema` declares only
the two tables and their pkeys. `mix phoenix_kit.repair` would therefore never notice or
restore a dropped owner index — the CASCADE delete path and "all slugs of this product"
would silently go to a sequential scan.

**Not fixed, deliberately.** Adding manifest entries by hand is exactly the drift the
PR was careful to avoid, and the entries belong to the same manifest regeneration the
PR already lists as a follow-up (which also has to add the `crawlers` permission seed
and retire the `seo` one). Recorded here so the regeneration picks up all three, rather
than hand-editing the manifest twice.

---

## NITPICK

### F8. `ShopSlugProjection`'s SQL is chain source that `chain_hash` does not hash

`mix phoenix_kit.release_check`'s `compute_chain_hash/0` globs
`lib/phoenix_kit/migrations/postgres/**v*.ex`, so the new
`shop_slug_projection.ex` — which owns the DDL for two tables the manifest now
declares, plus the dedup that runs before them — is outside the hash. An edit there
changes what the chain builds while leaving the manifest's freshness stamp valid.
Nothing is wrong today (V172's own edit in this review re-stamps the hash anyway), and
widening the glob is a release-tooling change with its own blast radius, so this is
**recorded, not fixed** — it is worth folding into the next `release_check` pass, since
extracting shared migration helpers into non-`v*` files is a pattern that will recur.

### F9. `crawlers_no_index?/0` in the sitemap generator guards `rescue` but not `catch :exit`

`lib/modules/sitemap/generator.ex`. Pre-existing (it was `seo_no_index?/0`), but the
project rule is explicit — an unreachable database raises on an unowned checkout and
*exits* on a dead pool. **Fixed**, since the function was being touched anyway.

### F10. Renamed test file kept the old module name

`test/phoenix_kit_web/users/auth_crawlers_no_index_test.exs` still defined
`PhoenixKitWeb.Users.AuthSeoNoIndexTest`. **Fixed.**

### F11. `mark_failed/2`'s comment says the claim increments `attempts`; it does not

`lib/phoenix_kit/scheduled_jobs.ex`. The claim only flips `pending → processing`; the
`inc: [attempts: 1]` in both `mark_failed/2` branches is where the attempt is spent,
which is why the threshold reads `attempts + 1`. The code is right, the comment
mis-describes it. **Fixed.**

### F12. Typo in an `ExpectedSchema` comment

`phoenix_kit_shop_categorie_slugs` → `phoenix_kit_shop_category_slugs`. **Fixed.**

---

## Reviewed and found correct (no action)

Recorded so a later reader does not re-derive them:

- **`Bots.ua_fragments/1` excluding `ua: nil`.** `Google-Extended` and
  `Applebot-Extended` are robots.txt-only opt-out tokens crawling under the main
  search UA. Blocking `:ai_training` therefore cannot 403 Googlebot — the exclusion is
  by construction in the registry, not by a filter the blocker could forget.
- **`CrawlerBlocker` placement.** In `:phoenix_kit_auto_setup` before the auth plug, so
  a request destined for a 403 does not pay for session work; the public
  sitemap/llms.txt scope does not pipe through it, so policy files stay fetchable by
  the very bots being blocked. Both reads are `rescue`/`catch :exit` guarded and the
  whole plug is default-off.
- **`CrawlerMetas` not gating the noindex meta on the module toggle.** Correct: the
  directive is a staging safety switch, and a disabled module must not silently expose
  a staging site. The verification metas *are* gated, which is also right — new
  behaviour, module off means off.
- **The maintenance-hook `{:halt, socket}`.** For an admin the message is fully
  handled; `{:cont, …}` handed `{:maintenance_status_changed, _}` to LiveViews with no
  clause for it and killed them. The catch-all `handle_maintenance_change(_msg, socket)`
  still returns `{:cont, …}`, so unrelated messages are unaffected.
- **`"processing"` as a new status value.** `phoenix_kit_scheduled_jobs.status` is a
  plain `varchar(255)` with no CHECK constraint (V135), so no migration is required;
  the schema's `@statuses` and the badge-class mapping were both updated.
- **`claim_and_execute/2`'s CAS.** `update_all` with `select: j` returns the
  post-update row via `RETURNING`, and the `status == "pending"` predicate is
  re-evaluated under the row lock, so a loser gets `{0, _}` rather than a second
  execution of a host handler that is not required to be idempotent.
- **`V172.rename_setting/4`.** Handles all three partial states (old only, both, new
  only) without violating the unique key, and the old row's value wins — which is the
  value the running site was honouring.

## Known, accepted

- `Live.Settings.Crawlers.mount/3` does its data loading in `mount/3` (≈10 settings
  reads plus two `File` calls) with no `handle_params/3`, so it all happens twice per
  page load. Flagged for the record, **not changed**: the settings are ETS-cached and
  every other settings LiveView in this repo is built the same way, so fixing this one
  in isolation buys little and costs consistency. It belongs to a sweep across the
  settings LiveViews.
- `robots_txt_present?` resolves `priv/static/robots.txt` relative to CWD, which is
  wrong under a release. Already recorded as a follow-up in the PR body.

---

## Validation

- `mix format` + `mix precommit` (compile as errors, `deps.unlock --check-unused`,
  `quality.ci` = format-check / credo --strict / dialyzer, JS tests) — exit 0.
- `mix test` against a live PostgreSQL — **3586 tests, 38 doctests, 0 failures**.

Two failures appeared on an earlier full run and did **not** reproduce: the second
identical run was clean, and both files pass in isolation. Both are pre-existing async
races unrelated to this PR, recorded here so the next reader does not chase them:

- `PhoenixKit.Integration.IntegrationsTest` — *"record_validation/2 broadcasts only
  when status or validation_status changes"*. Its `refute_receive
  {:integration_validated, _, _}` caught an `"openrouter"` broadcast from a *different*
  concurrent test: the PubSub topic is not scoped per test, so the refute is only as
  reliable as the scheduler. It should either subscribe to a per-test topic or match on
  its own provider name.
- `PhoenixKit.Install.CommonUnreachableTest` — *"an unqueryable database reports
  {:unreachable, _}"*. Exited with `owner #PID<...> exited` from
  `DBConnection.Holder.checkout/3`: the sandbox owner went away while the test was
  deliberately querying an absent prefix.
