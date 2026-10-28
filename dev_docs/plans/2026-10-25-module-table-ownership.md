# Module tables: every module owns its own

**Status:** in progress — steps 1–3 done, step 4 done, step 5 done, step 6 done, all unreleased. See the
[progress log](#progress-log).
**Started:** 2026-10-25. **Tracks:** this file is the shared record of where
the work stands; update it in the same commit as each step.

## Start here (handoff for the next session, 2026-10-25)

**Where it stands.** Steps 1–3 are done, committed and pushed to `main` in
every repo; **nothing is released**. Hosts see no change until the releases.

| Repo | Commits (latest first) |
|---|---|
| phoenix_kit | `c5cc437a7` plan; `fa7b25fe7` adoption_ddl fix; `7d52910ab` adoption_ddl; `39a0d4324` ModuleChainCheck + fresh-install test (step 2); `7e582bc0b` ModuleOwnedTables + guard (step 1); plus this handoff and `dev_docs/squash/adoption/` |
| hello_world | `a9afe70`, `4a436ce` (docs only) |
| comments `3f1e0b3` · staff `9b9d0a0` · user_connections `b5f10ab` · sync `b9cfcfb` · calendar `0110162` · referrals `e04892b` | step 3 chains |

**Release day (Friday 2026-10-30), in this order:**

1. **Core** — minor bump (new public modules `PhoenixKit.Migrations.ModuleOwnedTables`
   and `PhoenixKit.TestSupport.ModuleChainCheck`; `Repair.Differ.canonical_expression/1`).
   Steps 1–2 have no host-visible effect. Gate as usual (`mix prerelease`, full suite).
2. **The six step-3 modules**, after `mix deps.update phoenix_kit` in each so
   the lock resolves that core. Their `migrations_build_alone_test.exs` then
   runs instead of being excluded; it passed against local core for all six.
   Two raised their floor: user_connections `>= 2.22.3`, sync `>= 2.63.0`.
   On hosts, `mix phoenix_kit.update` runs each new chain once and only stamps
   the marker.

**Tools** (all in core): `dev_docs/squash/adoption_ddl.exs` (DDL as a fresh core
builds it), `dev_docs/squash/adoption/` (`gen_chain.py` + templates + README:
chain and tests from that DDL; `check_module_chains.exs`: `ModuleChainCheck`
over every module chain from core's VM — 27 of 31 pass today).

**Next: step 7** (steps 4, 5 and 6 are done). The failing chains shared one shape:
*an earlier version of the chain touches a table only core creates*, so on a
database without core's copy that version fails before anything adopts the
table. ai and billing build `up_statements/2` by replaying every version up to
`target` in order (`version_up/2`; billing's `if target >= N` blocks), so the
adoption DDL for core-created tables must be **emitted ahead of the first
statement that touches them** — not appended as the last version — while the
version number still goes up by one. Shipped versions' own statements stay
unedited.

- **ai** (step 4) — **DONE**, `c118542`, owner's OK given 2026-10-25 (ai's moduledoc and AGENTS.md said the three tables "stay in core's chain"; both rewritten). V5 adopts them, emitted ahead of V2's statements via `version_up/3` (a target below 5 builds the old chain); V4's `cost` guard is satisfied by ai's own copy and still stops on a core older than V223, so no guard change was needed. 1987 tests, 0 failures against local core. Original note: adopt `phoenix_kit_ai_endpoints`, `_prompts`,
  `_requests` (core changed them in V164, V169, V193, V223). ai's V4 raises
  unless core's V223 `ai_requests.cost` exists; once ai creates that table
  itself, that guard has to accept ai's own copy. Floor is already `~> 2.64`.
  Fails alone today at `phoenix_kit_ai_endpoints` missing.
- **document_creator** (step 4) — **DONE**, `f67f163`: V3 adopts the 7 tables, emitted first in `up/1` (ahead of V1/V2) rather than appended; marker `dcr_schema:3`; builds-alone test added; 1109 tests, 0 failures against local core. Its `mix precommit` shows an undefined-`ModuleChainCheck` warning in the new test until the module resolves the new core — same as the step-3 modules, clears on release day. Original note: `PhoenixKitDocumentCreator.Migrations.Schema`
  is Ecto-DSL (`execute/1`, no `up_statements/2`), V2, marker on
  `phoenix_kit_doc_documents` — itself core-created. Adopt its 7 V135 tables
  (`phoenix_kit_doc_{categories,document_sections,documents,headers_footers,template_presets,templates,types}`);
  the generator's templates do not fit as-is, use `adoption_ddl.exs` output by
  hand. Fails alone today at `phoenix_kit_doc_documents` missing.
- **billing** (step 5) — **DONE**, `3fa1164`: V6 emits the base `CREATE TABLE` of `phoenix_kit_currencies` and `phoenix_kit_orders` between V1 and V2 (sharing V4's text; output for targets 1–5 verified byte-identical, public and named prefix); seeds ride inside the `DO` block that creates the table (`to_regclass IS NULL`), because replaying them with `ON CONFLICT DO NOTHING` on an existing host would restore deleted rows and a second `is_default` EUR would hit V2's unique index. The `#{pn}` indexes were already handled by V4. The email-template seeding is not carried (`EmailDefaults` is billing's own fallback). The four skipped tests were stale and are back (50 tests pass). 883 tests, 0 failures against local core. Original note: V2 demotes duplicate default currencies in
  `phoenix_kit_currencies` before V4 adopts it → fails alone. Also carries core's
  **seed rows** (currencies EUR/GBP/USD, payment options bank_transfer/cod/paypal/
  stripe; and `phoenix_kit_email_templates`' billing seeder) — `ModuleChainCheck`
  compares shape, not rows, so seeds need their own check. Two of its indexes use
  core's schema-name convention (`#{np}`; see step 3's notes). Its AGENTS.md
  landmine about `subscription_type_uuid` missing on fresh builds is stale (it
  exists) — its four `@tag :skip` tests can likely come back.
- **ecommerce** (step 5): its chain lacks core's V186 columns
  (`phoenix_kit_shop_carts.base_currency`, `.exchange_rate`,
  `phoenix_kit_shop_cart_items.base_unit_price`); four `shop_*` indexes use the
  `#{np}` convention.
- **emails** passes the check but owns `phoenix_kit_email_templates` (seed rows,
  one `#{np}` index): verify both in step 5.

**Known, not part of this plan:** staff's suite has 31 web-test failures that
predate this work (redirects to `/admin/...` where its test router expects
`/en/admin/...`); core's `MediaFiltersTest` is flaky under load (passes alone).

**Local test databases created on this machine:** `phoenix_kit_user_connections_test`,
`phoenix_kit_referrals_test` (`createdb` them elsewhere).

Builds on [the module-table extraction guide](../guides/2026-09-05-module-table-extraction-guide.md)
(its Phase 0 / 1 / 2) and finishes it for every module, instead of inventing a
new protocol.

## Where we want to end up

- Each module's tables are created and changed **only** by that module's own
  migration chain.
- Core's migrations, `ExpectedSchema` manifest and runtime code know only
  core's own tables.
- A fresh install gets only the tables of the modules it installs.
- The manifest is generated from the chain, never written by hand.

## Why (found 2026-10-25)

- Core's chain creates **181 tables**: **40 are core's**, **141 belong to 25
  modules** — they were created when those modules lived inside core.
  `PhoenixKit.Migrations.ModuleOwnedTables` now records whose each one is.
- After the 2.0 squash, **36 of the 88 core versions (V136–V223) still created
  or changed module tables** — most recently V188 (user connections), V193 and
  V223 (AI requests), V218 (sync connections).
- `ExpectedSchema` (`lib/phoenix_kit/migrations/expected_schema.ex`) describes
  all 181 tables: 76,782 lines, 3,632 entries, about 1,500 of them module
  tables. Every new table costs ~1,000 hand-written lines; it grew by ~10,000
  lines in 2.5 months. Loading it adds ~6.4 MB to every node that runs a release.
  Only `mix phoenix_kit.repair`, `mix phoenix_kit.doctor` and
  `mix phoenix_kit.release_check` use it.
- Modules fall into four groups (inventory below): 6 have no migrations at all,
  2 depend on core for some tables, 17 adopted their tables but core still
  creates them first, 6 are fully independent.

## Rules for the whole project

- Follow the extraction guide's protocol; extend it, don't replace it.
- **Nothing destructive.** No table is dropped by anyone except through an
  explicit decision for that table (step 9).
- **Existing hosts see no schema change until step 8**, and step 8 affects only
  fresh installs: V135 never runs on an existing host, and hosts below V135
  are refused (`BelowFloorError`).
- One step = one unit of work, gated (`mix precommit` + full `mix test`),
  shipped on the weekly release day.

## Steps

| # | Step | Where | Status |
|---|---|---|---|
| 1 | Ownership map + guard test + rule in the docs | core, hello_world | **Done** 2026-10-25 (unreleased) |
| 2 | "Builds from scratch" test helper + a true fresh-install test | core | **Done** 2026-10-25 (unreleased) |
| 3 | First migration chain for comments, staff, user_connections, sync, calendar, referrals | 6 modules | **Done** 2026-10-25 (unreleased) |
| 4 | Complete the chains of ai (3 tables) and document_creator (7 tables) | 2 modules **Done** 2026-10-25 — document_creator `f67f163`, ai `c118542` (unreleased) |
| 5 | The step-2 test in every adopted module; fix what it finds | 17 modules | In progress — billing (`3fa1164`) and ecommerce (`54061bd`) done 2026-10-25; **Done 2026-10-25**: billing, ecommerce, emails, and the builds-alone test in the other 14 |
| 6 | Core's manifest hands every module-owned entry over | core | Not started |
| 7 | Manifest generator (frozen pre-squash part + generated rest, compact, in `priv/`); move core's hard-coded module-table lists to module callbacks | core | **Done** 2026-10-26 (7a `file_references/0`, 7b per-module manifests; unreleased) |
| 8 | Core stops creating module tables on fresh installs | core | **In progress** 2026-10-27 — decided: core 3.0, strip the DDL in place, installs must be at V225 first; on branch `core-3.0` (not yet merged or pushed) |
| 9 | Dead tables (`crm_user_role_view`, `email_metrics`, `email_orphaned_events`) | crm, emails | Not started — per-table decision |
| 10 | Ecosystem sweep for core 3.0: widen every package's core pin, release in order | core + all modules | Not started — after step 8 |

### Step 1 — ownership map and guard (done)

- `PhoenixKit.Migrations.ModuleOwnedTables` (`lib/phoenix_kit/migrations/module_owned_tables.ex`):
  `core_tables/0` (40), `owners/0` (141 tables under 25 OTP apps), `owner/1`,
  `tables_for/1`, `last_core_version_touching_module_tables/0` (223).
  Ownership follows the code: the package with the Ecto schema, or the module
  whose chain adopts a schema-less table. 63 manifest `owner:` labels disagree
  (57 say `:core`, 6 say `:comments` for posts' and customer support's tables);
  the list is the authority.
- `test/phoenix_kit/migrations/module_owned_tables_test.exs` (no database): every
  table core's chain creates is classified exactly once; **no core version after
  V223 names a module table in its code** (parsed source, so comments and docs
  don't count); the scan is proven on V223 and on a synthetic version.
- Docs: core `AGENTS.md` (Database), the extraction guide's inventory,
  hello_world's README (the template's database conventions), workspace `AGENTS.md`.

### Step 2 — prove a module can build its tables alone (done)

- `PhoenixKit.TestSupport.ModuleChainCheck.check(repo, MyModule.Migrations)`
  (`lib/phoenix_kit/test_support/module_chain_check.ex`, ships in `lib/` like
  `PostgresPreflight`). In a scratch schema: core's chain; the module's chain
  the way `mix phoenix_kit.update` runs it (**today**); drop the module's
  tables; the module's chain again (**alone**); compare columns, indexes,
  constraints and triggers by name and definition, in the canonical form
  repair's differ uses (`Differ.canonical_expression/1`, made public for
  this). A chain that raises is a finding. Takes ~2 s per module.
- Tested in core against three fixture chains
  (`test/phoenix_kit/test_support/module_chain_check_test.exs`): a chain with
  its own table passes; a module relying on core and an incomplete adoption
  are reported table by table and column by column.
- `test/integration/fresh_install_manifest_test.exs`: a database built **from
  nothing** verifies clean against `ExpectedSchema` (0 error or repairable
  findings; the same 17 informational ones as the suite's database) and holds
  exactly the 181 tables `ModuleOwnedTables` classifies.
- Documented in the extraction guide ("Proving the chain builds the tables
  without core") and hello_world's README.
- Each module adds the one-test file once it depends on the core release that
  ships the helper; the first ones come with step 3.

**Preview, 2026-10-25** — every module chain in the workspace checked from
core's test VM (module beams loaded from their own `_build`, nothing changed
in the modules):

| Result | Modules |
|---|---|
| Pass (15 adopted) | catalogue, crm, customer_support, dashboards, emails, entities, legal, locations, manufacturing, newsletters, open_graph, posts, projects, publishing, warehouse |
| Pass (6 independent) | agent, boards, bookings, inbox, stats, web_analytics |
| Fails alone — expected, step 4 | ai (`phoenix_kit_ai_endpoints` missing), document_creator (`phoenix_kit_doc_documents` missing) |
| Fails alone — step 5 | billing (V2 updates `phoenix_kit_currencies`, which only V4 adopts), ecommerce (lacks `base_currency`, `exchange_rate`, `base_unit_price`, core's V186 columns on carts and cart items) |
| Not checkable yet — step 3 | comments, staff, user_connections, sync, calendar, referrals (no chain) |

Found on the way: core seeds rows into three module tables (`phoenix_kit_currencies`
and `phoenix_kit_payment_options` for billing, `phoenix_kit_email_templates` for
emails); `ModuleChainCheck` compares shape, not rows, so those seeds are
billing's and emails' to carry in step 5. On a fresh build `phoenix_kit_subscriptions.subscription_type_uuid`
**exists**, so `phoenix_kit_billing`'s landmine ("missing on a from-scratch
build") and its four `@tag :skip` subscription tests look stale — check when
billing is fixed in step 5.

### Step 3 — six modules get their first chain

comments, staff, user_connections, sync, calendar, referrals. Each copies the
hello_world coordinator: V1 adopts its tables with `CREATE … IF NOT EXISTS`,
shape- and name-identical to what core builds **today** (including core's later
changes: V136, V141, V164, V166, V188, V218), stamps a marker, `down/1` only
unstamps; the step-2 test proves it. comments and staff first (most dependents).

**How each one is done** (comments is the worked example):

1. `MIX_ENV=test mix run --no-start dev_docs/squash/adoption_ddl.exs OUT.ex <tables>`
   in core prints the tables' DDL exactly as a fresh core install builds them.
2. The module gets `<App>.Migrations` in the shape of `phoenix_kit_locations`'
   chain: V1 = those statements, a namespaced `<ns>_schema:1` marker, `down/1`
   only rewrites the marker; `migration_module/0` returns it.
3. `test_helper.exs` replays `up_statements/1` after core's `ensure_current/2`,
   so the suite runs on the adopted schema; `migrations_test.exs` pins every
   name, FK action and the prefix, and checks the statements against core's
   manifest; `migrations_build_alone_test.exs` runs `ModuleChainCheck`, tagged
   `:requires_module_chain_check` and excluded until the module resolves a core
   that ships it.
4. The core floor must include every core version that shaped the tables: V1
   re-states today's shape, and over an older core's tables it could fail
   (user_connections: V188's unique indexes meet the duplicates V188 removes
   first). Checked per module against the core release that first carried each
   version.
5. AGENTS.md (no longer "owns no migrations"), CHANGELOG `Unreleased`.

| Module | Chain | Marker | Floor | Commit | Notes |
|---|---|---|---|---|---|
| comments | V1, 4 tables | `pkcmt_schema:` on `phoenix_kit_comments` | 2.38.0 (unchanged; V166 is in 2.0.0) | `3f1e0b3` | 151 tests, 0 failures |
| staff | V1, 7 tables | `pkstf_schema:` on `phoenix_kit_staff_people` | 2.43.0 (unchanged; V136 is in 2.0.0) | `9b9d0a0` | 31 web-test failures **predate this** (redirects to `/admin/...` where tests expect `/en/admin/...`; same 31 at HEAD before the change) |
| user_connections | V1, 6 tables | `pkucn_schema:` on `phoenix_kit_user_connections` | **2.22.3** (was `~> 2.0`; V188) | `b5f10ab` | gained a test Repo and database (`phoenix_kit_user_connections_test`); no `pk_dep/3`, so its builds-alone check ran from core's VM |
| sync | V1, 2 tables | `pksyn_schema:` on `phoenix_kit_sync_connections` | **2.63.0** (was 2.38.0; V218) | `b9cfcfb` | 2198 tests, 0 failures; one index uses core's schema-name convention (`np`); the old `PhoenixKitSync.Migration` stays, marked superseded |
| calendar | V1, 2 tables | `pkcal_schema:` on `phoenix_kit_calendar_events` | 2.38.0 (unchanged; V141 is in 2.0.0) | `0110162` | 157 tests, 0 failures |
| referrals | V1, 2 tables | `pkref_schema:` on `phoenix_kit_referral_codes` | `~> 2.0` (unchanged; nothing after V135) | `e04892b` | gained a test Repo and database (`phoenix_kit_referrals_test`) |

After step 3 every module chain in the workspace was checked again from core's
VM: **27 of 31 build their tables without core**; the four that do not are
steps 4 (ai, document_creator) and 5 (billing, ecommerce).

**A trap found on the way, now handled:** core's V56 convention puts the schema
name in front of nine index names on a named-schema install (none on `public`).
`adoption_ddl.exs` first copied its own scratch schema's name into such a name;
it now emits `#{np}`, which a chain sets per prefix (sync is the first user).
The drift-lock test against core's manifest caught it before anything was
pushed. The nine are sync's `phoenix_kit_sync_connections_uuid_idx` and eight
on billing, ecommerce and emails tables — step 5 checks those.

**Releasing step 3:** the six modules ship after the core release that carries
`ModuleChainCheck`, in the same release day. Their `:requires_module_chain_check`
exclusion then stops excluding anything; it can go when a module next raises
its core floor.

### Step 4 — ai and document_creator

**document_creator: done 2026-10-25** (`f67f163`). The chain is Ecto-DSL, so the
adoption is private functions called first in `up/1` (V3), not a generator
output; hosts at V2 run it once as a no-op. The pattern for ai/billing is the
same: adoption DDL ahead of the first statement that touches a core-only table.

**ai: done 2026-10-25** (`c118542`), after the owner agreed to the move. V5
adopts the three tables; the SQL is `version_up/3`-ordered so it precedes V2.
ai's docs (moduledoc, `migration_module/0`, AGENTS.md, CHANGELOG) were updated
in the same commit. document_creator's chain creates only its taxonomy table; its
other 7 come from V135.

### Step 5 — the 17 adopted modules

Add the step-2 test to each; any whose chain cannot really build its tables
alone gets fixed. The preview (step 2) found two:

- **billing** — its V2 demotes duplicate default currencies in
  `phoenix_kit_currencies` before V4 adopts that table; alone, V2 hits a
  missing table. The adoption has to come first (a new version that creates
  every adopted table before the V2/V3 changes apply, or guards on V2/V3).
- **ecommerce** — core's V186 added `base_currency`, `exchange_rate` (carts)
  and `base_unit_price` (cart items); ecommerce's chain never declares them.

### Step 6 — core's manifest lets go (done)

Remove every module-owned object from `ExpectedSchema` (the guide's Phase 1 for
all of them at once), using `ModuleOwnedTables`; `doctor`/`repair` then check
core's tables only. Requires steps 3–5, so each module can vouch for its own
tables. Later, step 7's generator can produce a manifest per module so repair
checks module tables again, owned by the module this time.

*Done as a filter, not a deletion* (decided 2026-10-25): `ExpectedSchema.objects/1`
and `data_invariants/1` drop everything on a table `ModuleOwnedTables` lists as a
module's: its table, columns, constraints and indexes, the seeds on it, the
sequences named after it, and the two V137 email invariants. What is left is 40
tables, 489 columns, 124 constraints, 165 indexes, 108 seeds and 4 invariants,
all core's. The dead text stays in `expected_schema.ex` (about 60% of it) until
step 7 rewrites the file, so no `v*.ex` changes and `chain_hash` is untouched.
The newsletters FK exception in `@module_owned_ids` is now covered by the rule.
Consequence: until step 7, `doctor` and `repair` say nothing about a module's
tables. Repair is additive-only (its executor never issues a `DROP`), and no
database changes: re-running `mix phoenix_kit.update` re-runs each module chain,
which is idempotent, and puts back what is missing.

### Step 7 — generated manifest

Split the manifest: a frozen part for what only the pre-squash chain could know
(entries born at or below V135, their old revisions, `legacy_optional`) and a
part generated by replaying V135→head with `generate_baseline.exs`'s catalog
snapshots. One line per object, stored in `priv/` and read only when repair or
doctor runs, with a test that fails when it is stale. Also move core's
hard-coded module-table lists (storage's orphaned-file check, doctor's
NULL-uuid check) to module callbacks.

*Step 7 so far (2026-10-25).* Two decisions and one built part.

- **Doctor's NULL-uuid list stays in core.** It guards the V56 backfill, which core's own chain still runs against
  those tables, so it is core history, not a module concern. It only reads, and skips a table that is missing,
  so it is harmless once core stops creating module tables. Not moved.
- **Storage's orphan-file list moves by callback.** `PhoenixKit.Module.file_references/0` (optional, no default;
  a default `[]` would switch off core's protection for every module) returns `{table, dynamic}` pairs, collected
  from all modules by `ModuleRegistry.all_file_references/0`. In `Storage.orphaned_files_query/1`, core's built-in
  entry for a table is dropped only when the module that `ModuleOwnedTables` says owns the table supplies a list;
  every other module keeps core's, so an older module version stays protected. A broken callback fails closed.
  Tests: `test/integration/storage_module_file_references_test.exs`. **Core half done and additive; nothing changes
  until a module implements it.** Two details: core's built-in list is public as `Storage.builtin_file_references/0`
  (`@doc false`), so a module's test can prove its pairs render the same SQL as core's; and a core entry also steps
  aside when a supplier names its table, because `phoenix_kit_project_portal_submissions` has no owner in
  `ModuleOwnedTables` (projects creates it itself, core never did). A module defines the callback **without
  `@impl`**, so it compiles against today's Hex core and does nothing there; no core floor is needed, because core
  falls back whenever the callback is absent. Each module's test is gated like the chain check
  (`:requires_core_file_references`, excluded while `Storage.builtin_file_references/0` is not exported).
- **Done, per module** (2026-10-26, all pushed, unreleased): each has a `FileReferences` module holding its pairs
  (moved verbatim from `storage.ex`), a one-line `file_references/0` in its main module (no `@impl`), a
  `file_references_test.exs` and a CHANGELOG entry. No core floor was raised: core falls back whenever the callback
  is absent, and the test is excluded until core exposes `Storage.builtin_file_references/0`. projects `e5bb40f`
  (`project_portal_submissions`), posts `665847a` (`post_media`, `post_groups`, `posts`), customer_support `a667657`
  (`ticket_attachments`), ecommerce `e1fb780` (`shop_products`, `shop_categories`), catalogue `0fd0aad` (`cat_items`,
  `cat_categories`, `cat_catalogues`, `cat_pdfs`), publishing `c78f56a` (`publishing_contents`,
  `publishing_versions`), entities `a1e611c` (`entity_data`). Each passes against local core, where the test proves
  its SQL equals core's own copy. Gate: format and `quality.ci` clean in all seven; suites green on Hex core except
  projects, whose `ProjectCalendarLiveTest` "reloads on a projects PubSub broadcast" fails at `HEAD` with or without
  this change (not part of this plan). Whether core deletes its copy at 3.0 is undecided: keeping it as a permanent
  safety net costs nothing.
- **7b, per-module manifests: decided (a) on 2026-10-26; core half and the customer_support pilot built, other modules not started.** Core's `ExpectedSchema` keeps
  core's own objects (step 6 already filters the rest); each module ships a manifest of its own tables, and
  repair checks them again.
  - *Shape.* A generated module `<App>.ExpectedSchema` implementing the existing
    `PhoenixKit.Migrations.ExpectedSchema.Behaviour` (`objects/1`, `data_invariants/1`, `chain_hash/0`), so
    `Repair.Differ`, `Executor` and the additive-only rules work unchanged. Core learns of it through a new
    optional `PhoenixKit.Module` callback (`expected_schema/0`, no default, like `file_references/0`), so an older
    module simply has none and is skipped.
  - *Version scope, kept simple.* One revision per object, the module chain's end state. Repair checks a module's
    tables only when the module's recorded version equals its current chain head; a module that is behind is
    reported as "run update", not healed against a guessed older shape. No per-version history for modules.
  - *Generator.* Reuses `ModuleChainCheck`'s "module alone" build in a scratch schema plus the generator's
    `Catalog` snapshot (catalog queries only, no `pg_dump`, so it runs here, unlike the core generator). Lives in
    core `lib/` so a module runs it from its own repo, like `ModuleChainCheck`. A module test rebuilds and fails
    when its committed manifest is stale (the module's `chain_hash`).
  - *Repair.* After the core pass, one pass per module that supplies a manifest; findings are labelled with the
    module. `doctor` and `repair` print module findings separately.
  - *Order.* Core half (callback, repair pass, generator, fixture tests) first and additive; then one pilot
    module end to end; then the rest. Nothing changes for a host until a module ships a manifest.
  - **Rolled out to the other 24 owner modules (2026-10-26, gate green, committed and pushed).** One generated `<Module>.ExpectedSchema`, an `expected_schema/0` callback (no `@impl`), a `:requires_core_expected_schema` test and a CHANGELOG bullet each. Not touched: `phoenix_kit_bookings` (Max's rework). Findings along the way:
    * The generator runs best against an empty database (`PGDATABASE=pk_modgen_empty`): several chains look a constraint up by name alone, not by schema, so a `public` copy hides it in the scratch schema.
    * Core's generator excludes `fk_newsletters_broadcasts_template` from *core's* manifest (newsletters repoints it). Module mode now keeps it (`build_objects` skips `module_owned?` when `owner:` is given).
    * `phoenix_kit_projects` has two such name-only lookups in its own chain (`phoenix_kit_project_assignments_dates_check`, `phoenix_kit_project_portals_access_mode_check`, `migrations/schema.ex`). Harmless in `public`; its test lists them as known gaps.
    * A fresh non-public schema names some indexes with the schema in them; the test compares the unprefixed name.
    * `phoenix_kit_og` is OTP app `:phoenix_kit_og`; the ownership map keys on it. `phoenix_kit_legal`'s test repo has no sandbox and needs `:phoenix_kit, :repo` set while core's chain builds.
    * `phoenix_kit_billing` declares `Helpers.validate_prefix!/1` in its `CoreCompat` (the generated file calls it).
    * Generator output is not byte-stable between runs for some modules (property order in a few objects); regenerate rarely and review the diff.
  - **Pilot built (2026-10-26, gate green, committed and pushed): core half plus customer_support.**
    - *Core.* `PhoenixKit.Module.expected_schema/0` (optional, no default, not in `defoverridable`);
      `ModuleRegistry.all_expected_schemas/0` (`%{app => %{manifest:, migrations:}}`; a raise, a nil manifest, a
      manifest without the three exports or a module without a loaded migrations module is left out);
      `Repair` runs one more pass per manifest after core's (`add_module_passes/3`, opt `:module_manifests` for
      tests), gated on the module's `migrated_version_runtime/1` against `current_version/0`: equal = checked,
      lower = an info `:module_behind` finding, 0 = silent, higher or unreadable = silent. Findings carry
      `module:` and their message starts with the app. Reuses `apply_scope/7` unchanged with `since: 1` on every
      object. The core-adopt branch is untouched. `ModuleChainCheck.build_alone/4` is the "core, then the module's
      chain alone" build, public. Tests: `test/integration/repair_module_manifest_test.exs` (9).
    - *Generator.* `dev_docs/squash/generate_module_manifest.exs`. It loads `generate_baseline.exs` as a library
      (`PK_GEN_LIBRARY=1` stops its `Main.main` from running), takes `Catalog.snapshot/2` of the scratch schema,
      keeps the module's tables, and renders through the core emitter (`render_manifest/3` gained `:header`,
      `:invariants`, `:owner`; `build_objects/2` gained `:owner`). Catalog queries only: it ran here against the
      PG18 server, which the core generator cannot. `generate_baseline.exs --check` still passes. The migrations
      module must be compiled from `--source` files (schemas it reads included), since core does not depend on the
      module. `chain_hash` of a module manifest is a fingerprint of its objects, not of the chain files.
    - *customer_support.* `PhoenixKitCustomerSupport.ExpectedSchema` (77 objects, 4 tables), `expected_schema/0`
      in the main module (no `@impl`), `test/integration/expected_schema_test.exs` (4: table set, a fresh chain has
      no findings, every index and constraint is in the manifest, a dropped column is found and repaired),
      excluded by `:requires_core_expected_schema` against a core without `build_alone/4`. Passes against local
      core.
    - *Staleness.* There is no file hash to compare. A stale manifest shows up in the module's test as a missing
      or extra object; a chain change still needs the generator re-run.
    - *When core releases:* each module's `file_references/0` and `expected_schema/0` get `@impl` once the core
      floor is raised, otherwise core's compiler warns "@impl not set" on the module.

### Step 8 — core stops creating module tables (fresh installs only)

Remove the module DDL from V135 and from the later versions that touch module
tables. Prerequisite found in step 3: modules' tables reference each other
(`phoenix_kit_projects`' tables carry nine foreign keys to staff's), so module
chains must run in dependency order (staff before projects), or such foreign
keys must be guarded, wherever core no longer creates the referenced tables. Risk: a fresh install of new core with an old module version that has
no chain. Options, decided when we get here:

- **(a) at core 3.0** — modules pin `< 3.0.0`, so a 3.0 install always has module
  versions with their own chains. Recommended.
- **(b) in 2.x** — core still creates a module's tables when that module's
  loaded version does not claim them.

#### Step 8, chain ordering (done 2026-10-26)

Decision: **(a) at core 3.0** (made 2026-10-26). First part, shippable on its own in 2.x:

- *The graph.* Foreign keys between owners, from a full core chain: `ecommerce → billing` (1),
  `newsletters → emails` (1, guarded by `to_regclass`, and the FK is newsletters' own), `projects → entities` (1),
  `projects → staff` (9). Everything else points at core tables (users, files, roles). The only unguarded
  references are projects' (to staff and entities) and ecommerce's (to billing's `payment_options`); a
  `manufacturing → entities` link has no FK by design.
- *The order.* `mix phoenix_kit.update` wrote module migration files in display-name order. Now
  `Migrations.Modules.pending/1` runs `order_by_dependencies/1`: a module comes after every pending module that its
  OTP application reaches through `applications` / `optional_applications` (its `mix.exs` deps), transitively.
  No callback, no module change; unrelated modules keep name order; a cycle keeps name order instead of failing.
  All four real edges are mix deps (projects lists staff and entities, ecommerce lists billing).
- *Not covered by it:* an edge that exists in SQL but not in `mix.exs` (none today; newsletters → emails is guarded).
  A migration file reused from an interrupted run keeps its old timestamp, so it can sort before a newer file.
- Tests: `modules_test.exs` (sorter with a dependency map, a chain, a cycle, the real application graph,
  `pending/1`). Gate: `mix precommit` exit 0; `test/phoenix_kit/migrations` and `test/mix` 0 failures.
- *Rehearsal built (2026-10-26):* `ModuleChainCheck.check_all/3` + `dev_docs/squash/rehearse_module_chains.exs`
  (empty database, `PGDATABASE=pk_modgen_empty`). It builds core, runs all 25 chains on top (today), drops every
  module-owned table, runs the chains again alone in order, and diffs tables, columns, indexes, constraints and
  triggers. Name order is run as a control. **Result: with one added edge, all 25 chains rebuild the identical
  schema in dependency order; name order fails.** `--edge a:b` adds an undeclared dependency.
- *Two findings from it, both fixed (2026-10-26):*
  1. **`document_creator` → `projects` was undeclared.** Its V1 added `doc_documents.project_uuid REFERENCES
     phoenix_kit_projects` unguarded, but its mix.exs has no sibling deps and projects does not depend on it
     either (duck-typed hub). Decision: **guard the FK.** The chain adds the column plain and the constraint only
     where `phoenix_kit_projects` exists (`to_regclass`); a host without projects keeps the plain column, and
     re-running the chain after projects is installed adds it. Its manifest leaves the constraint out
     (`generate_module_manifest.exs --exclude constraint:...`), and its test lists it in `@known_gaps`. The
     rehearsal accepts that one difference (`allow:`).
  2. **`projects` declared `staff` and `entities` as `optional: true`** yet its chain carries unguarded
     `REFERENCES` to both (9 + 1 FKs). Decision: **make both hard deps** (mix.exs, AGENTS/README/CHANGELOG),
     which also puts the edge in the application graph that `order_by_dependencies/1` reads. The People seam in
     the code and its `WITHOUT_STAFF` compile gate stay as they are.
  Result: `rehearse_module_chains.exs` with no extra edge: **name order fails (projects before staff),
  dependency order rebuilds the identical schema.**
- *Core to module FKs:* none. No core table references a module-owned table.

#### Step 8, done on branch `core-3.0` (2026-10-27)

Decision (2026-10-27): **strip the module DDL in place and require V225 first**, over guarding the deltas or a new
squashed baseline. V225 is the last 2.x migration (the short-code column); the gate follows whatever the last 2.x is.

- *Why in place is safe.* V135 only ever runs on a fresh install, and V136..V225 run on a fresh install or on an
  install that stepped up one version at a time. With the gate, no install replays them on module tables that
  already exist, so nothing has to be preserved for a mid-chain host.
- *What changed.* V135: 792 module statements removed from `up/1`, 106 module `DROP TABLE`s from `down/1`, plus three
  legacy tables core created and later dropped (`phoenix_kit_ai_accounts`, `phoenix_kit_newsletters_lists`,
  `phoenix_kit_newsletters_list_members`), which are no longer created at all. 34 deltas that only did module DDL
  (V136–V141, V144–V146, V148, V149, V151, V154–V156, V158, V159, V162, V164, V166–V169, V171, V173, V177–V180, V186,
  V188, V193, V218, V223) are stubs: their moduledoc stays as history, `up/1`/`down/1` only move the version marker.
  V152 and V185 keep their core parts (send profiles; `activities.permanent`). V164 was a repair pass over drift on
  existing hosts, so it is a stub too.
- *The gate.* `Postgres.minimum_version/0` (225) next to `initial_version/0` (135, the fresh-install baseline).
  `plan_up/4` raises `BelowFloorError` below it, naming "the last 2.x release" as the bridge; `phoenix_kit.update`
  refuses at generation time. A fresh 3.0 install that stopped part-way resumes (the check only raises when the
  database holds a module table, which only a 2.x chain creates).
- *Proof.* `rehearse_module_chains.exs --record-full` on `main`, `--compare-full` on the branch: core's new chain
  plus the 25 chains in dependency order gives the **same whole schema** (tables, columns, indexes, constraints,
  functions, seeds, triggers; CHECK spellings and clock-stamped seeds normalised). The one difference is the
  guarded `doc_documents.project_uuid` foreign key (the document creator does not depend on projects).
  `check_all/3` also passes; name order fails (control). `ModuleOwnedTables.last_core_version_touching_module_tables/0`
  is 0: the guard test fails any core migration that names a module table in code.
- *Tests.* Tests of module DDL went (V145, V155, V156, V158, V162, V186, V193, V218, V223 and the V164 relaxed-columns
  test, the v167/V171/user-connections integration tests, the module halves of V135/V152/V164 tests); the storage
  orphan tests build the few module tables they read inside the test transaction
  (`test/support/module_fixture_tables.ex`). Full suite on a rebuilt database: 12,933 tests, 29 failures, of which
  23 of them also fail on `origin/main` (30 do there) (the bucket-create `varchar(255)` truncation in `ManagedLibraryTest`/`LinkCopyTest`, 26 + 4 there,
  from c5bef85bf, not this branch) and one is a flaky LiveView test that passes alone; the other five were rewritten
  and pass. `mix dialyzer` clean; `mix credo --strict` has two suggestions, both in c5bef85bf's storage code.
- *Left for the merge into `main` / the 3.0 release:* bump to 3.0.0, replace `@bridge_version "2.x"` with the real
  last 2.x, the `builtin_file_references` decision (kept for now: it is guarded by table existence), and the
  `main` copy of this plan (step 10 was added there, uncommitted).

### Step 9 — dead tables

`phoenix_kit_crm_user_role_view` (CRM copied it into core's view preferences,
V7), `phoenix_kit_email_metrics` and `phoenix_kit_email_orphaned_events` (no
reader). Dropping deletes data: an explicit decision per table, done in the
owning module's chain, never core's.

### Step 10 — ecosystem sweep for core 3.0

Core is the only package that goes to 3.0. Modules keep their own version lines (most are 0.x): a module's version
describes its own API, and nothing in a module breaks. What every package that depends on core needs is a minor
release whose core pin admits 3.0.

- **The pin.** A compound floor (`>= 2.64.0 and < 3.0.0`) becomes `< 4.0.0`; a `~> 2.0` becomes `>= 2.0 and < 4.0`
  (a two-segment `~> 2.0` cannot resolve 3.0). The range keeps admitting 2.x wherever the module works on both, and
  the 25 owner modules do (their chains adopt tables core already made). Never a three-segment pin.
- **Why the ceiling is the safety net.** A host cannot resolve core 3.0 with a module release that predates its own
  chain or `file_references/0`, because that release is pinned `< 3.0.0`. So the pin guarantees a chain exists
  wherever 3.0 runs, which is also what lets core drop `builtin_file_references` (open decision, step 7b).
- **Who.** All 25 owner modules, and the packages that depend on core but own no core-created table (boards,
  inbox, stats, web_analytics, db, hello_world, agent, bookings once Max's rework lands). `@impl` is added to every
  module's `file_references/0` and `expected_schema/0` in the same release, since the core floor now has the
  callbacks.
- **Order**, as in `dev_docs/2026-08-10-phoenix-kit-2.0-ecosystem-sweep.md` (workspace): core 3.0 first, then
  `phoenix_kit_ai`, then by sibling dependency (staff and entities before projects, billing before ecommerce,
  comments before its dependents), then the rest in any order. Raise sibling pins in the same commits as the core pin.
- **Core 3.0's own release notes** say: be at V225 (the last 2.x, 2.65.0) first; then upgrade core and every module together.
- Release day is the weekly one; nothing here ships before the user asks.

#### Step 10, discovery (2026-10-27)

Every package's full suite was run against core 3.0 (`core-3.0`, via `PHOENIX_KIT_PATH`) on a fresh database per
package, four at a time. Results by class (no package was changed):

- **Obsolete "core audits the tables" tests** (module chain vs core's `ExpectedSchema`; the objects are gone from core's
  manifest): customer_support 3, warehouse 2, manufacturing 2, newsletters 2, open_graph 3, projects 3, and the same
  shape in the other owners. They go, replaced by each module's own `ExpectedSchema` test (already in place).
- **A sibling's tables are no longer there** (the test setup must run the sibling's chain): warehouse, catalogue and
  publishing need ai (`phoenix_kit_ai_endpoints`, `_prompts`; ai is a dependency, so its chain is on hand); agent needs
  `phoenix_kit_ai_requests`; ecommerce needs billing's `payment_options`; manufacturing needs entities. **Undeclared
  dependencies** the tests exposed: calendar → staff (`staff_people`) and locations; sync → staff (`staff_skills`);
  inbox → emails (`email_logs`).
- **Not caused by 3.0** (to confirm against a 2.x baseline): catalogue's `Categories.create_category/N is undefined`
  (221 tests), staff's LiveView redirect tests (known locale-prefix failures), db (16), publishing (a handful).
- **Harness limits, not findings:** legal and entities insist on their own database names, photos needs an
  already-migrated database, and `No version requirement found for :phoenix_kit` appears where the harness replaced
  the dependency with a path.
- Passing outright: ai (2,296), boards, hello_world, stats, templates_editor, ecommerce unit suite, crm (2 left).

## Decisions

| Decision | Status |
|---|---|
| Follow the extraction guide; no new protocol | Made 2026-10-25 |
| Ownership authority is `ModuleOwnedTables`, not the manifest's `owner:` labels | Made 2026-10-25 |
| `phoenix_kit_consent_logs` is legal's (legal's chain owns its shape; core still creates it) | Made 2026-10-25 |
| ai's endpoints/prompts/requests move to ai (step 4) | Made 2026-10-25 — owner agreed; done in ai `c118542` |
| Step 8: (a) at 3.0 or (b) in 2.x | Made 2026-10-26 — (a) at 3.0 |
| Step 9: drop or keep each dead table | Open |

## Progress log

- **2026-10-25** — Investigation (manifest, table ownership, migration
  dependencies) and this plan. Step 1 done: `ModuleOwnedTables`, the guard test,
  docs (core, hello_world). Gate: `mix precommit` clean; full suite 89 doctests,
  12,780 tests, 0 failures (21 skipped, `:requires_createrole` excluded).
  Unreleased; ships with core's next release.
- **2026-10-25** — Step 2 done: `ModuleChainCheck`, its fixture tests, the
  fresh-install test, docs. Preview over all 25 module chains: 21 pass;
  ai and document_creator fail as expected (step 4); billing and ecommerce are
  step 5's real work. Gate: `mix precommit` clean; full suite 89 doctests,
  12,785 tests, 0 failures (21 skipped, `:requires_createrole` excluded). One
  earlier run hit a flaky async test (`MediaFiltersTest`, stack badge count;
  passes 5/5 alone, runs before any `async: false` test). Unreleased.
- **2026-10-25** — Step 3 started: comments, staff and user_connections have
  their own chains (pushed, unreleased; each ships after the core release that
  carries `ModuleChainCheck`). `dev_docs/squash/adoption_ddl.exs` added to core
  for the DDL. user_connections' floor raised to 2.22.3.
- **2026-10-25** — Step 5 started: billing V6 (`3fa1164`); the checker passes it. Unreleased.
- **2026-10-25** — Step 5: ecommerce V6 (`54061bd`) adds core V186's three columns (`ADD COLUMN IF NOT EXISTS`, no backfill) plus the builds-alone test; checker OK, 4771 tests (3 position-pinned migration tests adjusted), quality.ci clean. Unreleased.
- **2026-10-25** — Step 5: emails (`a081f13`) checked. Core's chain seeds nothing into `phoenix_kit_email_templates` (the package seeds system templates at runtime) and its one `__PK_NAME_EXEMPT__` index is already carried, so no chain change; builds-alone test added. 2028 tests green against a local core (emails pins core on Hex with no `PHOENIX_KIT_PATH` switch, so a temporary uncommitted path dep). Unreleased.
- **2026-10-25** — Step 5 finished: the builds-alone test added to catalogue `131c998`, crm `a16a608`, customer_support `80be167`, dashboards `e755a88`, entities `b24d02b`, legal `465f889`, locations `c6ef9ce`, manufacturing `b0c8ec5`, newsletters `740a0c3`, open_graph `1342c66`, posts `922793a`, projects `d587883`, publishing `ce4952c`, warehouse `4bede57`. Every one passes against local core; full suites and credo green against Hex core. legal's test points core's `:repo` env at its test repo for its own duration (its config never set it). Two failures are already there without the change and are not part of this plan: legal `DataCollectionTest` (registry) and open_graph `EditorLiveTest` (3, locale-prefixed URLs). Unreleased.
- **2026-10-26** — Step 7a done in the seven modules (see step 7): projects `e5bb40f`, posts `665847a`,
  customer_support `a667657`, ecommerce `e1fb780`, catalogue `0fd0aad`, publishing `c78f56a`, entities `a1e611c`.
  Core `dcd2416d6` exposes `Storage.builtin_file_references/0` and hands over a table a supplier names. Unreleased;
  the modules ship after the core release that reads the callback.
- **2026-10-26** — Step 7b started, option (a) chosen: `Module.expected_schema/0`, `ModuleRegistry.all_expected_schemas/0`,
  a repair pass per module manifest, `ModuleChainCheck.build_alone/4` and `generate_module_manifest.exs` in core;
  customer_support is the pilot (`ExpectedSchema`, 77 objects, plus its test). See step 7. Unreleased; the other 24
  modules are not started.
- **2026-10-25** — Step 7 started: `file_references/0` callback, registry aggregator and storage hand-over (core half);
  doctor's NULL-uuid list left in core. Unreleased.
- **2026-10-25** — Step 6 done: `ExpectedSchema` filters by `ModuleOwnedTables` (see step 6). Tests:
  `ModuleOwnedTablesTest` gains "lists core's tables only" and "lists every table of core's own", and
  reads the created tables through `ExpectedSchema.created_table_names/0` (unfiltered, goes in step 7);
  `ModuleOwnedManifestTest`'s "rest of the broadcasts table" now asserts the opposite (the whole table is
  the module's); the V167 posts-slug and V171 shop-slug manifest tests assert the objects are gone;
  `PhoenixKitRepairTest` accepts a subset of the classes. Unreleased.
- **2026-10-25** — Step 4 done: document_creator V3 (`f67f163`) and ai V5 (`c118542`); the checker passes both. Unreleased; both ship after the core release.
- **2026-10-25** — Step 3 done: sync, calendar and referrals too. sync's floor
  raised to 2.63.0; user_connections and referrals gained a test database.
  `adoption_ddl.exs` fixed for core's schema-name index convention. Builds-alone
  check over all 31 module chains: 27 pass, the other four are steps 4 and 5.
  Found on the way: staff's suite has 31 web-test failures that predate this
  work (locale prefix in its test router).

## Inventory (2026-10-25)

Tables core's chain creates, by owner. "Core changed after V135" lists the core
versions whose code names the module's tables.

**No migrations of their own (step 3):**

| Module | Tables | Core changed after V135 |
|---|---|---|
| comments | 4 | V164, V166 |
| staff | 7 | V136 |
| user_connections | 6 | V188 |
| sync | 2 | V218 |
| calendar | 2 | V141 |
| referrals | 2 | — |

**Partly on core (step 4, done):** ai — 3 of its 8 tables (V169, V193, V223);
document_creator — 7 of 8 (none after V135). Both now adopted by their chains.

**Adopted, but core still creates them first (step 5):** billing 11,
catalogue 18, posts 13, crm 10, ecommerce 10, warehouse 8, publishing 7,
emails 6, projects 6, customer_support 4, locations 4, manufacturing 3,
entities 2, newsletters 2, open_graph 2, dashboards 1, legal 1.

**Fully independent:** agent, boards, bookings, inbox, stats, web_analytics
(and ai's five newer tables).

The full table-by-table list is `PhoenixKit.Migrations.ModuleOwnedTables`.

#### Step 10, progress (2026-10-27)

Decision: tests get a sibling's tables by running the sibling's real chain in `test_helper.exs`, with the sibling as a
`only: :test` dependency (`pk_dep/3` honours `<APP>_PATH`). Pins on unpublished sibling versions resolve only once those
minors are on Hex (`staff ~> 0.11`, `locations ~> 0.8`, `emails ~> 0.7`, `crm ~> 0.18`); until then use the `_PATH` variables.

Done in the working trees (uncommitted in the module repos):
- **sync** (2201 tests, 0 failures): the sample table is core's `phoenix_kit_media_folders`; the array-column test builds its own table;
  the obsolete core-manifest test is removed.
- **calendar** (160, 0): staff, locations and crm chains run in `test_helper`; its external-items test uses its own source key
  because the real CRM source is now discovered; obsolete core-manifest test removed.
- **inbox** (844; 4 failures that are also on `origin/main`'s V225 `short_code` unique index, not 3.0): the emails chain runs in
  `test_helper`.
- **emails**: no seeding. An earlier attempt to seed the system templates from `migrate_legacy/0` was reverted: the
  database layer is being retired (see "Email templates leave the database" below).
- **core-3.0 fix**: V135 seeded email templates through the Emails module whenever it was on the code path; with the table gone the
  query aborted the migration transaction. The seeders and their manifest seed entry are removed.

Still obsolete "core audits the tables" tests to remove (same cut as sync/calendar): catalogue, comments, locations,
referrals, staff, user_connections (and the ones found in discovery: customer_support, warehouse, manufacturing, newsletters,
open_graph, projects).

#### Email templates leave the database (decided 2026-10-27, not started)

Email templates now live in files (`phoenix_kit_templates` overrides, edited with `phoenix_kit_templates_editor`) with
shipped defaults from core and modules (`PhoenixKit.Email.Catalog`). The database layer is retired in 3.0:
- core's `Email.Content` resolves file override, then default; no `Provider.get_active_template_by_name` row lookup;
- Emails drops the `Template` schema, the row-editing admin pages and `TemplateSources`' "hides" badges; its chain
  stops creating `phoenix_kit_email_templates`;
- upgrade path: `mix phoenix_kit_emails.templates.export` writes existing rows to files first; the table itself is a
  step 9 per-table decision, never dropped by a chain;
- core's V135 no longer seeds templates (done on `core-3.0`).

**Sizing (2026-10-27).**
- *Core, small:* the row layer is one branch in `Email.Content.resolve_with_sources/5` plus the `Provider` callbacks
  `get_active_template_by_name/1`, `render_template/3`, `track_usage/1`, `get_source_module/1` (`provider.ex`,
  `default_provider.ex`), the `db_template` field read by `Mailer` (usage tracking, send options) and `Email.Catalog`
  (`missing/6`). About 6 files, mostly deletions; `DefaultProvider` already answers `nil`.
- *Emails, the bulk:* `templates.ex` (2132 lines; row CRUD, `seed_system_templates`, usage stats), `template.ex` (896),
  `provider.ex`, `template_sources.ex`, `template_export.ex` (kept, it is the upgrade path), the editor and list pages
  (`web/templates*`, `web/template_editor*`, about 3000 lines with heex) and their routes/tabs, plus 18 test files.
  `Templates.send_email/4` is NOT a row API: it delegates to `Mailer.send_from_template/4` and billing calls it, so the
  facade stays (moved to a small module) or billing is repointed first.
- *Other modules:* billing only uses `send_email/4`; newsletters' chain reads `phoenix_kit_email_templates` once to carry rows
  over and already tolerates the table being absent; `phoenix_kit_templates_editor` calls `get_active_template_by_name`
  in `overriding.ex` (to warn that a row hides a file) and loses that check.
- *Order:* Emails 3.x drops the pages and schema first while core still accepts a provider returning rows; then core drops
  the layer at 3.0. Behavioural break: a host that edited templates in the admin UI must run the export before upgrading.

#### Step 10, test cleanup (2026-10-27)

Status in the module working trees (all uncommitted), full suite against core 3.0 on a fresh database:
- **Green:** sync, calendar, billing, customer_support, dashboards, manufacturing, open_graph, posts, publishing,
  warehouse, catalogue, comments, locations, referrals. Not yet re-run after the manifest-test removal: staff,
  user_connections, entities, legal (their remaining failures below).
- **Obsolete "core audits the tables" tests removed** (the module's own manifest and builds-alone tests cover them) in
  billing, calendar, catalogue, comments, customer_support, dashboards, emails, entities, legal, locations,
  manufacturing, newsletters, open_graph, posts (its shape-identity file is deleted), publishing, referrals,
  staff, sync, user_connections, warehouse; the helpers and attributes only they used went with them.
- **Sibling chains** run in `test_helper.exs` (real chains, dependency order) in catalogue, publishing, warehouse,
  manufacturing, newsletters, projects, calendar, inbox; projects' two builds-alone tests pass the new
  `ModuleChainCheck.check/3` and `build_alone/4` option `after: [chains]` (core `core-3.0`).
- **Remaining, not 3.0:** `core_pin_conformance_test` fails in every module until its pin is widened (the next sub-step) and
  under the harness' path swap; staff `header_trail_test` (6), projects `portal_live_test`/`project_calendar_live_test`
  (2) and inbox `short_code` (4) fail identically on `origin/main`; legal `data_collection_test` and entities
  `schema_owner_guard_wiring_test` (own-database harness limit) are unverified.
- **Not yet looked at beyond discovery:** agent, photos, ecommerce (3493 excluded), crm, newsletters/emails integration
  exclusions.

#### Step 10, pins and `@impl` (2026-10-27)

- Every module (bookings and the stub `phoenix_kit_templates` left alone) now pins core as `>= <floor> and < 4.0.0`. The 25
  owners plus the modules that implement the callbacks take floor `2.65.0` (assumed: the first minor after 2.64.1 that
  carries `file_references/0`, `expected_schema/0` and V225; adjust if the release is numbered differently); the rest keep
  their floor and only raise the ceiling. `file_references/0` and `expected_schema/0` carry `@impl PhoenixKit.Module`.
  Each `core_pin_conformance_test` admits 3.x and rejects 4.0.0, verified against the requirement strings
  (the tests themselves cannot run until 2.65.0 is on Hex).
- Found by the hidden-dependency audit (modules reading another module's table by name): `calendar` listed events with a
  query naming staff and CRM tables, and `crm` read `phoenix_kit_staff_people`, so on core 3.0 both failed on a host without
  those modules (crm swallowed it and answered empty). Both now check the table first; calendar has a regression test.
  `document_creator`'s tests build Projects' chain (test-only dep). Remaining cross-module reads are declared
  dependencies or already guarded (ecommerce→ai, inbox→emails, projects→staff).
- Not 3.0: db, staff and projects live-view failures and inbox `short_code` reproduce on `origin/main`.
- Nothing is committed in the module repos; every change is in the working trees.

#### Email templates leave the database, core half (2026-10-27, done on `core-3.0`)

Removed: the DB branch of `Email.Content.resolve_with_sources/5` (and `db_sources`, the `:db` source, `db_template` in
`resolved()`), the template callbacks of `Email.Provider` and `DefaultProvider`, `Mailer.track_usage_after_delivery/2` and its
callers (`Mailer`, `UserNotifier`, the notification email channel), `Catalog`'s DB special case, the preview's DB notice
and badge. Tests that stubbed a DB provider were removed or rewritten (welcome-email build failures are now injected with a
non-path template root; the exit/throw variants of that test went with the provider). Core tests: 1796 in the email,
mailer, users, notifications and settings areas, 0 failures. The Emails half and the editor follow.

`phoenix_kit_email_templates` is no longer in `ModuleOwnedTables`: no chain creates it any more (core's V135 does not,
Emails' V1 does not adopt it). Hosts that have it keep it untouched; dropping it is a step 9 per-table decision after the
export has been run.

#### Email templates leave the database, Emails and editor halves (2026-10-27, committed locally, not pushed)

- **Emails:** admin pages and tabs, row CRUD, seeding, the Provider template callbacks and the "db" layer of
  `TemplateSources` are gone; `Templates` keeps `send_email/4` (billing calls it) and a few helpers; `Template` is a read-only
  struct for the export. `TemplateExport` and the mix task stay as the upgrade path and tolerate an absent table;
  `TemplateExport.active_template/1` serves the editor. Chain: V1 no longer adopts the table, V3's html rewrite is guarded by
  `to_regclass`; manifest regenerated (11 tables). Suite against core-3.0: 1682 tests, 0 failures besides the pin test.
- **templates_editor:** reads the legacy row through `active_template/1`; the "a database template is what is sent" notice is gone.
- **Open at release prep:** Emails now works only on core 3.0, so its core floor must become `>= 3.0.0` (it is still 2.65.0 in
  mix.exs, which would let a 2.x host resolve a combination that breaks); old log rows keep a "Database template" badge; the
  test email can no longer be overridden by a file.

#### Release order and version bumps (prepared 2026-10-27, committed in each module repo, not pushed)

Every module except `phoenix_kit_bookings` (Max's rework), the `phoenix_kit_templates` stub and `phoenix_kit_photos` (never
released; stays 0.1.0) has a "Bump version to X" commit: the next minor, `## Unreleased` renamed to `## X - 2026-11-13`
(a placeholder date; change it to the real release day), `version/0` and version tests updated, and the sibling pins moved to
the first release that carries that sibling's own chain (`~> 0.27` for ai, `~> 0.24` billing, `~> 0.5` comments, `~> 0.7`
entities, `~> 0.8` locations, `~> 0.11` staff, `~> 0.50` catalogue, `~> 0.15` publishing, `~> 0.18` crm, `~> 0.7` emails,
`~> 0.32` projects, `~> 0.7` warehouse). Until a sibling is on Hex, `mix deps.get` in a module that pins it fails; locally set
`PHOENIX_KIT_<APP>_PATH`. A module whose sibling dependency is a plain tuple (publishing and posts → comments, legal →
publishing, newsletters → crm) cannot resolve locally at all until that sibling is published.

Release order (each tier after the previous one is on Hex):
0. **core 2.65.0**, then **core 3.0.0**.
1. no module dependencies: comments, ai, billing, entities, locations, emails (needs core 3.0), db, boards, stats, hello_world,
   web_analytics, customer_support, dashboards, referrals, open_graph, user_connections, sync, templates_editor.
2. staff, crm, posts (comments); publishing, agent (ai); catalogue (ai, entities); manufacturing (comments, entities, locations).
3. projects (ai, staff, comments, entities); legal (publishing); warehouse (billing, ai, catalogue, comments, locations);
   then ecommerce (billing; warehouse optional) and the modules whose test-only siblings are now published: calendar,
   inbox, newsletters, document_creator.
Tags: `v`-prefixed for the repos AGENTS.md lists (and boards, agent, projects...), bare otherwise; check `git tag --sort=-creatordate`.
