# Module tables: every module owns its own

**Status:** in progress — steps 1–3 done, step 4 done, step 5 started (billing and ecommerce done; emails and the 15 passing modules left), all unreleased. See the
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

**Next: step 5** (step 4 is done; billing and ecommerce are done). The failing chains shared one shape:
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
| 5 | The step-2 test in every adopted module; fix what it finds | 17 modules | In progress — billing (`3fa1164`) and ecommerce (`54061bd`) done 2026-10-25; emails seeds/index, then the test in the 15 that pass |
| 6 | Core's manifest hands every module-owned entry over | core | Not started |
| 7 | Manifest generator (frozen pre-squash part + generated rest, compact, in `priv/`); move core's hard-coded module-table lists to module callbacks | core | Not started |
| 8 | Core stops creating module tables on fresh installs | core | Not started — approach to decide |
| 9 | Dead tables (`crm_user_role_view`, `email_metrics`, `email_orphaned_events`) | crm, emails | Not started — per-table decision |

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

### Step 6 — core's manifest lets go

Remove every module-owned object from `ExpectedSchema` (the guide's Phase 1 for
all of them at once), using `ModuleOwnedTables`; `doctor`/`repair` then check
core's tables only. Requires steps 3–5, so each module can vouch for its own
tables. Later, step 7's generator can produce a manifest per module so repair
checks module tables again, owned by the module this time.

### Step 7 — generated manifest

Split the manifest: a frozen part for what only the pre-squash chain could know
(entries born at or below V135, their old revisions, `legacy_optional`) and a
part generated by replaying V135→head with `generate_baseline.exs`'s catalog
snapshots. One line per object, stored in `priv/` and read only when repair or
doctor runs, with a test that fails when it is stale. Also move core's
hard-coded module-table lists (storage's orphaned-file check, doctor's
NULL-uuid check) to module callbacks.

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

### Step 9 — dead tables

`phoenix_kit_crm_user_role_view` (CRM copied it into core's view preferences,
V7), `phoenix_kit_email_metrics` and `phoenix_kit_email_orphaned_events` (no
reader). Dropping deletes data: an explicit decision per table, done in the
owning module's chain, never core's.

## Decisions

| Decision | Status |
|---|---|
| Follow the extraction guide; no new protocol | Made 2026-10-25 |
| Ownership authority is `ModuleOwnedTables`, not the manifest's `owner:` labels | Made 2026-10-25 |
| `phoenix_kit_consent_logs` is legal's (legal's chain owns its shape; core still creates it) | Made 2026-10-25 |
| ai's endpoints/prompts/requests move to ai (step 4) | Made 2026-10-25 — owner agreed; done in ai `c118542` |
| Step 8: (a) at 3.0 or (b) in 2.x | Open |
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
