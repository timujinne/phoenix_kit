# PhoenixKit core 3.0 review — Codex

Date: 2026-10-27. Read-only source review; no commits, pushes, tags, releases, or publishing.

## Current status — follow-up on `f1f3ec4b2`

**The four original findings are addressed. No new blocking finding was identified in the fix commit.** Independently re-ran precommit, 104 targeted tests on the upgraded V225 database, and 34 tests on a newly created database; all passed. Both original ownership reproductions now pass. The full follow-up evidence is recorded at the end of this document. The original review below is retained as history and its initial verdict is superseded by this status.

## Original verdict — `ae0a44a22`

Do not give this branch unconditional release sign-off yet. The normal V225 upgrade and genuinely empty fresh-install paths passed the checks below, but the ownership boundary still has a demonstrated data-deleting exception, the upgraded-database suite has a new fixture regression, and the public upgrade documentation is unfinished. No critical issue was found in the exercised normal upgrade path.

## Scope and review tree

- Branch snapshot: `core-3.0` at `ae0a44a227caf4b78d0f2ecd2ffeaa3a91fdfbd4`.
- Main and `v2.65.0`: `60c1faa9e640c298e916fac4b6a4f861be81235a`.
- Isolated worktree: `/tmp/codex-pk3-review-20261027`. Main was merged there with `--no-commit --no-ff`; no merge commit was created and the original branches were not advanced.
- Both S3 fixes from the handoff were already ancestors of the reviewed branch. The remaining merge conflicted in `CHANGELOG.md` and `dev_docs/plans/2026-10-25-module-table-ownership.md`. For validation only, retained the 3.0 entry and corrected the 2.65 entry date to 2026-10-27; retained the branch's V225 plan and progress notes.
- No conflicts in `mix.exs`, `mix.lock`, or the migration manifest. Kept version 3.0.0 and main's eight lock updates. The stamped chain hash matches all 91 migration files: `b7af0c54300f13e6e7b55a00c7375cdf0fa77930f0001bb52f1314c99e2cf3d7`.
- No pull request exists for `core-3.0` in the queried PR list; `unassigned-core-3.0` is used instead of inventing a PR number.

## Findings

### BUG - HIGH — Catalog-driven core repairs still mutate module-owned tables

References: `lib/phoenix_kit/migrations/postgres/v163.ex:93`, `lib/phoenix_kit/migrations/postgres/v176.ex:89`, `lib/phoenix_kit/migrations/uuid_integrity.ex:243`; coverage gap at `test/phoenix_kit/migrations/module_owned_tables_test.exs:105`.

Removing literal module DDL left two indirect paths behind. V163 asks `UUIDIntegrity.broken_tables/2` for every broken `phoenix_kit_*` UUID column, without filtering ownership, then can rewrite the column, backfill it, delete duplicate rows, and add a primary key. V176 iterates the shared `UUIDFKColumns.fk_constraints/0` list, which still includes module tables, and issues `ALTER TABLE ... VALIDATE CONSTRAINT` against them. Neither version contains the literal module-table names that the new ownership test scans for, so that guard passes.

**Executed reproduction:** in a scratch schema with no core installation marker, created `phoenix_kit_email_events(uuid text, payload text)` containing two rows sharing a valid UUID and analyzed the table. Ran the real full `PhoenixKit.Migration.ensure_current/2` chain. V163 logged that it would delete one row and the row count changed from 2 to 1. A separate real Ecto migration invoking V176 changed an empty module comments FK from `convalidated = false` to `true`. Two ad hoc tests asserting the ownership contract fail on exactly those mutations.

**Scope:** an ordinary 2.x database at V225 is unaffected: it skips both historical versions. A genuinely empty fresh database has no module tables to touch either. The demonstrated failure occurs when module tables pre-exist and core is installed from version 0, a path the migrator accepts. The current claim that no core version touches a module table is therefore false, and the V163 path can destroy module data.

Filter both migration entry points to tables owned by `:core` (or turn their historical module portions into stubs), leaving explicit diagnostic/repair tooling independent as needed. Add a behavioral ownership test with pre-existing module tables; a literal-name scan cannot enforce this invariant. Restamp the chain hash after the final migration edits and re-run the manifest checks.


### BUG - MEDIUM — New storage fixtures break suites using an upgraded 2.x database

References: `test/support/module_fixture_tables.ex:18`, `test/support/module_fixture_tables.ex:56`; callers `test/integration/storage_catalogue_orphan_test.exs:28` and `test/integration/storage_module_file_references_test.exs:24`.

`create!/1` unconditionally creates tables that a 2.x database already contains. Upgrading to 3.0 deliberately preserves those tables. Running the requested suite against the existing V225 `beamlab_test` therefore fails before the affected test bodies execute: 10 module-file-reference tests fail on `phoenix_kit_post_media`, and 15 catalogue-orphan tests fail on `phoenix_kit_cat_catalogues`, all with PostgreSQL `42P07 duplicate_table`.

This is a regression in the test harness, not a PostgreSQL permission issue or a planner flake. Make fixture creation tolerate already-existing compatible tables, or isolate the fixtures so both fresh and upgraded databases are valid test substrates. Preserve the real legacy tables rather than requiring users to destroy their test database to validate an upgrade.

### IMPROVEMENT - HIGH — Finish the operator-facing 3.0 upgrade documentation

References: `README.md:32`, `README.md:65`, `README.md:84`, `README.md:308`; `guides/integration.md:52`, `guides/integration.md:68`; `dev_docs/plans/2026-10-25-module-table-ownership.md:504`.

The CHANGELOG describes the V225 / 2.65.0 bridge correctly, but README still presents the 2.0 upgrade as the current major upgrade and its dependency examples select 2.x. The linked integration guide still selects 1.7. There is no 3.0 upgrade guide. The plan's release instructions still say V224 in one place, contradicting the actual gate.

Add and link the requested operator recipe: pin 2.65.0, fetch dependencies, run `mix phoenix_kit.update` and any generated migrations until the target database/prefix reports V225, export edited email templates before removing their database reader, then update core and all installed modules to compatible versions together and run the module migrations. Include the canonical public API paths and declarations that replace the removed names. Keep earlier major-upgrade guidance explicitly historical.

### IMPROVEMENT - MEDIUM — Commit database-backed upgrade-gate coverage

Reference: `test/phoenix_kit/migrations/postgres_below_floor_test.exs:139`.

The new test named "refused with the bridge named" calls only `plan_up/4`; it does not call the migrator or assert that an exception message names 2.65.0. The bridge test accepts any 2.x version and checks only `minimum <= current`. This cannot catch a regression in `up/1`'s later exception/bypass logic or prove that the shipped bridge builds the accepted schema. Keep a real V224 refusal / V225 acceptance test, plus interrupted fresh-install recovery, in the repository.

## Executed verification

Environment: Elixir 1.19.6, OTP 28.5.0.8, PostgreSQL 18.4. PostgreSQL was reachable; the full suite used the existing V225 `beamlab_test`. All Mix invocations were sequential. `PGPOOL=12` was used with `--max-cases 8`.

| Check | Result |
|---|---|
| `PGDATABASE=beamlab_test PGPOOL=12 mix precommit` | Exit 0. Compilation, unused-lock check, test-file compilation, formatting, strict Credo, Dialyzer under the existing ignore configuration, and 476 JavaScript tests passed. |
| `PGDATABASE=beamlab_test PGPOOL=12 mix test --max-cases 8` | Exit 2 after 1142.9 seconds: **89 doctests, 12,861 tests, 26 failures, 38 skipped (1 excluded)**. |
| Full-suite failure classification | **25 new fixture collisions** in finding 2; **one media-filter assertion** at `test/integration/phoenix_kit_web/live/users/media_filters_test.exs:167`. That media-filter test passed when re-run alone. |
| Known environment/planner caveats | Only `:requires_createrole` was excluded by preflight. V220's known planner-flake test did not fail in this run. No trigger-disabling permission failure was reported; none of the 26 failures is classified as an environmental permission error. |
| Fresh-database focused run | **1 doctest, 101 tests, 0 failures** on newly created `codex_pk3_review_test_20261027`; integration tests ran. |
| Ad hoc real-database upgrade and ownership tests, plus isolated media-filter rerun | **6 tests, 2 failures**: the two failures intentionally assert module-table non-interference and expose V163/V176. V224 refusal, V225 acceptance, interrupted fresh-install recovery, and the isolated media-filter test passed. |
| 25-module rehearsal | Exit 0. Name order fails on missing `phoenix_kit_staff_teams` while projects runs; dependency order passes. |
| Whole-schema comparison with 2.65.0 | Raw compare exits 1 with **35 differences, all objects of `phoenix_kit_email_templates`**, intentionally retired on fresh installs. No differences outside that table were reported after the script's existing guarded-project-FK exclusion. |

### Real upgrade-gate proof

Used the migration source from the exact `v2.65.0` tag, loaded only into a separate review process, to build scratch schemas `cdx3_old224` and `cdx3_old225` through the real old chain. This did not recompile or modify the main checkout.

In the normal 3.0 test process:

- `PhoenixKit.Migration.ensure_current(Repo, prefix: "cdx3_old224", log: false)` raises `PhoenixKit.Migrations.BelowFloorError`; assertions verify `db_version == 224`, `floor == 225`, and a message containing `2.65.0`. The version marker stays 224 and the captured column shapes stay unchanged.
- The same call on `cdx3_old225` succeeds. Assertions verify the marker stays 225, column shapes stay unchanged, and an inserted legacy module comment still contains `preserve-me`.
- A chain genuinely built by 3.0 only through V162, with no module tables, successfully resumes to V225. This is the deliberate fresh-install recovery exception, not an old 2.x upgrade.

### Fresh install, manifests, callbacks, and ordering

The focused run included these files:

```text
test/integration/prefix_migration_test.exs
test/integration/fresh_install_manifest_test.exs
test/integration/repair_module_manifest_test.exs
test/integration/storage_catalogue_orphan_test.exs
test/integration/storage_module_file_references_test.exs
test/phoenix_kit/migrations/module_owned_tables_test.exs
test/phoenix_kit/migrations/postgres_below_floor_test.exs
test/phoenix_kit/migrations/modules_test.exs
test/phoenix_kit/test_support/module_chain_check_test.exs
test/phoenix_kit/api/module_neutral_test.exs
test/mix/tasks/phoenix_kit_release_check_test.exs
```

The newly created database contains exactly **40 `phoenix_kit*` tables** in public after core's chain. Fresh-install tests also compare the actual table set with `ModuleOwnedTables.core_tables/0`, reject module tables, and verify the real schema against core's manifest in a scratch schema. The prefix test runs the full chain in a named schema. The ownership source scan passes across every retained version, including V224/V225; finding 1 explains its blind spot in earlier versions.

The module-manifest fixture tests exercise repair dispatch, version gating and tagged findings. Storage-reference tests exercise handover, missing tables, modules without the callback and fail-closed errors. Those tests pass on a fresh substrate; their failure on the upgraded substrate is fixture setup, not an assertion that the callback logic is wrong.

Ran the rehearsal using current `/workspace` module migration sources and the existing script's normalizations. The baseline used 2.65.0's migration sources with those same current module chains. It recorded 220 tables, 2,571 columns, 782 indexes, 628 constraints, 7 sequences, 10 functions, 119 seeds and 8 triggers. Compared the 3.0 build against that record. The only reported differences are the retired template table, its 20 columns, primary-key constraint and 13 indexes. The script intentionally excludes `phoenix_kit_doc_documents_project_uuid_fkey`; that conditional FK is not claimed to match. Column positions, certain equivalent expression spellings and clock-stamped seeds are normalized by the script, so this is its structural comparison, not a byte-for-byte dump comparison.

The rehearsal correctly proves the dependency order matters: projects fails before staff in the control run and succeeds in the dependency-ordered run. Its prerequisite edges correspond to the actual hard dependencies in the inspected module source; core's `Modules.order_by_dependencies/1` obtains its graph through loaded OTP applications rather than display names.

## Source inspection and limits

- Reviewed the branch changes against main, the ownership plan and progress notes, project conventions, prefix rules, migration dispatch, retained repair helpers, manifest filtering, callback aggregation, module migration sorting, email resolution/provider removal, API removal, routing and operator docs.
- V224 and V225 themselves operate on core tables. No new module-owned DDL after V223 was found. The remaining ownership violations are the indirect earlier V163/V176 paths described above.
- No runtime references to `PhoenixKit.API.Legacy`, `check_cart_rows/1`, removed template-provider callbacks, `track_usage_after_delivery/2`, or `content.db_template` remain in core. `ModuleNeutralTest` passed. The only allowed shop-era name inside the machine API is the intentionally retained database column mapping `source: :cart_token_hash`; this does not require a migration to rename stored data.
- The API routing tests in the full suite passed, including rejection of the removed `/api/shop/v1` and `/mcp/shop` forwards. Old alias strings in tests are rejection cases, not served routes. Neither compiled build retains a Legacy BEAM artifact.
- Legacy email-template names remain in historical/diagnostic migration metadata such as `UUIDFKColumns`; they are not runtime email-template readers. Core no longer asks the email provider for a database template, and the preview and callers use the file/default result shape.
- Core's built-in optional storage references remain guarded by table existence; supplied module callbacks take over their owned references and errors fail closed. No additional dangling core runtime table query was identified in this scan.
- Actual module migration chains were exercised for all 25 owner modules. Callback mechanics were exercised using core's fixture tests; **this review did not run every external module's full application suite, validate each installed module's real manifest through a production application registry, test a production database, or prove a published Hex dependency resolution for the future ecosystem release**. Those are separate from the core verification above. No claim of complete ecosystem release readiness is made.
- The test role cannot exercise every skipped privileged test. A green focused result is not a claim about those skipped paths.

## Reproduction artifacts and cleanup

Review-only drivers and logs are in `/tmp`:

```text
/tmp/codex-pk3-precommit.log
/tmp/codex-pk3-full-suite.log
/tmp/codex-pk3-build-old.exs
/tmp/codex-pk3-build-old.log
/tmp/codex_pk3_review_test.exs
/tmp/codex-pk3-proofs.log
/tmp/codex-pk3-focused.log
/tmp/codex-pk3-record-old.exs
/tmp/codex-pk3-record.log
/tmp/codex-pk3-baseline-v2.term
/tmp/codex-pk3-compare.log
/tmp/codex-pk3-rehearsal.log
```

The two old-version scratch schemas and the two newly created databases were removed after validation. Existing `beamlab_test` was not reset or dropped. The isolated worktree remains available with its local uncommitted merge for inspection. `/workspace/phoenix_kit` remains on main; the only added workspace document is this review. No production source was edited, committed, pushed or published.


## Follow-up review — 2026-10-27, `f1f3ec4b2`

Reviewed all 12 files changed by `f1f3ec4b2670c39a484531d03028c57825f57df6` against `ae0a44a22`. Confirmed the remote `core-3.0` head with `git ls-remote`: it points to the fix commit. Updated the existing isolated review worktree to that commit and again combined main there without creating a merge commit. The two documentation conflicts were resolved only in that scratch tree; no source edits were made to either original branch.

### Disposition of the original findings

| Finding | Disposition |
|---|---|
| BUG - HIGH: V163/V176 mutate module-owned tables | **Resolved.** V163 filters discovered broken tables to `ModuleOwnedTables.owner(name) == :core` before repair. V176 filters its constraint list by the table being altered. Re-ran the original reviewer reproductions unchanged: the module email-events table retains both duplicate rows and its text UUID column; the module comments FK remains NOT VALID. |
| BUG - MEDIUM: storage fixture collisions on upgraded databases | **Resolved.** Fixture DDL replaces legacy tables inside the sandbox transaction. All 25 previously failing storage tests pass on the existing V225 database and on a fresh database. Public column, constraint and index snapshots taken before and after the upgraded-database test run are identical (4,783 catalog rows), confirming that the temporary swaps and cascading constraint drops roll back. |
| IMPROVEMENT - HIGH: missing 3.0 operator documentation | **Addressed.** `guides/upgrading-to-3.0.md` gives the 2.65.0/V225 bridge, prefix handling, pre-upgrade template export, coordinated module upgrade and API removals. README links it, marks the old 2.0 guidance historical and updates dependency examples; integration examples now select 3.x. The guide is included in the ExDocs extras. The plan's stale V224 release instruction is corrected. |
| IMPROVEMENT - MEDIUM: real-migrator upgrade-gate coverage | **Addressed.** New committed integration tests invoke `ensure_current/2` against database fixtures, verify V224 refusal with the bridge named and unchanged marker/data, and check acceptance at the current minimum. These are minimal database fixtures; the full tagged-2.65.0 chain proof is the earlier review evidence, not what these new committed tests build. |

The 2.65.0 date difference is merge housekeeping, not a remaining correctness finding. The branch's entry still reads the planned 2026-10-30 date; main's existing entry is dated 2026-10-27. In the scratch merge, retained main's date for the already-existing 2.65.0 entry and kept the new 3.0 section. No date was changed on `core-3.0` by this review.

### Independently executed checks

- **`mix precommit`: exit 0**, including compilation, test-file compilation, formatting, strict Credo, Dialyzer under the existing ignores, and all **476 JavaScript tests**.
- Recomputed the hash of all **91** migration files: **`83a2ad46d1aeedffb8341f19b27c3f9c4d84062f874409bdbc25e431aedaf9d4`**, matching the updated manifest stamp.
- **104 targeted tests, 0 failures** on the existing `beamlab_test`, using `PGPOOL=12` and `--max-cases 8`. PostgreSQL was connected. This included both original ad hoc ownership reproductions, both new integration files, both storage suites, fresh-install manifest and prefix tests, existing UUID repair and V176 tests, **V220's 17 tests**, the ownership guard, and release-check tests. The three other tests in the original reviewer file were deliberately excluded by line selection; they were not failures or silently DB-excluded integration tests.
- **34 tests, 0 failures** on new `codex_pk3_followup_test_20261027`: both new integration files, both storage suites, the full named-prefix chain and fresh-install manifest tests. Its public schema was built from empty by the normal test helper.
- Compared public catalog snapshots before and after the upgraded-database run; **identical**. The original database remains at V225.
- All Mix invocations were sequential. The follow-up scratch database was removed afterward. No test database was reset.

Logs and snapshots:

```text
/tmp/codex-pk3-followup-precommit.log
/tmp/codex-pk3-followup-targeted.log
/tmp/codex-pk3-followup-fresh.log
/tmp/codex-pk3-followup-catalog.sql
/tmp/codex-pk3-followup-catalog-before.txt
/tmp/codex-pk3-followup-catalog-after.txt
```

### Scope of the follow-up conclusion

The fixes close the findings from the original review; no new blocker was found in this commit. **This follow-up did not repeat the entire ~19-minute suite or all 25 module-chain rehearsals.** Claude's supplied result of 12,867 tests with one V220 planner failure is reported evidence, not an independently reproduced full-suite result here. The isolated V220 suite did pass independently in this follow-up, and the earlier 25-module rehearsal remains recorded above. The original limits concerning external module application suites, privileged skipped cases and future published Hex dependency resolution still apply.

`/workspace/phoenix_kit` remains on main. Only this untracked review document was updated there. No production source was edited, committed, pushed or published.
