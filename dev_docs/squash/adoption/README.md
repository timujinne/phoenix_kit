# Adoption tooling

Maintainer tooling for moving a module's tables out of core: a module's V1
re-states the tables core's chain creates for it, exactly as a fresh core
install builds them (the extraction guide's Phase 0;
`dev_docs/plans/2026-10-25-module-table-ownership.md`, steps 3–5). Not shipped,
not compiled.

| File | What it does |
|---|---|
| `../adoption_ddl.exs` | Builds a fresh core install into a scratch schema and prints the given tables' DDL: `CREATE TABLE IF NOT EXISTS` (columns in order), every constraint as a `guarded_constraint/4` call, every index not backing a constraint, with `#{p}` for the schema and `#{np}` for core's schema-name index convention; plus triggers and seed rows to handle by hand |
| `gen_chain.py` + `template_*.ex(s)` | Turns that output and a small JSON config into `<App>.Migrations` (V1, the shape of `phoenix_kit_comments`' chain), `migrations_test.exs` (every name pinned, FK actions, prefix threading, the drift lock against core's manifest) and `migrations_build_alone_test.exs` (core's `ModuleChainCheck`) |
| `example_sync.json` | The config `phoenix_kit_sync`'s chain was generated from — copy it per module |
| `check_module_chains.exs` | Runs `PhoenixKit.TestSupport.ModuleChainCheck` over every module chain in the workspace from core's test VM (module beams from their own `_build/test`) |

## Making one module's chain

```bash
# in core
MIX_ENV=test mix run --no-start dev_docs/squash/adoption_ddl.exs \
  dev_docs/squash/adoption/<module>_ddl.ex <table> <table> ...
cd dev_docs/squash/adoption && cp example_sync.json <module>.json   # edit it
python3 gen_chain.py <module>.json && rm <module>_ddl.ex <module>.json
```

Then by hand, in the module (comments, staff, sync and referrals are worked
examples, by commit, in the plan's step 3 table):

1. `migration_module/0` returning the chain.
2. `test_helper.exs`: after `PhoenixKit.Migration.ensure_current/2`, replay
   `Migrations.up_statements("public")` through the repo when
   `migrated_version_runtime/0` is behind; exclude `:requires_module_chain_check`
   unless `Code.ensure_loaded?(PhoenixKit.TestSupport.ModuleChainCheck)`.
   A module with no test database gets one (user_connections, referrals).
3. The core floor: at least the core release carrying every core version that
   shaped the tables (V1 can fail over an older core's tables).
4. AGENTS.md (it no longer "owns no migrations"), CHANGELOG `Unreleased`.
5. `mix precommit`, the full suite, and the builds-alone test against local
   core: `PHOENIX_KIT_PATH=../phoenix_kit mix deps.get && mix test <file>`, then
   restore `mix.lock` from a copy and `mix deps.get` (never commit the path
   lock). A module without `pk_dep/3` is checked with `check_module_chains.exs`.

The `template_*` files are not valid Elixir (`@@NAME@@` placeholders): core's
format-on-edit hook (`.claude/hooks/format-edited-file.sh`) reports a failure
when one is edited, and that is expected. `mix format` and credo never read
`dev_docs/`.

The generator handles the common cases; read what it writes. It asserts when a
constraint name uses `#{np}` (none so far) and reports triggers and seed rows,
which it does not generate.
