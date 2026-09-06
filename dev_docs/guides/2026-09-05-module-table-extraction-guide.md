# Module-owned tables: extracting them from core

Core's baseline (V135) still creates tables that belong to modules
(`phoenix_kit_shop_*`, `phoenix_kit_cat_*`, `phoenix_kit_entities*`, …).
The protocol for a module to take ownership without a breaking core release
is written once, in the Hello World template module:

* `phoenix_kit_hello_world` README → `## Database conventions` →
  `### Versioned migrations` → `#### Adopting a table core already creates (extraction)`
* template coordinator: `lib/phoenix_kit_hello_world/migrations.ex`
* live examples: `phoenix_kit_legal` (`phoenix_kit_consent_logs`,
  `dev_docs/reports/2026-08-10-consent-logs-extraction.md`),
  `phoenix_kit_billing` (`phoenix_kit_payment_provider_configs`),
  and since 2026-09: `phoenix_kit_catalogue` (`pkc_schema`),
  `phoenix_kit_entities` (`pkn_schema`), `phoenix_kit_ecommerce` (`pke_schema`).

The three phases, in one paragraph each:

**Phase 0 — adopt.** The module ships V1 whose every statement is
`CREATE … IF NOT EXISTS` / guarded `DO $$ … $$`, shape- and name-identical
to core's objects, and stamps a namespaced `COMMENT ON TABLE` marker
(`<ns>_schema:1`) on one designated table. `down/1` only unstamps. Core
keeps creating the same tables; nothing changes for hosts.

**Phase 1 — first shape change.** Before releasing a module V2 that alters
one of these tables: add the changed objects to `@excluded_exact` in
`dev_docs/squash/generate_baseline.exs`, regenerate `ExpectedSchema`, and
raise the module's core version floor — otherwise `mix phoenix_kit.repair`
reverts the change on every run.

**Phase 2 — core stops creating.** Only at core's next baseline squash does
core drop its copy of the DDL. The module's V1 must already be able to
create the tables from scratch. Core never drops module tables
conditionally ("if the module is absent") — uninstall is a documented
manual step in the module README.

Tables that a module has stopped using but that core still creates (for
example `phoenix_kit_shop_products` once the shop reads products from
`phoenix_kit_catalogue`) are marked with a `COMMENT ON TABLE … 'deprecated
<date>: …'` by the host app, never dropped by anyone in this cycle; the
squash of Phase 2 decides their fate.
