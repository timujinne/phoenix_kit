# AGENTS.md

**PhoenixKit** — foundation for building Elixir/Phoenix apps (SaaS, ERP, marketplaces, AI apps, community platforms). Library-first architecture with Phoenix/PostgreSQL: auth + Magic Links, role-based access (Owner/Admin/User), admin dashboard, daisyUI 5 themes, versioned migrations, layout integration with parent apps.

## Workflow

0. **First clone only:** `git config core.hooksPath .githooks` — enables the
   tracked pre-commit hook (`.githooks/pre-commit`). Git deliberately will not
   do this for you: a clone must not be able to run code on checkout, so one
   manual command is the floor. `mix phoenix_kit.doctor` reports it under
   "Git Hooks" when it is missing, and distinguishes "not enabled" from
   "could not check".
1. Make changes
2. `mix precommit` — compile (warnings as errors) + `deps.unlock --check-unused` + `quality.ci` (format-check, credo --strict, dialyzer) + JS tests. **Does NOT run `mix test`** — see "CI/CD" below.
3. Fix problems
4. `git diff` / `git status` → commit

## Development Commands

- `mix setup` — full setup; `mix deps.get` — deps only; `mix ecto` — list ecto commands
- `mix format`, `mix credo --strict`, `mix dialyzer`, `mix quality`, `mix quality.ci`

### Tests

Two levels: **unit** (`test/phoenix_kit/`, `test/modules/` — no DB) and **integration** (`test/integration/`, `test/modules/*/integration/` — real PostgreSQL via Ecto sandbox).

```bash
mix test.setup    # create DB + run migrations (first time)
mix test          # run all (migrations auto via test_helper)
mix test.reset    # drop + recreate
```

Test DB `phoenix_kit_test` uses embedded `PhoenixKit.Test.Repo` (`test/support/test_repo.ex`). Schema comes from the versioned migration chain — `test_helper.exs` runs `PhoenixKit.Migration.ensure_current/2` on every boot. **Do not** swap in `Ecto.Migrator.run(repo, [{0, PhoenixKit.Migration}], :up, all: true)` — it goes silently stale (see `ensure_current/2` moduledoc).

**Without PostgreSQL:** integration tests are auto-excluded; unit tests still run (banner printed, exit 0).

DB tests: `use PhoenixKit.DataCase, async: true` — auto-tags `:integration`.

### Local cross-repo development

Core has no `phoenix_kit` dep of its own — the flow matters from the **consumer** side. Every feature module wraps its `phoenix_kit*` deps in a `pk_dep/3` helper, so a module's suite can run against **uncommitted local core** without publishing. From inside the module's directory:

```bash
PHOENIX_KIT_PATH=../phoenix_kit mix test
```

Var name = dep app upper-cased + `_PATH`; unset = published Hex pin (`mix hex.publish` / CI unaffected). `phoenix_kit_parent` does the same permanently — use it to exercise the whole tree against local core. Details: workspace `AGENTS.md` → "Testing a module against local deps".

### Code Search

- `rg` — text/regex/strings/comments
- `ast-grep` — structural patterns; **prefer over text grep for code searches**: `ast-grep --lang elixir --pattern 'def $FUNC($$$ARGS) do $$$BODY end' lib/`

## Pull Requests

- **Branch:** PRs against **`main`** (`gh pr create --base main --head <fork-owner>:<branch>`). The `dev` branch was retired 2026-06-01; do not target it.
- **CI/CD:** `.github/workflows/ci.yml` is **manual-only** (`workflow_dispatch`) — nothing runs on push or PR. When dispatched: `postgres:16` + `mix format --check-formatted`, `mix credo --strict`, `mix dialyzer`, `mix deps.unlock --check-unused`, `mix test.setup` + `mix test`.
- ⚠️ **Nothing runs the Elixir suite automatically — not CI, not `precommit`.** For anything touching the schema, run `mix test` yourself: with no DB reachable, `test_helper.exs` excludes every `:integration` test but still **exits 0** — a green summary proves nothing about a migration.
- Point the suite at an existing DB (avoids needing `CREATEDB`; bound concurrency on shared servers):
  ```bash
  PGHOST=… PGUSER=… PGPASSWORD=… PGDATABASE=my_scratch_db PGPOOL=20 mix test --max-cases 8
  ```
- ⚠️ **Database-less runs set `config :phoenix_kit, :update_mode, true`** (`test_helper.exs`): every `PhoenixKit.Settings` read short-circuits to `nil`, so **every settings-dependent unit assertion runs against "nothing is configured"**. A test that needs a *value* must prime the cache itself (start `PhoenixKit.Cache.Registry` + `{PhoenixKit.Cache, name: :settings}`, then `PhoenixKit.Cache.put/3` — consulted before the short-circuit). Worked example: `test/phoenix_kit/utils/safe_destination_settings_test.exs`.
- **Commit messages:** start with `Add`, `Update`, `Fix`, `Remove`, `Merge`.
- **Versioning:** bump `mix.exs` `@version` + `CHANGELOG.md`; run `mix compile`, `mix test`, `mix format`, `mix credo --strict` before committing. Latest migration version:
  ```bash
  ls lib/phoenix_kit/migrations/postgres/v*.ex | sed 's/.*\/v\([0-9]*\)\.ex/\1/' | sort -rn | head -1
  ```
- **CHANGELOG entries:** write against the bumped `@version` heading; match existing style (Added / Changed / Fixed / i18n, bullets from PR scopes + post-merge review fixes).
- **PR reviews:** `dev_docs/pull_requests/{year}/{pr_number}-{slug}/{AGENT}_REVIEW.md` (`CLAUDE_REVIEW.md` for Claude). Severities: `BUG - CRITICAL/HIGH/MEDIUM`, `IMPROVEMENT - HIGH/MEDIUM`, `NITPICK`.
- **Publish:** `mix hex.build`, `mix hex.publish`, `mix docs`.

## Database

- Schemas use `@primary_key {:uuid, UUIDv7, autogenerate: true}`
- New migrations use `uuid_generate_v7()` (NOT `gen_random_uuid()`)
- Oban-style versioned migrations in `lib/phoenix_kit/migrations/postgres/`

### Prefix-safe migrations (named-schema installs)

The chain supports running into a named Postgres schema (`prefix:` opt / `--prefix`). Full reference + incident history: `dev_docs/guides/2026-07-27-prefix-safe-migrations.md`. Rules for any new `execute`-built SQL:

- **Index names stay bare on CREATE** — qualify only on `DROP INDEX`.
- **Every existence check needs a schema anchor** — `table_schema` on `information_schema.*`, `schemaname` on `pg_indexes`, name-based `pg_class` + `pg_namespace` JOIN for `pg_constraint` (never `'p.table'::regclass` in an IMMEDIATE check — it raises when the relation doesn't exist yet and aborts the whole transaction).
- **Schema-qualify functions** via `PhoenixKit.Migrations.Postgres.Helpers.ensure_uuid_v7_function/1` + `uuid_v7_call/1`; **never bare `CREATE EXTENSION`** (use `Helpers.ensure_extension!/1`) **or bare `CREATE SCHEMA`** (check `information_schema.schemata` first; thread `create_schema: false` to external migrators like Oban).
- Prefix validated at the entry points (`Helpers.validate_prefix!/1`); tooling resolves `--prefix` → `config :phoenix_kit, prefix:` → `"public"`.
- **New table-backed schemas must `use PhoenixKit.SchemaPrefix`** right after `use Ecto.Schema` — enforced by `test/phoenix_kit/schema_prefix_test.exs`. Prefix is compile-time config (`config.exs`, never `runtime.exs`).
- **Oban rides the same prefix** — the host's `config :app, Oban` must carry `prefix: "..."`.
- Oracle: `test/integration/prefix_migration_test.exs` runs the full chain into a scratch schema (bad SQL queued by one version often blows up at a later version's `flush()`).

## Integrations System

Centralized OAuth / API key / bot token / credential management. Full reference: `dev_docs/guides/2026-07-27-integrations-system.md`; design: `dev_docs/plans/integrations-system.md`.

- **Storage:** `phoenix_kit_settings` JSONB, keys `integration:{provider}:{name}`. Consumers reference connections by storage-row **uuid** — all public API except `add_connection/3` and the read shims is uuid-strict.
- **Owner scopes:** `:system` (website-wide UI `/admin/settings/integrations/website`) vs `{:user, uuid}` (personal UI `/admin/settings/integrations`). Every context call takes an `:owner` opt, **default `:system`** — pass `owner:` explicitly on the personal path or a forgotten owner silently births a SYSTEM row. Never encrypt `owner_uuid`.
- **Module callbacks:** `required_integrations/0`, `integration_providers/0`, optional `migrate_legacy/0` (run via `ModuleRegistry.run_all_legacy_migrations/0`).

## Core Form Components

`PhoenixKitWeb.Components.Core.{Input, Select, Textarea, Checkbox}` — canonical form primitives. Use over raw `<input>`/`<select>`/`<textarea>` in new code. They handle `phx-feedback-for`, gettext error display, label wiring, daisyUI styling. Reference: `lib/phoenix_kit_web/users/user_form.html.heex`.

- `class` attr → merges onto the **styled element** (input/label/textarea/checkbox). Pass daisyUI modifiers here: `input-sm`, `select-primary`, `checkbox-accent`, etc.
- `<.input>` also has `wrapper_class` → goes to the outer `<div phx-feedback-for>`.
- Prefer FormField binding: `<.input field={@form[:email]} type="email" label="Email" />`. Raw `name=`/`value=` still works for dynamic field names.

## Core List-UI Components

The canonical toolkit for admin list views — DnD reorder, bulk-select, sort, strategy reorder, load-more pagination. All live in `lib/phoenix_kit_web/components/core/`. Reference call sites: `phoenix_kit_projects`' `projects_live.ex` / `tasks_live.ex` / `templates_live.ex`.

- **Sortable** — `<.sortable_tbody enabled={…} event="reorder_x" id="…">` + `<.sortable_row item_id={uuid}>`; `enabled={false}` omits the hook so DnD turns off when sort_by ≠ position. Pair with `<.drag_handle_cell>` / `<.drag_handle_header_cell>` (render the `.pk-drag-handle` the SortableGrid hook reads).
- **TreeTable** — `<.tree_name_cell depth expandable expanded toggle_event value icon>` is the file-explorer name cell (indent, disclosure chevron, type icon) that composes into `table_default` rows. The consumer owns the walk and the expanded set.
- **BulkSelect** — `<.bulk_select_scope>` wraps the table; selection lives client-side, the hook pushes `%{"uuids" => […]}` on action-click. Children: `<.bulk_select_header_cell>`, `<.bulk_select_cell value={uuid}>`, `<.bulk_actions_toolbar>`. Consumer LVs collapse 0–1 captured uuids to `:all` (a single-row "reorder" is a no-op).
- **ReorderModal** — `<.reorder_modal>` strategy-picker dialog. The consumer LV owns the strategy whitelist (hardcoded string→atom map — never `String.to_existing_atom` on attacker input).
- **Modal `keep_in_dom`** — `<.modal keep_in_dom>` renders the `<dialog>` always; visibility flips via `data-show`. **Pass an explicit `id=`** — the auto-derived id collides when two kept-in-DOM modals share a close-event name.
- **SortSelector** — `<.sort_selector sort_by sort_dir options manual_field>`; select sends only `sort_by`, arrow only `sort_dir` (race-free). `manual_field={:position}` hides the direction toggle. Accepts `id` (default `"pk-sort-selector-#{event}"`).
- **Pagination** — `<.load_more>` for embeddable / DnD-aware lists (rows append, selection persists); `<.pagination>` for standalone pages with deep-linkable state.

## Multilang Form Components

`PhoenixKitWeb.Components.MultilangForm` — `<.multilang_tabs>`, `<.multilang_fields_wrapper>`, `<.translatable_field>`, plus helpers `mount_multilang/1`, `handle_switch_language/2`, `merge_translatable_params/4`. Forms `import` it and call `mount_multilang(socket)` in `mount/3`.

**Wrapper scope rule** (load-bearing): `<.multilang_fields_wrapper>` wraps translatable fields **only**. The wrapper's id includes `@current_lang`, so a switch causes morphdom to re-mount everything inside. Non-translatable fields (pricing, status, actions) render as siblings outside the wrapper or they lose state on every switch.

**Language switching:** client-side skeleton toggle + 150ms trailing debounce on the server. `mount_multilang/1` attaches a `:handle_info` hook via `Phoenix.LiveView.attach_hook/4` that intercepts the timer message — consumers don't need a `handle_info` clause. LiveComponent fallback: rescue `ArgumentError` from `attach_hook` and add the clause manually. The `switching_lang` attr is a backwards-compat no-op.

**Translatable fields:** `<.translatable_field>` takes `changeset={@changeset}` (not FormField) — its behavior changes with the active tab (primary-language vs JSONB-backed secondary). When mixed with `<.input>`/`<.select>`, the LV keeps both `:changeset` and `:form = to_form(changeset)` in sync via a private helper from mount/validate/save-error paths.

## Built-in Dashboard

Tabs, subtabs, badges, context selectors: see `lib/phoenix_kit/dashboard/README.md`.

## Login & Registration

Auth surface: session persistence, post-auth destinations, email confirmation. Full reference: `dev_docs/guides/2026-07-28-login-and-registration.md`. All settings live on `/admin/settings/users`.

- **Session persistence:** `remember_me_enabled` (default true) is the master switch — off hides the checkbox everywhere AND hard-blocks the cookie inside `maybe_write_remember_me_cookie/3`, so no caller or forged param can persist a session. `remember_me_default` (default true) = checkbox starts **checked**. Policy: `Auth.remember_me_enabled?/0` / `remember_me_default?/0`; flows with no UI to tick (magic-link, OAuth) use `Auth.remember_me_params/0`. **Never hardcode `%{"remember_me" => "true"}`**.
- **Post-auth destination:** one resolver, `Routes.post_auth_path/1`. Precedence: explicit `return_to` (param or gate-stashed session key) > `after_registration_path` > `after_login_path` > `/admin` (`log_in_user/3` honors `"return_to"` too). Tail is `/admin`, not `"/"` — core declares `/admin` unconditionally; `"/"` belongs to the host and may 404. Both settings validate as local paths on save, re-guarded on read.
- ⚠️ **`Routes.local_path?/1` is the only redirect guard** — rejects `//`, `/\`, and **ASCII control characters** (browsers strip tab/CR/LF, so `"/\t/evil.com"` lands as `//evil.com`; LiveView's `validate_local_url!` does not block these). Every LiveView `redirect(to: ...)` of user-influenced input MUST go through it. Path settings are also refused if they bounce an authenticated visitor — including **`/users/log-out`**, a real GET route that would sign every user straight back out.
- **Carrying `return_to`:** `Routes.return_to_query/1` threads it across login/register/magic-link/QR/OAuth links and the magic-link email URL. A new sign-in entry point must thread it too.
- ⚠️ **Public auth endpoints rate-limit BEFORE the lookup** — limiting inside the send throttles only addresses that resolve to a user, turning the deliberately generic copy into an account-existence oracle.
- **Email confirmation:** `require_email_confirmation` (default true) gates *enforcement* only; emails always send. Honored at **eleven** sites: the `ensure_authenticated`, `ensure_authenticated_scope`, `ensure_owner`, `ensure_admin`, `ensure_module_access` on_mount hooks; the `require_authenticated_user` / `require_authenticated_scope` plugs; and the role/permission plugs `require_owner` / `require_admin` / `require_module_access` / `require_role` (these four share the private `confirmation_gate/2`, since the shipped `:phoenix_kit_admin_only` pipeline runs them with NO preceding `require_authenticated_*`). Add it to any new gate.
- **The parked `/users/confirm` page** advances users instead of stranding them: on mount when already confirmed (covers a direct DB flip + refresh) and live off the `{:user_confirmed, _}` broadcast. It subscribes *before* re-reading the user.
- ⚠️ **Soft-failure paths need `rescue` AND `catch :exit`** — an unreachable DB raises on an unowned checkout but *exits* on a dead pool. Bites on a settings cache miss; presents as suite flakiness. Never evict a real settings key in a test; read a unique probe key instead.
- ⚠️ **Flash belongs inside the LiveView tree** (LayoutWrapper / dashboard / host layout). `root.html.heex` deliberately has none — a copy there double-rendered every message with duplicate ids.
- ⚠️ Rate limiting keys on `Plug.Conn.get_peer_data/1`, **not** `conn.remote_ip`, and the test adapter reports one peer for every conn — a login-heavy test file shares a single bucket. Give each test its own peer (`with_peer/2` in `auth_flows_test.exs`).
- ⚠️ A `disabled` `<.checkbox>` still submits its **un-disabled** hidden `value="false"` fallback, silently rewriting the setting on save. Don't use `disabled` to mean "inactive right now" in a settings form.

## Permissions

`PhoenixKit.Users.Permissions` — allowlist model (row present = granted, absent = denied); Owner always has full access, enforced in code. The moduledoc is the source of truth; highlights:

- **Module keys** gate admin sections/feature modules; custom keys via `register_custom_key/2`. The two integration keys are independent flat keys: `integrations_system` is auto-granted to Admin, `integrations` is opt-in (never auto-granted).
- **`"*"` superadmin key** (`Permissions.superadmin_key/0`) — a blanket Owner-equivalent grant honored by `Scope.superadmin?/1` / `has_module_access?/2` / `accessible_modules/1`. In `all_module_keys/0` but NOT `enabled_module_keys/0` (never a *required* key); cannot be registered as a custom key.
- **Admin-area gate**: `Scope.can_access_admin_area?/1` — true for Owner, Admin, OR any single permission holder (`admin?/1` is a deprecated alias). `Scope.holds_all_enabled_permissions?/1` is the "can do everything, like Owner" check.
- **Sub-permissions** — dotted keys under a base (`"calendar.view_others"`), declared in `permission_metadata/0`'s `sub_permissions`, checked by the module via `Scope.can?/2`. A sub implies its base (granting a sub auto-grants the base; revoking the base cascades). Grant/revoke run under a per-`{role, base-key}` advisory lock.
- **Edit protection**: `can_edit_role_permissions?/2` — users cannot edit their own role; only Owner can edit Admin.

## Activity Feed

Tracks business-level actions. Admin UI: `/admin/activity` (and `/admin/activity/:uuid`). Core: `lib/phoenix_kit/activity/`.

```elixir
PhoenixKit.Activity.log(%{
  action: "post.created",       # required — "resource.verb"
  module: "posts",              # filterable
  mode: "manual",               # "manual" | "auto" | "cron" | "script"
  actor_uuid: user.uuid,
  resource_type: "post",
  resource_uuid: post.uuid,
  target_uuid: nil,             # who was affected (drives notifications)
  metadata: %{"actor_role" => "user", "title" => post.title}
})
```

- **Profile/field changes** — `log_user_change("user.profile_updated", user, changeset, actor_uuid: …, target_uuid: …, mode: "manual", actor_role: "admin")` auto-extracts `field_from`/`field_to` from a changeset; skips logging if nothing changed.
- **Conventions:** `action` = `resource.verb`; `module` = key string; `actor_role` baked at log time; `resource_type` usually equals `module`. Examples: `rg 'Activity.log' lib/phoenix_kit/users/`.
- **External modules** — guard with `Code.ensure_loaded?(PhoenixKit.Activity)` before calling.
- **Cleanup:** `activity_retention_days` setting (default 90). `PhoenixKit.Activity.PruneWorker` runs daily via Oban.

## Notifications

Per-user inbox driven by the activity log. Full reference: `dev_docs/guides/2026-07-27-notifications.md`.

- **Generation:** `Activity.log/1` with `target_uuid != actor_uuid` fans out a `phoenix_kit_notifications` row via `Notifications.maybe_create_from_activity/1` — **never insert directly**. Kill switch: `notifications_enabled` (default `"true"`).
- **API:** `PhoenixKit.Notifications` — `list_for_user/2`, `recent_for_user/2`, `count_unread/1`, `mark_seen` / `mark_all_seen` / `dismiss` / `dismiss_all`, `get_notification/2` (recipient-scoped). Render via `Notifications.Render.render/1`, which honors `notification_text` / `notification_icon` / `notification_link` metadata keys.
- **UI:** embeddable `PhoenixKitWeb.Live.NotificationsBell` (sticky nested LV, owns its PubSub sub); "seen" only on explicit user action. PubSub topic: `Notifications.Events.topic_for_user(uuid)`.
- **Per-user preferences:** mute by *type*; types merge core + modules' `notification_types/0` callback. `Notifications.Prefs.user_wants?/2` is **fail-open**.
- **External delivery channels** (Telegram, Email; modules add via `notification_channels/0`): parallel routing layer — `Channel` behaviour, `Channels` registry, `ChannelConfig` under `custom_fields["notification_channel:<key>"]`, fail-closed `Routing`, Oban `DeliveryWorker` (`:notifications` queue) + `DigestWorker` cron. Inbox insert is decoupled from channel enqueue. ⚠️ `DigestWorker` runs ONLY from cron, so `mix phoenix_kit.update` must **backfill those entries into existing hosts** (`ObanConfig.ensure_digest_cron_entries/2`) — a digest cadence suppresses the per-event inbox row, so a missing entry drops the notification entirely. Registry lookups need `Code.ensure_loaded?` alongside `function_exported?/3` (false for an unloaded module under a release); the settings LV `Map.take`s params against known keys.
- **Cleanup:** `Notifications.PruneWorker` daily; retention `notifications_retention_days` → `activity_retention_days` (default 90).

## MediaBrowser Component

Embeddable media UI (folder tree, grid/list, upload, search, selection, trash): `lib/phoenix_kit_web/components/media_browser.ex`. Full attrs/behavior: `dev_docs/guides/2026-07-27-media-browser.md`.

**One-line embed** — the macro injects upload setup, the `"validate"` stub, and the `handle_info` delegator:

```elixir
use PhoenixKitWeb.Components.MediaBrowser.Embed
```

```heex
<.live_component module={PhoenixKitWeb.Components.MediaBrowser}
  id="media-browser" parent_uploads={@uploads} />
```

`parent_uploads={@uploads}` is required (LiveView `allow_upload` constraint). Key attrs: `scope_folder_id`, `on_navigate={:navigate}` (controlled mode), `initial_params`, `admin`, `select_mode`.

**URL sync (shareable folder deep links):** `use …Embed, url_sync: true` puts folder/search/page/view in the URL via lifecycle hooks (`attach_hook`, **not** injected clauses) — composes with a host LV that has its own `handle_params`/`handle_info`. The patch appends the query to the **current** path, so locale/resource segments are preserved. Reference: `lib/phoenix_kit_web/live/users/media.ex`.

## Guidelines

### External Module Auto-Discovery

Standalone module packages **must** include `:phoenix_kit` in `extra_applications`:

```elixir
def application, do: [extra_applications: [:logger, :phoenix_kit]]
```

Without this, `PhoenixKit.ModuleDiscovery` won't find it and routes 404. Template: `phoenix_kit_hello_world`.

### Tailwind CSS for External Modules

Modules with UI implement `css_sources/0`:

```elixir
@impl PhoenixKit.Module
def css_sources, do: [:phoenix_kit_my_module]
```

Discovery is automatic at compile time via the `:phoenix_kit_css_sources` compiler — generates `assets/css/_phoenix_kit_sources.css`. Parent setup (one-time, by `mix phoenix_kit.install`): add the compiler to `compilers:` in `mix.exs` (before `:phoenix_live_view`) and `@import "./_phoenix_kit_sources.css";` in `app.css`. After setup, adding/removing modules is zero-config.

### JavaScript Hooks for External Modules

PhoenixKit ships hooks (RowMenu, TableCardView, SortableGrid, etc.) in `priv/static/assets/phoenix_kit.js`, exposed as `window.PhoenixKitHooks`. Parent spreads into LiveSocket:

```javascript
hooks: { ...window.PhoenixKitHooks, ...colocatedHooks }
```

**Parent setup (by `mix phoenix_kit.install`):** copy `phoenix_kit.js` to `priv/static/assets/vendor/`, add `<script src={~p"/assets/vendor/phoenix_kit.js"}></script>` **before** `app.js` in root layout. `mix phoenix_kit.update` refreshes it. External modules add hooks via inline `<script>` on `window.PhoenixKitHooks` (see hello_world).

### Layout Wrapper

PhoenixKit LiveView templates use `<PhoenixKitWeb.Components.LayoutWrapper.app_layout>` (NOT `Layouts.app`):

```heex
<PhoenixKitWeb.Components.LayoutWrapper.app_layout
  flash={@flash} page_title={@page_title} current_path={@url_path}
  project_title={@project_title} phoenix_kit_current_scope={@phoenix_kit_current_scope}
  current_locale={assigns[:current_locale]}>
  <!-- content -->
</PhoenixKitWeb.Components.LayoutWrapper.app_layout>
```

Only `flash` is required. Note: the assign is `@url_path`, the attr is `current_path`. Full attr list: `lib/phoenix_kit_web/components/layout_wrapper.ex`.

### URL Prefix and Navigation

**NEVER hardcode PhoenixKit paths.** Use prefix helpers:

| Scenario | Use |
|---|---|
| Template links | `<.pk_link navigate="/path">` or `patch` |
| LV navigate/patch | `Routes.path("/path")` |
| Controller redirect | `Routes.path("/path")` |
| Email URLs | `Routes.url("/path")` |

```elixir
alias PhoenixKit.Utils.Routes
push_navigate(socket, to: Routes.path("/dashboard"))
url = Routes.url("/users/confirm/#{token}")
```

```heex
<.pk_link navigate="/dashboard">Dashboard</.pk_link>
<.pk_link_button navigate="/admin/users" variant="primary">Manage Users</.pk_link_button>
```

### LiveView form ids

Every `<form phx-change=…>` needs a unique `id` — without it LiveView form recovery is silently disabled and host test suites warn `missing_form_id`. LiveComponent → derive from `@id`; inside a comprehension → include the row uuid; `<.form for={%{}}>` needs an explicit `id` (only `for={@changeset}` supplies one for free). Detect with a multi-line-aware scanner, not line-oriented grep. Full audit: `dev_docs/investigations/2026-07-27-missing-form-id-audit.md`.

## Parent Project

### Install Commands

- `mix phoenix_kit.install` — install (use `--help`)
- `mix phoenix_kit.update` — update
- `mix phoenix_kit.status` — installation status
- `mix phoenix_kit.gen.migration` — custom migration

Features: versioned migrations, table prefix, idempotent ops, PostgreSQL validation, mailer templates.

### External Module Route Discovery

Routes auto-discovered at compile time via `ModuleDiscovery` beam scanning. The host router auto-recompiles when module deps change — `phoenix_kit_routes()` injects `__mix_recompile__?/0` with a hash of the discovered set.

**Two patterns:**
1. **Single page** — set `live_view: {Module.Web.IndexLive, :index}` on a tab in `admin_tabs/0` or `settings_tabs/0`. Route auto-generated. Used by: hello_world, sync, catalogue, document_creator, emails (settings), user_connections, legal.
2. **Multi-page** — implement `route_module/0` returning a module with `admin_routes/0` and `admin_locale_routes/0`. Required for sub-routes (`/new`, `/edit`, `/:id`). Do NOT also set `live_view:` on the main tab. Used by: ai, entities, publishing, newsletters.

Only one `live_view:` per path (core deduplicates, first wins — avoid). Fallback for failed auto-discovery:

```elixir
config :phoenix_kit, route_modules: [PhoenixKitEntities.Routes]
```

### Publishing Routing Strategy

Publishing's `/:language/:group/*path` catch-all matches every 2+ segment URL and Phoenix has no fall-through — host routes declared after `phoenix_kit_routes()` shaped `/:locale/<literal>/...` were silently shadowed. Fix: `compile_publishing_routing/1` in `integration.ex` emits an internal `__phoenix_kit_publishing_dispatch` scope plus a host-router `call/2` override that prepends the internal prefix on a `RouterDispatch.maybe_rewrite/1` cache hit (`restore_path/2` un-rewrites after route bind). Known blind spot: `mix phx.routes` shows publishing routes under the internal prefix, not the user-facing URL. The mechanism generalizes — lift to a registry shape when a second module needs it.

## daisyUI version (host-owned; advisory warnings only)

The daisyUI plugin lives in the **host** app (`assets/vendor/daisyui.js` + `daisyui-theme.js`). Core only declares a designed-for minimum (`PhoenixKit.Install.DaisyUI.minimum_version/0`, currently 5.6.0) and warns below it from `phoenix_kit.install` / `phoenix_kit.update` / `phoenix_kit.doctor` — advisory, never touching host files. **Do NOT re-add `scrollbar-gutter` overrides** in layouts, PkDialog, or modules (removed 2026-07-12; daisyUI ≥ 5.1 handles the gutter). Rationale for not vendoring daisyUI in core: `dev_docs/investigations/2026-07-12-daisyui-version-management-investigation.md`.

## TODOs

Workspace-tracked items not ready for inline `# TODO` in `lib/`.

### Component test coverage for `phoenix_kit_web/components/core/`

Partial coverage exists in `test/phoenix_kit_web/components/core/`. Remaining gaps:

- `<.draggable_list>` — three branches need rendered-HTML asserts: (a) `:draggable=false` → no SortableJS hook, no `cursor-grab`; (b) `draggable, sortable_handle=nil` → hook + full-item `cursor-grab`; (c) `draggable, sortable_handle=".pk-drag-handle"` → hook + `data-sortable-handle` set, **no** `cursor-grab` on the item wrapper (caller's responsibility).
- `<.table_default>` card-view branch — pin `phx-hook="SortableGrid"`, `data-sortable-*`, `data-id`, `class="sortable-item"`, drag-handle footer.
- `<.input>`, `<.select>`, `<.textarea>` — inline error rendering, daisyUI variant classes, FormField vs raw `name=`/`value=` dispatch.
- `<.flash>` if complexity has grown.

### Signed file-URL hardening (`modules/storage`)

In `lib/modules/storage/services/url_signer.ex` + `file_controller.ex`:

- **`POST /api/upload` is unauthenticated and takes the owner from `params["user_uuid"]`** — a live unauthenticated *write*, top of the list. The storage routes sit in the `[:browser, :phoenix_kit_auto_setup]` scope with no auth plug; `UploadController.create/2` falls back to the param verbatim. An anonymous client (CSRF token from the public login page) can attribute a 100 MB upload to any account and trigger variant processing. Fix: drop the params fallback, honor a `user_uuid` override only for an authenticated admin, rate-limit the action.
- **Token is 16-bit** — first 4 hex chars of an MD5, ~65k space, brute-forceable. Widen it (consider HMAC over MD5).
- **Tokens never expire**, yet the 401 says *"Invalid or expired token."* Add real expiry or fix the message.
- **`/api/files/:uuid/info` is unauthenticated** and returns a valid signed URL for any uuid — defeats the signing scheme. Lock it down.
- **Fails open on a nil `secret_key_base`** — the token degrades to a predictable no-secret hash. Fail closed.

Read half is low urgency (current use is public post images); the upload half is a live unauthenticated write. Don't rely on the "capability URL" framing for sensitive files.
