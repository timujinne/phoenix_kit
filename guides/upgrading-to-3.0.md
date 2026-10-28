# Upgrading to PhoenixKit 3.0

**New installs need nothing from this guide.** `mix igniter.install phoenix_kit` gives you core's tables, and every
module you install creates its own.

3.0 is a major release because of two removals. Read both before you upgrade a production database.

1. **Core no longer creates the tables of the optional modules.** Until 2.65 core's migration chain created 140 tables
   that belong to 25 modules (ai, billing, catalogue, emails, ...). From 3.0 each module's own migration chain creates
   its tables, and `mix phoenix_kit.update` runs the installed modules' chains after core's, in dependency order (staff
   before projects, billing before ecommerce). Existing tables are left exactly as they are.
2. **Email templates no longer come from the database.** A message is built from your override files
   (`priv/phoenix_kit_templates/...`, see [Email templates](email-templates.md)) or the shipped default. The
   `phoenix_kit_email_templates` table is no longer read, and the admin pages that edited it are gone.

The machine API also lost its deprecated shop names (see "Removed" below).

## Order of operations

1. **Get to 2.65.0 first.** 3.0 only upgrades a database that is at **V225**, the last 2.x version. A lower database is
   refused with `BelowFloorError`, which names 2.65.0 (a database below V135 goes to `1.7.236` first, then 2.65.0; see
   [Upgrading to 2.0](https://github.com/BeamLabEU/phoenix_kit/blob/main/dev_docs/guides/2026-08-07-upgrading-to-2.0-guide.md)).

   ```elixir
   {:phoenix_kit, "== 2.65.0"}   # the bridge
   ```

   ```bash
   mix deps.get
   mix phoenix_kit.update   # repeat until it reports V225; run the generated migration(s)
   ```

   For a prefixed install, pass the same `--prefix` you installed with, and check each prefix.

2. **Export email templates you edited in the admin UI** (skip if you never changed one):

   ```bash
   mix phoenix_kit_emails.templates.export
   ```

   This writes your active templates as files under your app. Do it **before** you move to 3.0: the 3.0 emails module has
   no way to read the table through the application, and an edit that lives only in the table stops being sent.
   Commit the files. The table itself is not touched or dropped.

3. **Move everything together.** Core 3.0 and every installed module must be on a release that accepts core 3.x (their
   core requirement reads `>= <floor> and < 4.0.0`). Update all `phoenix_kit*` dependencies in one commit; a module
   still on an older release keeps resolving core 2.x and `mix deps.get` will say so. `phoenix_kit_emails` needs core
   3.0 or later.

   ```bash
   mix deps.update phoenix_kit phoenix_kit_ai phoenix_kit_billing ...   # every phoenix_kit* you use
   mix phoenix_kit.update   # core's migrations (none change a table), then each module's chain
   ```

   The module chains adopt the tables that already exist and add what is missing, so on an upgraded database they change
   nothing that holds data.

4. Run `mix phoenix_kit.doctor`. It checks core's tables; a module's tables are checked from its own manifest when the
   module is installed.

## Removed in 3.0

- **Machine API:** the deprecated paths `/api/shop/v1` and `/mcp/shop` (use `/api/public/v1` and `/mcp/public`), the old
  settings keys `api_public_cart_rate_per_min`, `api_public_cart_rows_per_ip_hour` and
  `api_public_cart_rows_global_hour` (the rows stay in `phoenix_kit_settings`; the first save of Settings -> API writes the
  new `api_public_token_rate_per_min`, `api_public_new_rows_per_ip_hour` and `api_public_new_rows_global_hour`), a public
  tool that names its caller token `cart_token` must now declare `client_token:`, the four shop error codes now come only
  from the module that declares them (`api_problems/0`), and `PhoenixKit.API.RateLimit.check_cart_rows/1` is
  `check_new_rows/1`.
- **Email provider callbacks** `get_active_template_by_name/1`, `render_template/2,3`, `track_usage/1` and
  `get_source_module/1`, and `PhoenixKit.Mailer.track_usage_after_delivery/2`. A custom provider drops them.

## If something goes wrong

- *`BelowFloorError` naming 2.65.0* - the database is below V225. Do step 1.
- *A module's table is missing after the upgrade* - run `mix phoenix_kit.update` again with the module installed; its
  chain creates what is missing. Nothing in core 3.0 drops a table.
- *`mix deps.get` cannot resolve* - a module is still on a release that pins core `~> 2.x`; update it to the 3.x-ready release.
