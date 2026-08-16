defmodule PhoenixKit.Migrations.Postgres.V172 do
  @moduledoc """
  V172: the built-in SEO module becomes Crawlers.

  Everything the module holds is bot policy — the noindex directive, crawler
  guidance, and (from this release) per-bot-group access controls — while
  actual SEO work lives in the external `phoenix_kit_seo` package. The rename
  frees the name for the thing that owns it and stops the settings page
  overselling itself. Data moves in two places:

  ## Settings rows

  `seo_module_enabled` → `crawlers_module_enabled` and `seo_no_index` →
  `crawlers_no_index`, with the `module` tag on any `'seo'`-tagged row
  updated to `'crawlers'`. Guarded so a half-migrated database (both keys
  present) deduplicates rather than violating the unique key: the old row is
  renamed only when the new key is absent, and any leftover old row is then
  deleted. The old row's value wins over a stray new one — it is the one the
  running site was actually honoring.

  ## Permission rows

  Roles granted `'seo'` gain `'crawlers'`. The old `'seo'` rows are **kept,
  deliberately**: the ExpectedSchema manifest (repair) still lists the V135
  `'seo'` seed as required, so deleting the rows here would make
  `mix phoenix_kit.repair` re-create them on its next run — a migration and a
  repair tool fighting over the same row. The stale grants are inert (no
  module registers the `'seo'` key, so no page reads them, and the
  permissions matrix only renders registered keys) and their removal belongs
  to the next manifest regeneration, where the seed entry itself moves.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    rename_setting(p, "seo_module_enabled", "crawlers_module_enabled", "crawlers")
    rename_setting(p, "seo_no_index", "crawlers_no_index", "crawlers")

    # Any remaining rows tagged with the old module name (operator-created or
    # future settings written before an upgrade) follow the module.
    execute("""
    UPDATE #{p}phoenix_kit_settings
    SET "module" = 'crawlers'
    WHERE "module" = 'seo'
    """)

    # Copy the permission grant. ON CONFLICT covers re-runs and the fresh
    # install path (V135 seeds 'seo', this version adds 'crawlers' beside it).
    execute("""
    INSERT INTO #{p}phoenix_kit_role_permissions ("role_uuid", "module_key")
    SELECT rp.role_uuid, 'crawlers'
    FROM #{p}phoenix_kit_role_permissions rp
    WHERE rp.module_key = 'seo'
    ON CONFLICT DO NOTHING
    """)

    # Single-step runs rely on the migration stamping its own marker — the
    # runner only writes it for multi-step ranges.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '172'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    rename_setting(p, "crawlers_module_enabled", "seo_module_enabled", "seo")
    rename_setting(p, "crawlers_no_index", "seo_no_index", "seo")

    # Only operator rows that up/1's broad retag moved go back to 'seo'.
    # The new-feature rows (crawlers_allow_*, verification, llms extra) never
    # existed under the old name — retagging them would invent history, and
    # V166-era code reads none of them either way.
    execute("""
    UPDATE #{p}phoenix_kit_settings
    SET "module" = 'seo'
    WHERE "module" = 'crawlers'
      AND "key" NOT LIKE 'crawlers%'
    """)

    # The 'seo' grants were never deleted on the way up, so going down removes
    # only the copies this version created — the ones whose role still holds
    # 'seo'. A 'crawlers' grant an operator added afterwards to a role that
    # never had 'seo' is theirs, not ours, and survives the rollback.
    execute("""
    DELETE FROM #{p}phoenix_kit_role_permissions rp
    WHERE rp.module_key = 'crawlers'
      AND EXISTS (
        SELECT 1 FROM #{p}phoenix_kit_role_permissions seo
        WHERE seo.role_uuid = rp.role_uuid AND seo.module_key = 'seo'
      )
    """)

    # Rollback lands on the version that precedes this one.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '171'")
  end

  # Rename a settings row by key, tolerating every partial state: if only the
  # old key exists it is renamed in place (value preserved); if both exist the
  # old row is dropped in favor of… itself — the old value is what the site
  # was honoring, so the new row is overwritten from it first.
  defp rename_setting(p, old_key, new_key, module_tag) do
    execute("""
    UPDATE #{p}phoenix_kit_settings new
    SET "value" = old."value",
        "value_json" = old."value_json"
    FROM #{p}phoenix_kit_settings old
    WHERE new."key" = '#{new_key}' AND old."key" = '#{old_key}'
    """)

    execute("""
    UPDATE #{p}phoenix_kit_settings
    SET "key" = '#{new_key}', "module" = '#{module_tag}'
    WHERE "key" = '#{old_key}'
      AND NOT EXISTS (
        SELECT 1 FROM #{p}phoenix_kit_settings s2 WHERE s2."key" = '#{new_key}'
      )
    """)

    execute("""
    DELETE FROM #{p}phoenix_kit_settings
    WHERE "key" = '#{old_key}'
    """)
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
