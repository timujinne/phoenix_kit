defmodule PhoenixKit.Migrations.Postgres.V185 do
  @moduledoc """
  V185: activities can be permanent, and are ordered to the microsecond;
  posts remember the zone they were scheduled in.

  ## Why

  A stored instant does not say which regime wrote it. When the `time_zone`
  setting moved from an integer offset to an IANA id (2.13.9) and five
  modules turned out to have added that value to other instants, the rows
  they had written could not be repaired, because nothing recorded WHEN the
  setting changed or what it was before: `phoenix_kit_settings.date_updated`
  holds the last change only, and no settings writer logged to the activity
  feed — which prunes after `activity_retention_days` anyway. The question
  "what was this setting at that instant?" had no answer.

  The activity feed is the right home for that answer — it already holds
  who did what to which resource, with a before/after convention in its
  metadata and an admin page — once two things hold:

    * **`permanent`** (`boolean NOT NULL DEFAULT false`): an entry the
      pruner never deletes. Any module may keep an entry this way; settings
      changes are the first.
    * **`inserted_at` to the microsecond** (`timestamp(0)` → `timestamp`):
      "what was the value at that instant" walks a resource's entries by
      time, and two changes inside one second must not read as
      simultaneous. Widening the precision rewrites no rows.

  ## And the posts column (moved to `phoenix_kit_posts` in core 3.0)

  `phoenix_kit_posts.time_zone` (`varchar(64)`, nullable) was added here, the
  same lesson applied to the table that stores a typed wall clock. That table
  belongs to the posts module, so core 3.0 no longer adds the column: the
  posts chain does.

  Rolling back drops the flag (permanent entries become prunable). It leaves `inserted_at` wide: narrowing it back would
  rewrite and round every row under an exclusive lock, and the previous
  code reads a microsecond value fine (Ecto truncates on load).
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("""
    ALTER TABLE #{p}phoenix_kit_activities
      ADD COLUMN IF NOT EXISTS permanent boolean NOT NULL DEFAULT false
    """)

    # Precision 0 → 6. PostgreSQL treats a precision INCREASE on timestamp
    # as binary-compatible: no table rewrite, no scan.
    execute("""
    ALTER TABLE #{p}phoenix_kit_activities
      ALTER COLUMN inserted_at TYPE timestamp without time zone
    """)

    # Single-step runs rely on the migration stamping its own marker — the
    # runner only writes it for multi-step ranges.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '185'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # `inserted_at` stays at microsecond precision on purpose — see the
    # moduledoc.
    execute("ALTER TABLE #{p}phoenix_kit_activities DROP COLUMN IF EXISTS permanent")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '184'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
