defmodule PhoenixKit.Migrations.Postgres.V166 do
  @moduledoc """
  V166: frozen comment attribution — who a comment is FROM, at the time.

  Two problems, one row.

  ## The name has to be frozen

  A comment header used to render `user.email`, which on a public issue
  board published a full address next to every remark. Replacing it with a
  live name chain fixes the address but not the deeper issue: a name
  resolved at RENDER time rewrites history. Someone leaves, is renamed, or
  finally fills in their profile, and every comment they ever wrote is
  silently re-signed. `author_display_name` records what the world was
  shown when the comment was made.

  Null for every existing row, on purpose: a backfill would invent a
  history we do not have, so old rows keep resolving live and only new ones
  are pinned.

  ## Speaking for the project

  Someone answering on their employer's public board may be speaking as
  themselves or on behalf of the project, and those are different acts. The
  choice is stored, not recomputed: recomputing means a membership change
  retroactively alters who said what — and worse, un-masks somebody who
  deliberately posted under the project's name.

  **`user_uuid` is never cleared.** Posting as the project changes what the
  PUBLIC sees, and nothing else: internally the actual author stays on the
  row, so moderation, audit and "who actually said this" keep working. A
  shared voice with no accountable person behind it is how this feature
  goes wrong.

  `attributed_label` is frozen alongside `attributed_project_uuid` for the
  same reason prices are snapshotted on orders: the project may be renamed
  or deleted, and the comment should still say what it said.

  No FK on `attributed_project_uuid` — projects live in an optional
  package, exactly like the mention targets in V165.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("""
    ALTER TABLE #{p}phoenix_kit_comments
      -- What the reader was shown. NULL on historical rows, which keep
      -- resolving live; only rows written from here on are pinned.
      ADD COLUMN IF NOT EXISTS author_display_name TEXT,
      -- 'personal' | 'project'. NULL reads as 'personal' so nothing needs
      -- a backfill and no existing comment changes meaning.
      ADD COLUMN IF NOT EXISTS attribution_mode TEXT,
      -- The project spoken for, and the name it had at the time.
      ADD COLUMN IF NOT EXISTS attributed_project_uuid UUID,
      ADD COLUMN IF NOT EXISTS attributed_label TEXT
    """)

    # Only two values are meaningful, and a typo'd third would render as an
    # unhandled state on a public page. Cheaper to refuse it here.
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE c.conname = 'phoenix_kit_comments_attribution_mode_check'
          AND t.relname = 'phoenix_kit_comments'
          AND n.nspname = '#{schema_name(prefix)}'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_comments
          ADD CONSTRAINT phoenix_kit_comments_attribution_mode_check
          CHECK (attribution_mode IS NULL OR attribution_mode IN ('personal', 'project'));
      END IF;
    END $$;
    """)

    # Every comment a project has spoken through, for the moderation view
    # that has to answer "what have we said publicly, and who wrote it".
    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_comments_attributed_project_idx
      ON #{p}phoenix_kit_comments (attributed_project_uuid)
      WHERE attributed_project_uuid IS NOT NULL
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '166'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_comments_attributed_project_idx")

    execute("""
    ALTER TABLE #{p}phoenix_kit_comments
      DROP CONSTRAINT IF EXISTS phoenix_kit_comments_attribution_mode_check
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_comments
      DROP COLUMN IF EXISTS attributed_label,
      DROP COLUMN IF EXISTS attributed_project_uuid,
      DROP COLUMN IF EXISTS attribution_mode,
      DROP COLUMN IF EXISTS author_display_name
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '165'")
  end

  defp schema_name("public"), do: "public"
  defp schema_name(prefix), do: prefix

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
