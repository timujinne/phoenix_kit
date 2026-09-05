defmodule PhoenixKit.Migrations.Postgres.V183 do
  @moduledoc """
  V183: annotations can anchor to something other than a file.

  ## Why

  Every annotation row pointed at a `phoenix_kit_files` row through a
  `NOT NULL` `file_uuid`. That was right for the media viewer, where a
  shape is always drawn over an image, and wrong for a whiteboard, where
  there is no image at all — Fresco's canvas renders a scene with zero
  images and Etcher draws over empty canvas without needing one. The
  projects module bridged the gap by minting a solid-white PNG per board,
  registering it as a Storage file and drawing over that. Etcher's own
  API has always been keyed by `target_type` + `target_uuid`; this
  migration lets the table say the same.

  ## What it does

    * `file_uuid` becomes nullable.
    * `target_type` (`varchar(32)`, `NOT NULL`, default `'file'`) and
      `target_uuid` (`uuid`) are added; every existing row is backfilled
      with `target_type = 'file'`, `target_uuid = file_uuid`.
    * An index on `(target_type, target_uuid)` for the board lookups.
    * A CHECK constraint pins the two shapes: a `'file'` target carries its
      file in BOTH columns (`file_uuid = target_uuid`), and any other target
      carries no file at all. Nothing in between.

  Reads of existing rows are unchanged — `file_uuid` is still there and
  still the file. Rolling back deletes the non-file annotations (they have
  no home in the old shape), drops the two columns and the constraint, and
  makes `file_uuid` `NOT NULL` again.
  """

  use Ecto.Migration

  # Constraint existence is checked with a name-based `pg_class` +
  # `pg_namespace` JOIN, never `'schema.table'::regclass`. The cast raises
  # rather than answering false when the relation is absent, which aborts the
  # whole transaction — see `dev_docs/guides/2026-07-27-prefix-safe-migrations.md`
  # and the same check in V180. It cannot bite here (V135 creates the table at
  # the migration floor), but this file is the template the next migration is
  # copied from.
  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("ALTER TABLE #{p}phoenix_kit_annotations ALTER COLUMN file_uuid DROP NOT NULL")

    execute("""
    ALTER TABLE #{p}phoenix_kit_annotations
      ADD COLUMN IF NOT EXISTS target_type character varying(32) NOT NULL DEFAULT 'file',
      ADD COLUMN IF NOT EXISTS target_uuid uuid
    """)

    execute("""
    UPDATE #{p}phoenix_kit_annotations
       SET target_type = 'file', target_uuid = file_uuid
     WHERE target_uuid IS NULL AND file_uuid IS NOT NULL
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_annotations_target_index
      ON #{p}phoenix_kit_annotations USING btree (target_type, target_uuid)
    """)

    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE c.conname = 'phoenix_kit_annotations_target_check'
           AND t.relname = 'phoenix_kit_annotations'
           AND n.nspname = '#{prefix}'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_annotations
          ADD CONSTRAINT phoenix_kit_annotations_target_check CHECK (
            (target_type = 'file' AND file_uuid IS NOT NULL AND target_uuid = file_uuid)
            OR (target_type <> 'file' AND file_uuid IS NULL AND target_uuid IS NOT NULL)
          );
      END IF;
    END $$;
    """)

    # Single-step runs rely on the migration stamping its own marker — the
    # runner only writes it for multi-step ranges.
    execute("COMMENT ON TABLE #{p}phoenix_kit IS '183'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Non-file annotations (a whiteboard's shapes, say) have no home in
    # the old shape: a rollback DROPS them. Back the table up first if
    # the rollback is not final.
    execute("DELETE FROM #{p}phoenix_kit_annotations WHERE target_type <> 'file'")

    execute("""
    ALTER TABLE #{p}phoenix_kit_annotations
      DROP CONSTRAINT IF EXISTS phoenix_kit_annotations_target_check
    """)

    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_annotations_target_index")

    execute("""
    ALTER TABLE #{p}phoenix_kit_annotations
      DROP COLUMN IF EXISTS target_uuid,
      DROP COLUMN IF EXISTS target_type
    """)

    execute("ALTER TABLE #{p}phoenix_kit_annotations ALTER COLUMN file_uuid SET NOT NULL")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '182'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
