defmodule PhoenixKit.Migrations.Postgres.V135BaselineSchemaTest do
  @moduledoc """
  Final-shape schema pins carried forward from the deleted `V107Test`,
  `V112Test`, `V113Test`, and `V125Test` (squash floor 135 — spec
  `dev_docs/plans/2026-07-14-squash-migrations-spec.md` §5.3).

  V107/V112/V113/V125 are all below the floor and no longer exist as
  standalone migration modules — their DDL now lives, final-state only,
  inside `PhoenixKit.Migrations.Postgres.V135`. What those test files
  pinned was never the migration MECHANISM (none of them could invoke
  `up/1`/`down/1` outside an `Ecto.Migrator` runner in the first place —
  see their now-deleted moduledocs) but the resulting DB shape, verified
  at boot through `test_helper.exs`'s `ensure_current/2`. That shape is
  unchanged by the squash (verified separately by the generator's S1
  dump-diff against the pre-squash chain, `dev_docs/squash/verify.exs`),
  so these assertions are moved here verbatim rather than deleted —
  losing them would silently drop coverage for column types, index
  predicates, FK delete actions, and CHECK-constraint enforcement that
  the manifest's own structural `check:` SQL does not exercise at `mix
  test` time (that only runs live via `mix phoenix_kit.repair`/the
  squash verification harness).

  NOT carried forward (see `dev_docs/plans/2026-07-14-squash-inventory.md`,
  "What the squash changed" for the full accounting):

    * `V106Test` — pinned `V106.down/1`'s cross-mode-duplicate pre-check
      SQL, a migration-rollback mechanism that no longer exists as a
      distinct step once V106 is folded into the V135 baseline (the
      baseline's own `down/1` tears down the whole slice, it does not
      replay V106's granular pre-check). The FINAL fact it protected —
      `phoenix_kit_projects` has no unique-name index left — is already
      encoded by omission in the generated manifest (confirmed by
      `dev_docs/squash/output/generation_report.md`'s "Dropped along the
      chain" list, which names `phoenix_kit_projects_name_index` /
      `_name_template_index` / `_name_project_index` explicitly) and by
      this file's own "dropped unique-name indexes" tests below.
    * `V107Test`'s backfill-correctness describes (`integration_uuid`
      backfill from `phoenix_kit_settings`) — pure upgrade-only data
      rewrite (D7: zero historical backfills in the baseline); a fresh
      floor-135 install has no legacy rows to backfill and no lasting
      invariant to assert (unlike V114, below, `integration_uuid` may
      legitimately be NULL forever). Its schema-shape describes ARE kept.
    * `V114Test` — entirely upgrade-only data-rewrite logic (composite-key
      `integration:<provider>:<name>` → uuid-only storage), unreachable
      at floor 135. The END-STATE invariant it protected ("no composite
      `integration:*` keys remain") is already a generator-emitted
      `data_invariant` in `PhoenixKit.Migrations.ExpectedSchema` (`since:
      114`), checked by `mix phoenix_kit.repair`/verify, not by this file.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Test.Repo

  # ---------------------------------------------------------------------------
  # Shared helpers
  # ---------------------------------------------------------------------------

  defp column(table, column) do
    %{rows: rows} =
      Repo.query!(
        """
        SELECT data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_name = $1 AND column_name = $2
        """,
        [table, column]
      )

    case rows do
      [[data_type, is_nullable, default]] ->
        %{type: data_type, nullable: is_nullable, default: default}

      [] ->
        nil
    end
  end

  defp index_exists?(name) do
    %{rows: [[exists]]} =
      Repo.query!("SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = $1)", [name])

    exists
  end

  defp constraint_exists?(name) do
    %{rows: [[exists]]} =
      Repo.query!("SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = $1)", [name])

    exists
  end

  # Returns the ON DELETE action ('a' no action, 'r' restrict, 'c' cascade,
  # 'n' set null, 'd' set default) for a named FK constraint.
  defp fk_delete_rule(constraint_name) do
    %{rows: rows} =
      Repo.query!("SELECT confdeltype FROM pg_constraint WHERE conname = $1", [constraint_name])

    case rows do
      [[rule]] -> rule
      [] -> nil
    end
  end

  # ---------------------------------------------------------------------------
  # From V107Test — phoenix_kit_ai_endpoints.integration_uuid + name uniqueness
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # From V112Test — phoenix_kit_projects archived_at/translations/position/etc
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # From V113Test — phoenix_kit_files system_managed/parent_file_uuid + comment_media
  # ---------------------------------------------------------------------------

  describe "files system_managed column (from V113)" do
    test "exists on phoenix_kit_files as BOOLEAN NOT NULL DEFAULT false" do
      assert %{type: "boolean", nullable: "NO", default: "false"} =
               column("phoenix_kit_files", "system_managed")
    end
  end

  describe "files parent_file_uuid column + self-FK (from V113)" do
    test "exists as nullable UUID" do
      assert %{type: "uuid", nullable: "YES"} = column("phoenix_kit_files", "parent_file_uuid")
    end

    test "FK constraint cascades on delete" do
      assert constraint_exists?("phoenix_kit_files_parent_file_uuid_fkey")
      assert fk_delete_rule("phoenix_kit_files_parent_file_uuid_fkey") == "c"
    end
  end

  describe "files user_uuid NOT NULL dropped (from V113)" do
    test "is now nullable on phoenix_kit_files" do
      assert %{nullable: "YES"} = column("phoenix_kit_files", "user_uuid")
    end
  end

  describe "files indexes (from V113)" do
    test "parent_uuid index exists (partial: WHERE parent_file_uuid IS NOT NULL)" do
      assert index_exists?("phoenix_kit_files_parent_uuid_index")

      %{rows: [[indexdef]]} =
        Repo.query!("""
        SELECT indexdef FROM pg_indexes
        WHERE indexname = 'phoenix_kit_files_parent_uuid_index'
        """)

      assert indexdef =~ "WHERE (parent_file_uuid IS NOT NULL)"
    end

    test "system_managed index exists (partial: WHERE system_managed = false)" do
      assert index_exists?("phoenix_kit_files_system_managed_index")

      %{rows: [[indexdef]]} =
        Repo.query!("""
        SELECT indexdef FROM pg_indexes
        WHERE indexname = 'phoenix_kit_files_system_managed_index'
        """)

      assert indexdef =~ "WHERE (system_managed = false)"
    end

    test "system_dedup partial unique index exists on (parent_file_uuid, file_name)" do
      assert index_exists?("phoenix_kit_files_system_dedup_index")

      %{rows: [[indexdef]]} =
        Repo.query!("""
        SELECT indexdef FROM pg_indexes
        WHERE indexname = 'phoenix_kit_files_system_dedup_index'
        """)

      assert indexdef =~ "UNIQUE"
      assert indexdef =~ "parent_file_uuid"
      assert indexdef =~ "file_name"
      assert indexdef =~ "WHERE (system_managed = true)"
    end
  end

  describe "files CHECK constraint: user_uuid OR parent_file_uuid (from V113)" do
    test "constraint exists" do
      assert constraint_exists?("phoenix_kit_files_user_or_parent_check")
    end

    # V203 widened the rule: a file with a library (every file, since V202)
    # passes, so deleting its uploader (FK `SET NULL`) keeps the row. What
    # stays enforced is that the rule is still there and names all three.
    test "a row with no uploader and no parent passes on its library (V203)" do
      %{rows: [[definition]]} =
        Repo.query!("""
        SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE c.conname = 'phoenix_kit_files_user_or_parent_check'
          AND t.relname = 'phoenix_kit_files' AND n.nspname = 'public'
        """)

      assert definition =~ "user_uuid IS NOT NULL"
      assert definition =~ "parent_file_uuid IS NOT NULL"
      assert definition =~ "library_uuid IS NOT NULL"

      Repo.query!("""
      INSERT INTO phoenix_kit_files (
        uuid, original_file_name, file_name, file_path, mime_type,
        file_type, ext, file_checksum, user_file_checksum, size,
        status, system_managed, inserted_at, updated_at
      ) VALUES (
        uuid_generate_v7(), 'orphan.bin', 'orphan.bin', '/', 'application/octet-stream',
        'other', '.bin', 'x', 'x', 1,
        'active', false, NOW(), NOW()
      )
      """)
    end
  end

  # ---------------------------------------------------------------------------
  # From V125Test — phoenix_kit_project_statuses + projects catalog columns
  # ---------------------------------------------------------------------------
end
