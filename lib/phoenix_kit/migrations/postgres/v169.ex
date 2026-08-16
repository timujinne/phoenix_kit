defmodule PhoenixKit.Migrations.Postgres.V169 do
  @moduledoc """
  V169: anonymous entity submissions, and one duplicate foreign key.

  ## `phoenix_kit_entity_data.created_by_uuid` becomes nullable

  The public entity form is deliberately unauthenticated — that is the feature.
  It has nothing to put in `created_by_uuid`, and the column was NOT NULL, so on
  a freshly migrated database every anonymous submission died with a
  `not_null_violation` raised out of an unauthenticated controller
  (BeamLabEU/phoenix_kit#706).

  The two databases already disagreed about this. A long-lived install measured
  `is_nullable = YES` with 4 NULL rows out of 26, because V164 declines to
  re-impose NOT NULL while NULLs exist; a freshly migrated one measured
  `is_nullable = NO`, matching the source. Production had been storing anonymous
  submissions as NULL for some time and nothing had noticed — the consumers
  already guard for a missing creator (`data_navigator` renders
  `creator.email` only `if data_record.creator`).

  Nullable is the honest resolution of that split rather than a concession:

    * the column has **no foreign key** to `phoenix_kit_users` on any install
      (measured on both), so the invariant was never "a real user" — only "some
      UUID". The sister `created_by_uuid` columns that DO carry an FK are
      nullable with `ON DELETE SET NULL`;
    * the alternative — auto-filling the first Owner — puts a named person's
      address in front of every anonymous submission wherever a creator is
      rendered, and files those submissions in that person's audit trail.
      "Submitted by nobody" is a fact; attributing it to an administrator is
      not.

  Recorded in `V164`'s `@relaxed_after_v57` and corrected in `v135.ex`'s CREATE
  TABLE, so repair and a fresh install agree with this migration instead of
  fighting it — the same three-place treatment
  `phoenix_kit_users_tokens.user_uuid` got.

  ## `phoenix_kit_ai_requests.prompt_uuid` loses its duplicate FK

  `v135` adds this FK twice under two names, each block guarded only by its own
  name, so a freshly migrated database ends up with both
  (`fk_ai_requests_prompt_uuid` and
  `phoenix_kit_ai_requests_prompt_uuid_fkey`) — two identical constraint checks
  on every insert and update of the row, for no benefit
  (BeamLabEU/phoenix_kit_ai#20).

  **The legacy `phoenix_kit_ai_requests_prompt_uuid_fkey` is the one kept**, not
  the `fk_` name core's own `UUIDFKColumns.fk_constraint_name/2` would generate.
  It is the name the installed base actually carries — measured on two databases
  that have only that one — so converging on it renames nothing on a live
  install, and it is what Ecto's default `foreign_key_constraint/2` derives, so a
  consumer that never passed `:name` keeps working.

  Ordering matters: the survivor is created first when absent, so no install is
  ever momentarily left with no foreign key on the column.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)
    schema = schema_name(prefix)

    # Anonymous submissions are a supported flow; see the moduledoc. Idempotent:
    # DROP NOT NULL on an already-nullable column is a no-op. Guarded on the
    # table, like the AI block below — an unconditional ALTER is what turns a
    # partial install into a failed migration.
    execute("""
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_class t
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE t.relname = 'phoenix_kit_entity_data' AND n.nspname = '#{schema}'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_entity_data ALTER COLUMN "created_by_uuid" DROP NOT NULL;
      END IF;
    END
    $$
    """)

    # Converge the duplicated prompt FK onto the legacy name. Create-then-drop,
    # never drop-then-create: an install carrying only `fk_ai_requests_prompt_uuid`
    # must not lose referential integrity in between.
    #
    # Both statements sit inside ONE table-existence guard. `ALTER TABLE ... DROP
    # CONSTRAINT IF EXISTS` still requires the TABLE to exist — the `IF EXISTS`
    # only forgives a missing constraint — so an unguarded drop would raise
    # `relation does not exist` wherever the AI tables are absent.
    execute("""
    DO $$
    DECLARE
      survivor_ok boolean;
    BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_class t
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE t.relname = 'phoenix_kit_ai_requests' AND n.nspname = '#{schema}'
      ) THEN
        -- Shape, not just name. A constraint merely CALLED
        -- `phoenix_kit_ai_requests_prompt_uuid_fkey` — a CHECK, or a foreign key
        -- pointing somewhere else — is not the survivor, and treating it as one
        -- would drop the real `fk_` foreign key and leave the column
        -- unreferenced. Same reasoning as V164's `fk_shape_present`.
        SELECT EXISTS (
          SELECT 1 FROM pg_constraint c
          JOIN pg_class t ON t.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
          JOIN pg_class ref ON ref.oid = c.confrelid
          WHERE c.conname = 'phoenix_kit_ai_requests_prompt_uuid_fkey'
            AND t.relname = 'phoenix_kit_ai_requests'
            AND n.nspname = '#{schema}'
            AND c.contype = 'f'
            AND ref.relname = 'phoenix_kit_ai_prompts'
            AND c.conkey = ARRAY[
              (SELECT a.attnum FROM pg_attribute a
               WHERE a.attrelid = t.oid AND a.attname = 'prompt_uuid')
            ]::smallint[]
        ) INTO survivor_ok;

        IF NOT survivor_ok THEN
          -- Only safe to create when the name is free. If something else holds
          -- it, leave BOTH alone and say so rather than dropping a working key.
          IF EXISTS (
            SELECT 1 FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.conname = 'phoenix_kit_ai_requests_prompt_uuid_fkey'
              AND t.relname = 'phoenix_kit_ai_requests'
              AND n.nspname = '#{schema}'
          ) THEN
            RAISE WARNING 'phoenix_kit_ai_requests_prompt_uuid_fkey exists with an unexpected shape; leaving both prompt_uuid constraints untouched';
          ELSE
            ALTER TABLE #{p}phoenix_kit_ai_requests
              ADD CONSTRAINT phoenix_kit_ai_requests_prompt_uuid_fkey
              FOREIGN KEY (prompt_uuid) REFERENCES #{p}phoenix_kit_ai_prompts(uuid) ON DELETE SET NULL;
            survivor_ok := true;
          END IF;
        END IF;

        -- Never drop the duplicate unless a correctly shaped survivor is in
        -- place, so the column is never left with no foreign key at all.
        IF survivor_ok THEN
          ALTER TABLE #{p}phoenix_kit_ai_requests
            DROP CONSTRAINT IF EXISTS fk_ai_requests_prompt_uuid;
        END IF;
      END IF;
    END
    $$
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '169'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)
    schema = schema_name(prefix)

    # The de-duplication is deliberately NOT rolled back.
    #
    # `up` drops `fk_ai_requests_prompt_uuid` only where it exists, and the two
    # populations differ: a freshly migrated database had both names, an older
    # one had only the legacy `_fkey`. Nothing in the schema records which this
    # install was, so re-adding the `fk_` name here would hand the second group a
    # constraint they never had — inventing the duplicate on exactly the
    # databases that never suffered it. Leaving one correct foreign key in place
    # is a better rollback than restoring a defect.
    #
    # The column relaxation below IS reversible, and is what `down` restores.

    # Re-imposing NOT NULL is only possible when nothing relies on the
    # relaxation. Rolling back after even one anonymous submission would
    # otherwise abort the whole rollback, so this warns and leaves the column
    # nullable — the same choice V164 makes for the columns it repairs.
    execute("""
    DO $$
    DECLARE
      null_rows bigint;
    BEGIN
      -- Guarded on the table for the same reason `up/1` is: `LOCK TABLE` has no
      -- IF EXISTS, so an install without the entity tables would abort the whole
      -- rollback on `relation does not exist` — and `up/1` deliberately skipped
      -- them, so there is nothing here to undo.
      IF EXISTS (
        SELECT 1 FROM pg_class t
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE t.relname = 'phoenix_kit_entity_data' AND n.nspname = '#{schema}'
      ) THEN
        -- Take the lock the ALTER will need BEFORE counting. Otherwise a
        -- concurrent insert can add a NULL between the count and the ALTER, and
        -- the rollback aborts on exactly the case this branch exists to avoid.
        LOCK TABLE #{p}phoenix_kit_entity_data IN EXCLUSIVE MODE;

        SELECT count(*) INTO null_rows
        FROM #{p}phoenix_kit_entity_data WHERE created_by_uuid IS NULL;

        IF null_rows = 0 THEN
          ALTER TABLE #{p}phoenix_kit_entity_data ALTER COLUMN "created_by_uuid" SET NOT NULL;
        ELSE
          RAISE WARNING 'phoenix_kit_entity_data.created_by_uuid left nullable: % row(s) have no creator (anonymous public submissions). Resolve them before re-imposing NOT NULL.', null_rows;
        END IF;
      END IF;
    END
    $$
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '168'")
  end

  defp schema_name("public"), do: "public"
  defp schema_name(prefix), do: prefix

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
