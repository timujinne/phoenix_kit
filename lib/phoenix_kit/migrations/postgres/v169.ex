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

  ## Core 3.0

  Everything this version did belonged to a module's tables and now lives in
  that module's own migration chain (`PhoenixKit.Migrations.ModuleOwnedTables`,
  plan `dev_docs/plans/2026-10-25-module-table-ownership.md`, step 8): core no
  longer creates or changes them. The version is kept so the chain stays
  numbered; it only moves the marker. Hosts below V225 cannot upgrade to this
  release (`BelowFloorError`), so nobody replays what the text above describes.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '169'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '168'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
