defmodule PhoenixKit.Integration.ConstraintDeclarationTest do
  @moduledoc """
  Every constraint a changeset declares must exist in the database under that
  exact name.

  Ecto matches a constraint by NAME. `foreign_key_constraint(:user_uuid)` with no
  `:name` expects `<table>_user_uuid_fkey`, but this chain names most of its
  foreign keys `fk_<table-without-prefix>_<column>` — so the declaration silently
  matches nothing, and a violation escapes as a raw `Ecto.ConstraintError` (a 500)
  instead of the changeset error the caller is written to handle.

  Eleven declarations were wrong this way when this test was written, across
  storage, admin notes, OAuth providers, role assignments and role permissions.
  A per-site test would have pinned each one; this pins the RULE, so the next
  schema cannot repeat it.

  Names are read from the live database rather than parsed out of the migration
  chain, because the chain is what the database is built from but not what it
  necessarily still holds — a renamed column can leave a constraint carrying its
  old name (`phoenix_kit_file_instances_file_id_fkey` on a `file_uuid` column is
  exactly that).
  """
  use PhoenixKit.DataCase, async: true

  # Declarations with no backing database object, kept deliberately.
  #
  # `phoenix_kit_activities` has no foreign keys on ANY install (verified on a
  # freshly migrated database and on a long-lived one): activity rows outlive
  # the users they mention, which is the point of an audit log. The
  # declarations are inert rather than wrong — Ecto simply never matches them —
  # and they stay so the changeset already handles it the day an FK is added.
  @known_unbacked [
    {"phoenix_kit_activities", "phoenix_kit_activities_actor_uuid_fkey"},
    {"phoenix_kit_activities", "phoenix_kit_activities_target_uuid_fkey"}
  ]

  # Ecto's constraint types map onto different catalog objects, and conflating
  # them lets a wrong declaration pass: a NON-unique index named like a unique
  # constraint would satisfy a `unique_constraint`, and a CHECK would satisfy a
  # `foreign_key_constraint`. Keep them apart.
  defp existing_by_type(repo, schema) do
    {:ok, %{rows: constraints}} =
      repo.query(
        """
        SELECT t.relname, c.conname, c.contype
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = $1
        """,
        [schema]
      )

    # A `CREATE UNIQUE INDEX` produces no pg_constraint row, yet Postgres still
    # reports the INDEX name on violation and Ecto matches on that — so unique
    # declarations have to be checked against pg_indexes too, or every one of
    # them reads as broken. Unique indexes only.
    {:ok, %{rows: unique_indexes}} =
      repo.query(
        """
        SELECT tablename, indexname FROM pg_indexes
        WHERE schemaname = $1 AND indexdef LIKE 'CREATE UNIQUE INDEX%'
        """,
        [schema]
      )

    Enum.reduce(constraints, %{}, fn [table, name, contype], acc ->
      type =
        case contype do
          "f" -> :foreign_key
          "u" -> :unique
          "p" -> :unique
          "c" -> :check
          "x" -> :exclusion
          _ -> :other
        end

      Map.update(acc, type, MapSet.new([{table, name}]), &MapSet.put(&1, {table, name}))
    end)
    |> Map.update(
      :unique,
      MapSet.new(unique_indexes, fn [t, i] -> {t, i} end),
      fn existing ->
        Enum.reduce(unique_indexes, existing, fn [t, i], acc -> MapSet.put(acc, {t, i}) end)
      end
    )
  end

  defp core_schemas do
    {:ok, modules} = :application.get_key(:phoenix_kit, :modules)

    modules
    |> Enum.filter(fn mod ->
      Code.ensure_loaded?(mod) and function_exported?(mod, :__schema__, 1) and
        function_exported?(mod, :changeset, 2)
    end)
    |> Enum.sort()
  end

  test "every declared constraint exists in the database under that name" do
    schema = Application.get_env(:phoenix_kit, :prefix, "public")
    existing_by_type = existing_by_type(PhoenixKit.Test.Repo, schema)
    known_unbacked = MapSet.new(@known_unbacked)

    inspected =
      for mod <- core_schemas(),
          changeset = safe_changeset(mod),
          changeset != nil,
          do: {mod, mod.__schema__(:source), changeset.constraints}

    # A schema whose changeset/2 cannot be built from empty attrs is skipped,
    # which is a silent hole — assert enough of the tree was actually inspected
    # that a wholesale skip (a compile change, a renamed callback) cannot pass
    # this test by inspecting nothing.
    assert length(inspected) >= 20,
           "only #{length(inspected)} schema(s) inspected — the discovery or " <>
             "changeset construction above is broken, so this test proves nothing"

    # Grouped per field, because declaring the SAME field under two names is a
    # deliberate pattern where the surviving constraint name differs by install
    # age (phoenix_kit_ai's prompt_uuid). Only one of those can exist on any one
    # database; the group is satisfied when any declared name is real.
    missing =
      for {mod, table, constraints} <- inspected,
          # `match: :suffix`/`:prefix` declarations are matched by Ecto against a
          # PART of the reported name, so an exact-name check would misjudge
          # them. None exist today; skipping keeps this honest if one appears.
          {{field, type}, declared} <-
            constraints
            |> Enum.filter(&(Map.get(&1, :match, :exact) == :exact))
            |> Enum.group_by(&{&1.field, &1.type}, & &1.constraint),
          existing = Map.get(existing_by_type, type, MapSet.new()),
          not Enum.any?(declared, &MapSet.member?(existing, {table, &1})),
          not Enum.all?(declared, &MapSet.member?(known_unbacked, {table, &1})) do
        "#{inspect(mod)} declares #{type} on #{table}.#{field} as " <>
          "#{Enum.map_join(declared, " / ", &inspect/1)}, none of which exists"
      end

    assert missing == [], """
    #{length(missing)} constraint declaration(s) match nothing in the database:

    #{Enum.map_join(missing, "\n", &"  - #{&1}")}

    Ecto matches constraints by name. A declaration that names a constraint the
    chain never created can never fire, so the violation raises
    Ecto.ConstraintError instead of returning a changeset error. Pass the name
    the migration actually creates:

        foreign_key_constraint(:user_uuid, name: :fk_files_user_uuid)

    If the object genuinely does not exist on any install and the declaration is
    deliberate, add it to @known_unbacked with the reason.
    """
  end

  # A schema's changeset/2 registers its constraints regardless of whether the
  # attrs are valid, so empty attrs are enough. Some take different arities or
  # require a struct shape we cannot guess — skip those rather than fail, since
  # a skipped schema costs coverage while a crashed one costs the whole test.
  defp safe_changeset(mod) do
    struct = struct(mod)
    mod.changeset(struct, %{})
  rescue
    _ -> nil
  catch
    _, _ -> nil
  end
end
