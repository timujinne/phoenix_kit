defmodule Mix.Tasks.PhoenixKit.DoctorOrphanedFkTest do
  @moduledoc """
  `fk_validation_state/5` against a REAL Postgres connection — separate from
  `DoctorTest` (which stays pure per its own moduledoc: `run/1` needs the
  whole app, so that file only exercises decision functions with no repo).
  This one function is different: it already takes `repo` as an explicit
  argument, so it is a real unit-test seam without starting anything.

  RED without this round's fix (gate round 2, finding 1): a genuinely
  failing probe — forced here with a deliberately malformed identifier,
  which the un-parameterized SQL this function builds turns into a real
  Postgres syntax error — used to collapse into `:absent` (the same shape as
  "no such constraint"), which is exactly how `mix phoenix_kit.doctor`
  printed PASS for a check it never actually ran.
  """
  use PhoenixKit.DataCase, async: true

  alias Mix.Tasks.PhoenixKit.Doctor, as: DoctorTask
  alias PhoenixKit.Test.Repo

  describe "fk_validation_state/5" do
    test "a genuinely failing probe returns {:probe_failed, reason}, never :absent" do
      # The unescaped single quote breaks the query's string-literal
      # boundary — a real Postgres syntax error (42601), not a contrived
      # Elixir-level fault. Exactly the shape a permission or catalog-access
      # failure would also take: `{:error, %Postgrex.Error{}}`.
      assert {:probe_failed, %Postgrex.Error{}} =
               DoctorTask.fk_validation_state(
                 Repo,
                 "phoenix_kit_users_tokens",
                 "x'y",
                 "phoenix_kit_users",
                 "public"
               )
    end

    test "a real, validated constraint still reads :validated (unchanged by this round)" do
      assert :validated =
               DoctorTask.fk_validation_state(
                 Repo,
                 "phoenix_kit_users_tokens",
                 "user_uuid",
                 "phoenix_kit_users",
                 "public"
               )
    end

    test "a genuinely absent shape still reads :absent, not probe_failed" do
      assert :absent =
               DoctorTask.fk_validation_state(
                 Repo,
                 "phoenix_kit_users_tokens",
                 "user_uuid",
                 "phoenix_kit_user_roles",
                 "public"
               )
    end
  end

  describe "discover_fk_constraints/2 — I055: full catalog coverage, not the old 4-pair list" do
    test "finds real FK constraints on the live schema, well beyond the old hardcoded four" do
      assert {:ok, {constraints, _skipped_multi}} =
               DoctorTask.discover_fk_constraints(Repo, "public")

      # The old check knew exactly 4 pairs. A real installed schema has far
      # more single-column FKs than that — this is the whole point of I055:
      # if this ever regresses back toward "4", the fix regressed with it.
      assert length(constraints) > 10

      assert Enum.any?(constraints, fn c ->
               c.table == "phoenix_kit_users_tokens" and c.fk_col == "user_uuid" and
                 c.ref_table == "phoenix_kit_users"
             end)

      # convalidated must be a real boolean read from the catalog, not a
      # placeholder — a stray `nil` here would silently break the
      # `if convalidated, do: :validated, else: {:not_valid, ...}` branch in
      # `probe_fk/4` for every single discovered constraint.
      assert Enum.all?(constraints, fn c -> is_boolean(c.convalidated) end)
    end

    test "a genuinely wrong schema name returns zero constraints, not an error — the caller decides that's zero coverage" do
      assert {:ok, {[], []}} =
               DoctorTask.discover_fk_constraints(Repo, "definitely_not_a_real_schema_12345")
    end

    test "a malformed schema name (real catalog-access fault) returns {:error, _}, never a silent empty list" do
      # The unescaped quote breaks the query's own string literal boundary —
      # a genuine Postgres syntax error, the same class of fault I055 finding
      # 2 warns can otherwise collapse into "nothing found" and print PASS.
      assert {:error, %Postgrex.Error{}} = DoctorTask.discover_fk_constraints(Repo, "x'y")
    end
  end

  describe "fk_probe_cost_context/4 — I055 decision 5: measure, don't guess" do
    test "a real, indexed FK column reports an actual row estimate and 'indexed', not a guess" do
      context =
        DoctorTask.fk_probe_cost_context(Repo, "phoenix_kit_users_tokens", "user_uuid", "public")

      assert context =~ "phoenix_kit_users_tokens.user_uuid:"
      assert context =~ "indexed"
      refute context =~ "table likely large"
    end

    test "a nonexistent table/column pair degrades to 'row count unknown', never raises" do
      context =
        DoctorTask.fk_probe_cost_context(
          Repo,
          "definitely_not_a_real_table_12345",
          "col",
          "public"
        )

      assert context =~ "row count unknown"
    end
  end

  describe "check_orphaned_fk_refs/1 — destructive: a genuinely orphaned row outside the old 4 pairs is caught" do
    # I055's widened check reads every single-column FK straight from
    # `pg_constraint` (`discover_fk_constraints/2`), not just the four pairs
    # the old check knew by name. This proves that widened coverage actually
    # catches something the old four-pair list could never have seen:
    # `phoenix_kit_user_oauth_providers.user_uuid -> phoenix_kit_users.uuid`
    # (constraint `fk_user_oauth_providers_user_uuid`) was never one of the
    # old four (`phoenix_kit_users_tokens`, `phoenix_kit_user_role_assignments`,
    # `phoenix_kit_admin_notes`, `phoenix_kit_email_events`).
    #
    # A plain `INSERT` can't produce this row — the constraint rejects a
    # nonexistent `user_uuid` immediately, and it isn't `DEFERRABLE`, so
    # `SET CONSTRAINTS ALL DEFERRED` doesn't buy anything either. Disabling
    # the child table's own triggers for one statement is the standard
    # Postgres idiom for planting a row that could otherwise only arise from
    # the same kind of bypass in production — a bulk load with constraints
    # off, a restore from an inconsistent backup, direct catalog surgery —
    # which is exactly the class of real corruption I055 exists to catch,
    # not a contrived test-only shape.
    test "an orphaned phoenix_kit_user_oauth_providers.user_uuid row is reported, not read as clean" do
      Repo.query!("ALTER TABLE phoenix_kit_user_oauth_providers DISABLE TRIGGER ALL")

      Repo.query!("""
      INSERT INTO phoenix_kit_user_oauth_providers
        (user_uuid, provider, provider_uid, inserted_at, updated_at)
      VALUES (gen_random_uuid(), 'google', 'i055-destructive-orphan-test', now(), now())
      """)

      Repo.query!("ALTER TABLE phoenix_kit_user_oauth_providers ENABLE TRIGGER ALL")

      assert {:fail, message} = DoctorTask.check_orphaned_fk_refs("public")
      assert message =~ "phoenix_kit_user_oauth_providers.user_uuid"
    end
  end
end
