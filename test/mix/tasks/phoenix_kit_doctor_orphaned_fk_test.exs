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
end
