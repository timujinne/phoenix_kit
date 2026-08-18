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
end
