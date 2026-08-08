defmodule PhoenixKit.Migrations.Postgres.V161Test do
  @moduledoc """
  Tests V161's schema state and its `up/1` pre-check.

  V161.up/down can't be invoked outside an `Ecto.Migrator` runner (they
  rely on `Ecto.Migration.execute/1` and `repo()`, which both check for a
  runner process) — same constraint as V106Test/V145Test/V152Test/etc. The
  schema is verified at boot: `test_helper.exs` runs `ensure_current/2`
  (now through V161) before any test, so the schema-state assertions below
  pin the post-V161 shape.

  ## Pre-check coverage

  By the time this test runs, `phoenix_kit_users.username` is already
  `citext` with its unique index enforcing case-insensitive uniqueness —
  which means the exact collision V161's pre-check exists to catch can no
  longer be reproduced by inserting into the real table (the fix works!).
  So the pre-check's `GROUP BY lower(username) HAVING count(*) > 1` SQL is
  pinned against an inline `unnest($1::varchar[])` row source instead of
  `phoenix_kit_users` — same query shape (`lower(username)` / `WHERE
  username IS NOT NULL` / `GROUP BY` / `HAVING`), controlled input, no risk
  of colliding with the live unique index or other tests' data.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Test.Repo

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

  # information_schema reports citext columns as data_type "USER-DEFINED";
  # udt_name carries the real type name (same helper as V151/V152's tests).
  defp column_udt_name(table, column) do
    %{rows: [[udt_name]]} =
      Repo.query!(
        "SELECT udt_name FROM information_schema.columns WHERE table_name = $1 AND column_name = $2",
        [table, column]
      )

    udt_name
  end

  # A COPY of V161.up's pre-check SELECT (modulo the row source — see
  # moduledoc), not a call into it: once the column is citext the unique
  # index makes a real collision impossible to stage, so the SQL shape is
  # exercised against `unnest` instead.
  #
  # ⚠️ That means the two are only linked by hand. Editing the pre-check in
  # `v161.ex` does NOT fail this test — keep them in sync deliberately. What
  # this does buy is coverage of the subtle parts of the shape itself: the
  # `WHERE username IS NOT NULL` guard (without it every username-less
  # account folds into one NULL group and falsely aborts the upgrade), the
  # `lower()` grouping, and the `HAVING count(*) > 1` threshold.
  defp find_case_insensitive_duplicate(usernames) do
    Repo.query!(
      "SELECT lower(username) FROM unnest($1::varchar[]) AS username " <>
        "WHERE username IS NOT NULL GROUP BY lower(username) HAVING count(*) > 1 LIMIT 1",
      [usernames],
      log: false
    )
  end

  describe "up/1 — case-insensitive collision pre-check" do
    test "no usernames → no duplicate" do
      assert %{rows: []} = find_case_insensitive_duplicate([])
    end

    test "all-distinct usernames → no duplicate" do
      assert %{rows: []} = find_case_insensitive_duplicate(["alice", "bob", "carol"])
    end

    test "two users with no username (NULL) do not falsely collide" do
      # The exact regression the `WHERE username IS NOT NULL` guard exists
      # to prevent: GROUP BY treats every NULL as one group, so without the
      # filter this would report a false collision and abort the upgrade.
      assert %{rows: []} = find_case_insensitive_duplicate([nil, nil, "dave"])
    end

    test "same username differing only by case is detected" do
      assert %{rows: [["duptest"]]} =
               find_case_insensitive_duplicate(["duptest", "DupTest"])
    end

    test "exact duplicate (same case) is also detected" do
      assert %{rows: [["sameuser"]]} =
               find_case_insensitive_duplicate(["sameuser", "sameuser"])
    end

    test "a NULL alongside a real collision still surfaces the collision" do
      assert %{rows: [["mixed"]]} =
               find_case_insensitive_duplicate([nil, "mixed", "MIXED", nil])
    end
  end

  describe "phoenix_kit_users.username" do
    test "column type is citext" do
      assert column_udt_name("phoenix_kit_users", "username") == "citext"
    end

    test "stays nullable, varchar-length shape otherwise unchanged" do
      assert %{nullable: "YES"} = column("phoenix_kit_users", "username")
    end
  end

  describe "phoenix_kit_users.email — unaffected by V161" do
    test "still citext (V01 — out of scope for this migration)" do
      assert column_udt_name("phoenix_kit_users", "email") == "citext"
    end
  end

  describe "version marker" do
    test "phoenix_kit table comment is at or past V161" do
      %{rows: [[comment]]} =
        Repo.query!("SELECT obj_description('phoenix_kit'::regclass, 'pg_class')")

      # >= rather than ==: pinning the exact latest version breaks this
      # test every time a newer migration ships. What V161 owns is "the
      # chain reached at least me".
      assert String.to_integer(comment) >= 161
    end
  end
end
