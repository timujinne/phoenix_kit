defmodule PhoenixKit.Migrations.Postgres.V176Test do
  @moduledoc """
  V176's FK-validation repair, run against a real NOT VALID constraint with
  real orphaned rows behind it — the exact state A002's findings describe:
  `fk_users_tokens_user_uuid` sitting NOT VALID on a live install, nothing in
  core ever revisiting it.

  Filed as V175 originally; renumbered to V176 when upstream took V175 for
  an unrelated Buckets change while this branch was still in review.

  V176.up/1 can't be invoked outside an `Ecto.Migrator` runner (same
  constraint as V164Test/V174Test), and by the time any test runs the chain
  has already validated the declared FKs cleanly — empty test tables have no
  orphans to find, so testing "through the migrator" would prove nothing.
  This suite drives `validate_one/7` directly instead — the exact function
  `up/1` calls once per declared FK — against `phoenix_kit_users_tokens`
  after deliberately reproducing the real-world shape: a VALID constraint
  enforces every new write regardless of its own validation flag, so the
  only way a NOT VALID foreign key ever has orphaned rows behind it is that
  the rows predate the constraint. Reproduced here by dropping the
  (already-valid, chain-created) constraint, inserting a row that would
  violate it, then re-adding it NOT VALID — there is no other way to get an
  orphan behind a live FK.

  `async: false`: DROP/ADD CONSTRAINT takes a lock on
  `phoenix_kit_users_tokens`, a table virtually every other test in this
  repo touches (session tokens on login). Safe to hold for the length of
  this test's own sandboxed transaction (rolled back after, same as every
  other `DataCase` test), not worth the contention risk against
  concurrently running async tests.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.Postgres.V176
  alias PhoenixKit.Migrations.UUIDFKColumns
  alias PhoenixKit.Test.Repo

  @table "phoenix_kit_users_tokens"
  # `validate_one/7` takes `table` as an atom — the exact shape
  # `UUIDFKColumns.fk_constraints/0` entries carry, and what `up/1` passes it
  # in production. `@table` stays a string for SQL interpolation everywhere
  # else in this file.
  @table_atom :phoenix_kit_users_tokens
  @fk_col "user_uuid"
  @ref_table "phoenix_kit_users"
  @ref_col "uuid"
  @conname UUIDFKColumns.fk_constraint_name(@table, @fk_col)

  defp drop_constraint! do
    Repo.query!("ALTER TABLE #{@table} DROP CONSTRAINT #{@conname}")
  end

  # ON DELETE CASCADE matches UUIDFKColumns.fk_constraints/0's own
  # declaration for this pair — the same shape V164 creates it with.
  defp readd_not_valid! do
    Repo.query!("""
    ALTER TABLE #{@table}
    ADD CONSTRAINT #{@conname}
    FOREIGN KEY (#{@fk_col}) REFERENCES #{@ref_table}(#{@ref_col})
    ON DELETE CASCADE
    NOT VALID
    """)
  end

  defp convalidated? do
    %{rows: [[value]]} =
      Repo.query!(
        "SELECT c.convalidated FROM pg_constraint c JOIN pg_namespace n " <>
          "ON n.oid = c.connamespace WHERE c.conname = $1 AND n.nspname = 'public'",
        [@conname]
      )

    value
  end

  # No registered user needed: the whole point of this row is that it
  # points at a uuid nothing owns.
  defp insert_orphan_token! do
    now = DateTime.utc_now()

    {1, [%{uuid: uuid}]} =
      Repo.insert_all(
        @table,
        [
          %{
            token: :crypto.strong_rand_bytes(32),
            context: "session",
            user_uuid: Ecto.UUID.dump!(Ecto.UUID.generate()),
            inserted_at: now
          }
        ],
        returning: [:uuid]
      )

    uuid
  end

  defp token_exists?(uuid) do
    %{rows: [[count]]} =
      Repo.query!("SELECT count(*) FROM #{@table} WHERE uuid = $1", [uuid])

    count == 1
  end

  defp run_validate do
    V176.validate_one(Repo, @table_atom, @fk_col, @ref_table, @ref_col, "public", "public")
  end

  describe "validate_one/7 — orphaned rows present" do
    test "the constraint stays NOT VALID, the row survives, and the count is exact" do
      assert convalidated?() == true

      drop_constraint!()
      orphan_uuid = insert_orphan_token!()
      readd_not_valid!()
      refute convalidated?()

      label = run_validate()

      assert label =~ @conname
      assert label =~ "1 orphaned row"
      assert label =~ "left NOT VALID"

      # The one promise this version exists to keep: never delete a row or
      # null a reference to force the constraint through.
      refute convalidated?()
      assert token_exists?(orphan_uuid)
    end

    test "a second orphan changes only the count, not the outcome" do
      drop_constraint!()
      insert_orphan_token!()
      insert_orphan_token!()
      readd_not_valid!()

      assert run_validate() =~ "2 orphaned row"
      refute convalidated?()
    end
  end

  describe "validate_one/7 — no orphaned rows (RED without this version: nothing else in core ever calls VALIDATE CONSTRAINT on an already-existing key)" do
    test "the constraint becomes valid" do
      assert convalidated?() == true

      drop_constraint!()
      readd_not_valid!()
      refute convalidated?()

      assert run_validate() == nil
      assert convalidated?() == true
    end

    test "an already-valid constraint is left alone (no-op, idempotent)" do
      assert convalidated?() == true
      assert run_validate() == nil
      assert convalidated?() == true
    end
  end

  describe "attempt_validate/8 — VALIDATE fails for a reason OTHER than orphans (gate round 2, finding 2)" do
    test "RED without this round's fix: a swallowed VALIDATE failure must not report success" do
      drop_constraint!()
      readd_not_valid!()
      refute convalidated?()

      # Zero real orphans, so Probe.orphan_count/6 reads clean and this
      # proceeds to VALIDATE. A conname that does not exist makes Postgres
      # refuse (undefined_object, 42704) inside the DO block's EXCEPTION
      # handler -- caught there, logged to the Postgres log only, and
      # (before this round's fix) reported to Elixir as `nil`, i.e.
      # "validated", because "the query didn't raise" was trusted as
      # success. The real constraint (@conname) is untouched by any of this
      # and must stay exactly as NOT VALID as it started.
      label =
        V176.attempt_validate(
          Repo,
          @table,
          @fk_col,
          @ref_table,
          @ref_col,
          "fk_this_constraint_does_not_exist",
          "public",
          "public"
        )

      refute is_nil(label)
      assert label =~ "could not be validated"

      refute convalidated?()
    end

    test "a real VALIDATE success is still reported as success (nil), unchanged by this round" do
      drop_constraint!()
      readd_not_valid!()

      assert V176.attempt_validate(
               Repo,
               @table,
               @fk_col,
               @ref_table,
               @ref_col,
               @conname,
               "public",
               "public"
             ) == nil

      assert convalidated?()
    end

    test "RED without this round's fix: an already-valid twin under a different name must not count as the target validating (minor finding 2)" do
      # @conname is left exactly as this file's own setup leaves it: real,
      # and VALID. fk_shape_present/6 matches by shape (referencing column ->
      # referenced column), not by name -- on purpose, so a twin V164 itself
      # adopted under a different name is still found. That is correct for
      # V164's own use. Here it means a shape probe taken AFTER a failed
      # VALIDATE of some other name finds @conname anyway and reports it
      # valid -- true, but not proof that the name actually asked for
      # (`bogus_conname`, which was never created) validated.
      bogus_conname = "fk_users_tokens_user_uuid_does_not_exist"

      # Probe.orphan_count/6 genuinely reads 0 (real state, @conname is
      # untouched and clean), so attempt_validate proceeds to
      # `VALIDATE CONSTRAINT #{bogus_conname}` -- a name Postgres refuses
      # (undefined_object, 42704), caught by the DO block's EXCEPTION
      # handler and never raised into Elixir.
      label =
        V176.attempt_validate(
          Repo,
          @table,
          @fk_col,
          @ref_table,
          @ref_col,
          bogus_conname,
          "public",
          "public"
        )

      refute is_nil(label)
      assert label =~ "could not be validated"

      # The real constraint was never asked to validate and stays exactly as
      # it started -- untouched by any of this.
      assert convalidated?()
    end
  end
end
