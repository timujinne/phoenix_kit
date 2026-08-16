defmodule PhoenixKit.Integration.V168SlugIndexTest do
  @moduledoc """
  V168 repairs duplicate ticket and post-group slugs before it can build the unique
  indexes, so every test here manufactures the duplicates first.

  Each builds its own scratch table shaped like the real one rather than damaging it,
  so a failure cannot corrupt the schema for whatever runs next. The SQL under test is
  the migration's, run against that table. Same pattern as the V167 test.
  """
  use PhoenixKit.DataCase, async: false

  setup do
    tickets = "phoenix_kit_zz_v168_t_#{System.unique_integer([:positive])}"
    groups = "phoenix_kit_zz_v168_g_#{System.unique_integer([:positive])}"

    on_exit(fn ->
      Repo.query("DROP TABLE IF EXISTS #{tickets}", [])
      Repo.query("DROP TABLE IF EXISTS #{groups}", [])
    end)

    Repo.query!("""
    CREATE TABLE #{tickets} (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      slug character varying(255) NOT NULL,
      inserted_at timestamptz NOT NULL DEFAULT now()
    )
    """)

    Repo.query!("CREATE INDEX #{tickets}_slug_index ON #{tickets} USING btree (slug)")

    Repo.query!("""
    CREATE TABLE #{groups} (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_uuid uuid NOT NULL,
      slug character varying(255) NOT NULL,
      inserted_at timestamptz NOT NULL DEFAULT now()
    )
    """)

    {:ok, tickets: tickets, groups: groups}
  end

  # The migration's ticket dedup, verbatim except for the table name.
  defp dedup_tickets(table) do
    Repo.query!("""
    DO $$
    DECLARE
      r RECORD; suffix text; base text; candidate text; n int;
    BEGIN
      FOR r IN
        SELECT uuid, slug FROM (
          SELECT uuid, slug,
                 row_number() OVER (
                   PARTITION BY slug ORDER BY inserted_at ASC, uuid ASC) AS rn
            FROM #{table}) ranked
         WHERE rn > 1 ORDER BY slug, rn
      LOOP
        n := 2;
        LOOP
          suffix := '-' || n;
          base := regexp_replace(left(r.slug, 255 - length(suffix)), '-+$', '');
          candidate := base || suffix;
          EXIT WHEN NOT EXISTS (SELECT 1 FROM #{table} WHERE slug = candidate);
          n := n + 1;
        END LOOP;
        UPDATE #{table} SET slug = candidate WHERE uuid = r.uuid;
      END LOOP;
    END $$;
    """)
  end

  # The migration's post-group dedup, verbatim except for the table name.
  defp dedup_groups(table) do
    Repo.query!("""
    DO $$
    DECLARE
      r RECORD; suffix text; base text; candidate text; n int;
    BEGIN
      FOR r IN
        SELECT uuid, user_uuid, slug FROM (
          SELECT uuid, user_uuid, slug,
                 row_number() OVER (
                   PARTITION BY user_uuid, slug
                   ORDER BY inserted_at ASC, uuid ASC) AS rn
            FROM #{table}) ranked
         WHERE rn > 1 ORDER BY user_uuid, slug, rn
      LOOP
        n := 2;
        LOOP
          suffix := '-' || n;
          base := regexp_replace(left(r.slug, 255 - length(suffix)), '-+$', '');
          candidate := base || suffix;
          EXIT WHEN NOT EXISTS (
            SELECT 1 FROM #{table} WHERE user_uuid = r.user_uuid AND slug = candidate);
          n := n + 1;
        END LOOP;
        UPDATE #{table} SET slug = candidate WHERE uuid = r.uuid;
      END LOOP;
    END $$;
    """)
  end

  defp insert_ticket!(table, slug, inserted_at) do
    %{rows: [[uuid]]} =
      Repo.query!(
        "INSERT INTO #{table} (slug, inserted_at) VALUES ($1, $2) RETURNING uuid",
        [slug, inserted_at]
      )

    uuid
  end

  defp insert_group!(table, user_uuid, slug, inserted_at) do
    %{rows: [[uuid]]} =
      Repo.query!(
        "INSERT INTO #{table} (user_uuid, slug, inserted_at) VALUES ($1, $2, $3) RETURNING uuid",
        [Ecto.UUID.dump!(user_uuid), slug, inserted_at]
      )

    uuid
  end

  defp slug_of(table, uuid) do
    %{rows: [[slug]]} = Repo.query!("SELECT slug FROM #{table} WHERE uuid = $1", [uuid])
    slug
  end

  defp t(offset), do: DateTime.add(~U[2026-01-01 00:00:00Z], offset, :second)

  describe "ticket dedup" do
    test "the oldest row keeps the bare slug and later ones are suffixed", %{tickets: table} do
      first = insert_ticket!(table, "broken-login", t(0))
      second = insert_ticket!(table, "broken-login", t(10))
      third = insert_ticket!(table, "broken-login", t(20))

      dedup_tickets(table)

      assert slug_of(table, first) == "broken-login"
      assert slug_of(table, second) == "broken-login-2"
      assert slug_of(table, third) == "broken-login-3"
    end

    test "an unrelated row already holding the -2 pushes the duplicate to -3", %{tickets: table} do
      first = insert_ticket!(table, "printer", t(0))
      dup = insert_ticket!(table, "printer", t(10))
      squatter = insert_ticket!(table, "printer-2", t(20))

      dedup_tickets(table)

      assert slug_of(table, first) == "printer"
      assert slug_of(table, squatter) == "printer-2"
      assert slug_of(table, dup) == "printer-3"
    end

    test "a 255-char slug is trimmed to fit its suffix rather than overflowing", %{
      tickets: table
    } do
      long = String.duplicate("a", 255)
      first = insert_ticket!(table, long, t(0))
      dup = insert_ticket!(table, long, t(10))

      dedup_tickets(table)

      assert slug_of(table, first) == long
      repaired = slug_of(table, dup)
      assert String.length(repaired) <= 255
      assert String.ends_with?(repaired, "-2")
    end

    test "a slug ending in a dash does not become a double dash", %{tickets: table} do
      # left() can cut mid-word and leave a trailing dash; the regexp_replace strips it.
      long = String.duplicate("ab-", 84) <> "abc"
      first = insert_ticket!(table, long, t(0))
      dup = insert_ticket!(table, long, t(10))

      dedup_tickets(table)

      assert slug_of(table, first) == long
      refute slug_of(table, dup) =~ "--"
    end

    test "the unique index builds once the duplicates are gone", %{tickets: table} do
      insert_ticket!(table, "same", t(0))
      insert_ticket!(table, "same", t(10))

      # Proves the ordering matters: the index cannot be built first.
      assert_raise Postgrex.Error, fn ->
        Repo.query!("CREATE UNIQUE INDEX #{table}_u ON #{table} USING btree (slug)")
      end

      dedup_tickets(table)

      Repo.query!("DROP INDEX IF EXISTS #{table}_slug_index")
      Repo.query!("CREATE UNIQUE INDEX #{table}_slug_index ON #{table} USING btree (slug)")

      assert_raise Postgrex.Error, fn ->
        Repo.query!("INSERT INTO #{table} (slug) VALUES ('same')")
      end
    end
  end

  describe "post group dedup is scoped to the owner" do
    test "two users may hold the same slug and neither is touched", %{groups: table} do
      alice = Ecto.UUID.generate()
      bob = Ecto.UUID.generate()

      a = insert_group!(table, alice, "notes", t(0))
      b = insert_group!(table, bob, "notes", t(10))

      dedup_groups(table)

      assert slug_of(table, a) == "notes"
      assert slug_of(table, b) == "notes"
    end

    test "one user holding it twice is repaired", %{groups: table} do
      alice = Ecto.UUID.generate()

      first = insert_group!(table, alice, "notes", t(0))
      second = insert_group!(table, alice, "notes", t(10))

      dedup_groups(table)

      assert slug_of(table, first) == "notes"
      assert slug_of(table, second) == "notes-2"
    end

    test "the suffix probe is scoped, so another user's -2 does not push it to -3", %{
      groups: table
    } do
      alice = Ecto.UUID.generate()
      bob = Ecto.UUID.generate()

      insert_group!(table, bob, "notes-2", t(0))
      first = insert_group!(table, alice, "notes", t(10))
      second = insert_group!(table, alice, "notes", t(20))

      dedup_groups(table)

      assert slug_of(table, first) == "notes"
      # Bob's "notes-2" is irrelevant to Alice's namespace.
      assert slug_of(table, second) == "notes-2"
    end

    test "the composite unique index builds and then enforces per-user uniqueness", %{
      groups: table
    } do
      alice = Ecto.UUID.generate()
      bob = Ecto.UUID.generate()
      insert_group!(table, alice, "notes", t(0))
      insert_group!(table, alice, "notes", t(10))

      dedup_groups(table)

      Repo.query!("CREATE UNIQUE INDEX #{table}_u ON #{table} USING btree (user_uuid, slug)")

      # Bob may still take the slug Alice holds.
      Repo.query!("INSERT INTO #{table} (user_uuid, slug) VALUES ($1, 'notes')", [
        Ecto.UUID.dump!(bob)
      ])

      # Alice may not take it twice.
      assert_raise Postgrex.Error, fn ->
        Repo.query!("INSERT INTO #{table} (user_uuid, slug) VALUES ($1, 'notes')", [
          Ecto.UUID.dump!(alice)
        ])
      end
    end
  end
end
