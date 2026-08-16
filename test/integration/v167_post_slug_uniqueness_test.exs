defmodule PhoenixKit.Integration.V167PostSlugUniquenessTest do
  @moduledoc """
  V167 repairs duplicate post slugs, which a current install can no longer
  produce — so every test here manufactures the duplicates first.

  Each builds its own scratch table shaped like `phoenix_kit_posts` rather than
  damaging the real one, so a failure cannot corrupt the schema for whatever
  runs next. The SQL under test is the migration's, run against that table.
  """
  use PhoenixKit.DataCase, async: false

  setup do
    table = "phoenix_kit_zz_v167_#{System.unique_integer([:positive])}"
    on_exit(fn -> Repo.query("DROP TABLE IF EXISTS #{table}", []) end)

    Repo.query!("""
    CREATE TABLE #{table} (
      uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      slug character varying(255) NOT NULL,
      status character varying(50) NOT NULL DEFAULT 'draft',
      inserted_at timestamp(0) without time zone NOT NULL DEFAULT now()
    )
    """)

    Repo.query!("CREATE INDEX #{table}_slug_index ON #{table} USING btree (slug)")

    {:ok, table: table}
  end

  defp insert!(table, slug, status, inserted_at) do
    %{rows: [[uuid]]} =
      Repo.query!(
        "INSERT INTO #{table} (slug, status, inserted_at) VALUES ($1, $2, $3) RETURNING uuid",
        [slug, status, inserted_at]
      )

    uuid
  end

  defp slug_of(table, uuid) do
    %{rows: [[slug]]} = Repo.query!("SELECT slug FROM #{table} WHERE uuid = $1", [uuid])
    slug
  end

  defp at(seconds_ago) do
    DateTime.utc_now() |> DateTime.add(-seconds_ago, :second) |> DateTime.to_naive()
  end

  # The migration's repair block, with the table name substituted. Kept in one
  # place so a change to the migration has to be reflected here to stay green.
  defp dedupe!(table) do
    Repo.query!("""
    DO $$
    DECLARE
      g RECORD; r RECORD; suffix text; base text; candidate text; n int;
    BEGIN
      FOR g IN
        SELECT slug, count(*) FILTER (
                 WHERE status IN ('public', 'unlisted', 'scheduled')) AS live_n
          FROM #{table} GROUP BY slug HAVING count(*) > 1
      LOOP
        IF g.live_n > 1 THEN
          RAISE EXCEPTION
            'Cannot apply V167: slug % is shared by % live posts. Give one of them a different slug, then upgrade.',
            g.slug, g.live_n;
        END IF;
      END LOOP;

      FOR r IN
        SELECT uuid, slug FROM (
          SELECT uuid, slug, row_number() OVER (
            PARTITION BY slug
            ORDER BY CASE WHEN status IN ('public', 'unlisted', 'scheduled')
                          THEN 0 ELSE 1 END,
                     inserted_at ASC, uuid ASC) AS rn
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

  defp swap_index!(table) do
    Repo.query!("DROP INDEX IF EXISTS #{table}_slug_index")

    Repo.query!(
      "CREATE UNIQUE INDEX IF NOT EXISTS #{table}_slug_index ON #{table} USING btree (slug)"
    )
  end

  describe "de-duplication" do
    test "the oldest keeps the slug, later ones are suffixed", %{table: t} do
      a = insert!(t, "foo", "draft", at(300))
      b = insert!(t, "foo", "draft", at(200))
      c = insert!(t, "foo", "draft", at(100))

      dedupe!(t)

      assert slug_of(t, a) == "foo"
      assert slug_of(t, b) == "foo-2"
      assert slug_of(t, c) == "foo-3"
    end

    test "a suffix already taken by an unrelated post is skipped", %{table: t} do
      # The case a naive row_number() suffix gets wrong: "foo-2" exists
      # already, so the duplicate has to land on "foo-3".
      a = insert!(t, "foo", "draft", at(300))
      b = insert!(t, "foo", "draft", at(200))
      unrelated = insert!(t, "foo-2", "draft", at(250))

      dedupe!(t)

      assert slug_of(t, a) == "foo"
      assert slug_of(t, b) == "foo-3"
      assert slug_of(t, unrelated) == "foo-2"
    end

    test "a reachable post outranks an older draft", %{table: t} do
      draft = insert!(t, "foo", "draft", at(300))
      live = insert!(t, "foo", "public", at(100))

      dedupe!(t)

      # The draft is older but has no URL anyone can have linked.
      assert slug_of(t, live) == "foo"
      assert slug_of(t, draft) == "foo-2"
    end

    test "identical timestamps still produce a stable, total order", %{table: t} do
      # timestamps(type: :utc_datetime) stores whole seconds with no DB
      # default, so ties are ordinary. Without the uuid tiebreak the winner
      # would vary per run.
      same = at(100)
      a = insert!(t, "foo", "draft", same)
      b = insert!(t, "foo", "draft", same)

      dedupe!(t)

      [first, second] = Enum.sort([slug_of(t, a), slug_of(t, b)])
      assert first == "foo"
      assert second == "foo-2"
    end

    test "two live posts raise, and nothing is rewritten", %{table: t} do
      a = insert!(t, "foo", "public", at(300))
      b = insert!(t, "foo", "unlisted", at(100))

      assert_raise Postgrex.Error, ~r/shared by 2 live posts/, fn -> dedupe!(t) end

      assert slug_of(t, a) == "foo"
      assert slug_of(t, b) == "foo"
    end

    test "a 255-character slug is trimmed to fit rather than overflowing", %{table: t} do
      # varchar(255) ERRORS on overflow, it does not truncate.
      long = String.duplicate("a", 255)
      a = insert!(t, long, "draft", at(300))
      b = insert!(t, long, "draft", at(100))

      dedupe!(t)

      assert slug_of(t, a) == long
      assert String.length(slug_of(t, b)) == 255
      assert String.ends_with?(slug_of(t, b), "-2")
    end

    test "a base ending in a dash does not produce a double dash", %{table: t} do
      long = String.duplicate("a", 252) <> "-bb"
      insert!(t, long, "draft", at(300))
      b = insert!(t, long, "draft", at(100))

      dedupe!(t)

      refute slug_of(t, b) =~ "--"
    end

    test "case-different slugs are left alone — they do not collide", %{table: t} do
      a = insert!(t, "Foo", "draft", at(300))
      b = insert!(t, "foo", "draft", at(100))

      dedupe!(t)

      assert slug_of(t, a) == "Foo"
      assert slug_of(t, b) == "foo"
    end

    test "running twice changes nothing the second time", %{table: t} do
      insert!(t, "foo", "draft", at(300))
      insert!(t, "foo", "draft", at(100))

      dedupe!(t)
      %{rows: after_first} = Repo.query!("SELECT uuid, slug FROM #{t} ORDER BY slug")

      dedupe!(t)
      %{rows: after_second} = Repo.query!("SELECT uuid, slug FROM #{t} ORDER BY slug")

      assert after_first == after_second
    end
  end

  describe "the index swap" do
    test "the unique index is created and then rejects a duplicate", %{table: t} do
      insert!(t, "foo", "draft", at(300))
      insert!(t, "foo", "draft", at(100))

      dedupe!(t)
      swap_index!(t)

      %{rows: [[unique?]]} =
        Repo.query!(
          "SELECT indexdef ~ 'UNIQUE' FROM pg_indexes WHERE indexname = $1",
          ["#{t}_slug_index"]
        )

      assert unique?

      assert_raise Postgrex.Error, ~r/duplicate key/, fn ->
        insert!(t, "foo", "draft", at(50))
      end
    end

    test "CREATE UNIQUE ... IF NOT EXISTS alone is a silent no-op", %{table: t} do
      # Matching is by index NAME only. Without the DROP the index stays
      # non-unique and the migration reports success — which is the whole
      # reason the DROP is in the migration.
      Repo.query!("CREATE UNIQUE INDEX IF NOT EXISTS #{t}_slug_index ON #{t} USING btree (slug)")

      %{rows: [[unique?]]} =
        Repo.query!(
          "SELECT indexdef ~ 'UNIQUE' FROM pg_indexes WHERE indexname = $1",
          ["#{t}_slug_index"]
        )

      refute unique?
    end
  end

  describe "the manifest" do
    test "the shape flips to unique at 167, and is unchanged before it" do
      alias PhoenixKit.Migrations.ExpectedSchema
      alias PhoenixKit.Migrations.ExpectedSchema.Object

      object =
        "public"
        |> ExpectedSchema.objects()
        |> Enum.find(&(&1.id == "index:phoenix_kit_posts_slug_index"))

      assert object, "the posts slug index is missing from the manifest"

      # The revision is appended rather than edited: a V166 database must keep
      # reading its plain index as correct, or doctor reports drift with a
      # repair that cannot run.
      refute Object.shape_at(object, 166).unique
      assert Object.shape_at(object, 167).unique
    end
  end
end
