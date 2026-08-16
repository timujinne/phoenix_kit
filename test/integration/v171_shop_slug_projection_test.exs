defmodule PhoenixKit.Integration.V171ShopSlugProjectionTest do
  @moduledoc """
  V171's projection tables, trigger sync, and dedup.

  The trigger half runs against the REAL shop tables — `ensure_current/2`
  applied V171 to this database, so the projections and triggers exist. The
  dedup half manufactures duplicates a current install can no longer produce,
  on a scratch clone, driving the same parameterized SQL the migration runs
  (`ShopSlugProjection.dedupe_sql/3`).
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.Postgres.ShopSlugProjection

  defp insert_product!(slug_map, status \\ "draft") do
    %{rows: [[uuid]]} =
      Repo.query!(
        """
        INSERT INTO phoenix_kit_shop_products (uuid, title, slug, status, price, inserted_at, updated_at)
        VALUES (gen_random_uuid(), '{"en":"t"}', $1, $2, 100, now(), now())
        RETURNING uuid
        """,
        [slug_map, status]
      )

    uuid
  end

  defp projection(uuid) do
    %{rows: rows} =
      Repo.query!(
        "SELECT lang, value FROM phoenix_kit_shop_product_slugs WHERE product_uuid = $1 ORDER BY lang, value",
        [uuid]
      )

    rows
  end

  describe "the trigger" do
    test "projects each language, folding spellings to their base" do
      uuid = insert_product!(%{"en-US" => "hat", "de" => "hut"})

      assert projection(uuid) == [["de", "hut"], ["en", "hat"]]
    end

    test "never projects an empty value" do
      uuid = insert_product!(%{"en" => "cap", "ja" => ""})

      assert projection(uuid) == [["en", "cap"]]
    end

    test "an update rewrites the projection rather than accreting" do
      uuid = insert_product!(%{"en" => "old-slug"})

      Repo.query!(
        ~s(UPDATE phoenix_kit_shop_products SET slug = '{"en":"new-slug"}' WHERE uuid = $1),
        [uuid]
      )

      assert projection(uuid) == [["en", "new-slug"]]
    end

    test "deleting the product cascades its projection away" do
      uuid = insert_product!(%{"en" => "doomed"})
      Repo.query!("DELETE FROM phoenix_kit_shop_products WHERE uuid = $1", [uuid])

      assert projection(uuid) == []
    end
  end

  describe "the corrected uniqueness bucket" do
    test "the same value under two different languages is allowed" do
      # The old expression index REJECTED this pair — over-enforcement, since
      # a URL request always carries a language.
      insert_product!(%{"en" => "hat"})
      insert_product!(%{"de" => "hat"})
    end

    test "the same value under two spellings of one language collides" do
      insert_product!(%{"en" => "hat"})

      assert_raise Postgrex.Error, ~r/phoenix_kit_shop_product_slugs_pkey/, fn ->
        insert_product!(%{"en-US" => "hat"})
      end
    end

    test "a non-primary language is now enforced too" do
      # The old index constrained only the alphabetically-first key, so this
      # pair coexisted and the collision surfaced later, on an unrelated save.
      insert_product!(%{"en" => "hat"})

      assert_raise Postgrex.Error, ~r/phoenix_kit_shop_product_slugs_pkey/, fn ->
        insert_product!(%{"de" => "hut2", "en" => "hat"})
      end
    end
  end

  describe "the dedup" do
    setup do
      table = "phoenix_kit_zz_v171_#{System.unique_integer([:positive])}"
      on_exit(fn -> Repo.query("DROP TABLE IF EXISTS #{table}", []) end)

      Repo.query!("""
      CREATE TABLE #{table} (
        uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        slug jsonb NOT NULL DEFAULT '{}',
        status character varying(50) NOT NULL DEFAULT 'draft',
        inserted_at timestamp(0) without time zone NOT NULL DEFAULT now()
      )
      """)

      {:ok, table: table}
    end

    defp row!(table, slug_map, status, seconds_ago) do
      %{rows: [[uuid]]} =
        Repo.query!(
          """
          INSERT INTO #{table} (slug, status, inserted_at)
          VALUES ($1, $2, now() - ($3 || ' seconds')::interval) RETURNING uuid
          """,
          [slug_map, status, to_string(seconds_ago)]
        )

      uuid
    end

    defp slug_of(table, uuid) do
      %{rows: [[m]]} = Repo.query!("SELECT slug FROM #{table} WHERE uuid = $1", [uuid])
      m
    end

    defp dedupe!(table) do
      Repo.query!(ShopSlugProjection.dedupe_sql(table, "('active')", "public."))
    end

    test "live beats older draft; the rest suffix past taken values", %{table: t} do
      draft = row!(t, %{"en" => "hat"}, "draft", 300)
      live = row!(t, %{"en" => "hat"}, "active", 100)
      unrelated = row!(t, %{"en" => "hat-2"}, "draft", 200)

      dedupe!(t)

      assert slug_of(t, live) == %{"en" => "hat"}
      # "hat-2" was taken by an unrelated row, so the loser lands on "hat-3".
      assert slug_of(t, draft) == %{"en" => "hat-3"}
      assert slug_of(t, unrelated) == %{"en" => "hat-2"}
    end

    test "two live rows in one bucket raise, and nothing is rewritten", %{table: t} do
      a = row!(t, %{"en" => "hat"}, "active", 300)
      b = row!(t, %{"en-US" => "hat"}, "active", 100)

      assert_raise Postgrex.Error, ~r/shared by 2 live rows/, fn -> dedupe!(t) end

      assert slug_of(t, a) == %{"en" => "hat"}
      assert slug_of(t, b) == %{"en-US" => "hat"}
    end

    test "one row carrying two spellings of a language is left alone", %{table: t} do
      # The trigger folds both spellings into the single bucket (en, hat) with
      # SELECT DISTINCT, so there is no constraint to satisfy — rewriting one
      # of them would invent a second URL for a row that has one.
      row = row!(t, %{"en" => "hat", "en-GB" => "hat"}, "draft", 100)

      dedupe!(t)

      assert slug_of(t, row) == %{"en" => "hat", "en-GB" => "hat"}
    end

    test "an ACTIVE row's own spellings never read as two live rows", %{table: t} do
      # Counting entries rather than owners aborted the whole upgrade here.
      row = row!(t, %{"en" => "hat", "en-US" => "hat"}, "active", 100)

      dedupe!(t)

      assert slug_of(t, row) == %{"en" => "hat", "en-US" => "hat"}
    end

    test "a losing row's spellings move together to one candidate", %{table: t} do
      keeper = row!(t, %{"en" => "hat"}, "active", 300)
      loser = row!(t, %{"en" => "hat", "en-GB" => "hat"}, "draft", 100)

      dedupe!(t)

      assert slug_of(t, keeper) == %{"en" => "hat"}
      assert slug_of(t, loser) == %{"en" => "hat-2", "en-GB" => "hat-2"}
    end

    test "different languages sharing a value are left alone", %{table: t} do
      a = row!(t, %{"en" => "hat"}, "draft", 300)
      b = row!(t, %{"de" => "hat"}, "draft", 100)

      dedupe!(t)

      assert slug_of(t, a) == %{"en" => "hat"}
      assert slug_of(t, b) == %{"de" => "hat"}
    end

    test "running twice changes nothing the second time", %{table: t} do
      row!(t, %{"en" => "hat"}, "draft", 300)
      row!(t, %{"en" => "hat"}, "draft", 100)

      dedupe!(t)
      %{rows: first} = Repo.query!("SELECT uuid, slug FROM #{t} ORDER BY uuid")

      dedupe!(t)
      %{rows: second} = Repo.query!("SELECT uuid, slug FROM #{t} ORDER BY uuid")

      assert first == second
    end
  end

  describe "the manifest" do
    test "old indexes are legacy_optional; projection objects are required at 171" do
      alias PhoenixKit.Migrations.ExpectedSchema

      objects = ExpectedSchema.objects("public")
      by_id = Map.new(objects, &{&1.id, &1})

      assert by_id["index:idx_shop_products_slug_primary"].presence == :legacy_optional
      assert by_id["index:idx_shop_categories_slug_primary"].presence == :legacy_optional
      assert by_id["table:phoenix_kit_shop_product_slugs"].since == 171
      assert by_id["index:phoenix_kit_shop_category_slugs_pkey"].since == 171
    end
  end
end
