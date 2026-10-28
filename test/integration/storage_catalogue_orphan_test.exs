defmodule PhoenixKit.Integration.StorageCatalogueOrphanTest do
  @moduledoc """
  The orphan-file check must see catalogue references.

  The catalogue module (`phoenix_kit_catalogue`) stores its image references
  inside the JSONB `data` column of `phoenix_kit_cat_items`,
  `phoenix_kit_cat_categories`, and `phoenix_kit_cat_catalogues` rather than
  dedicated FK columns, so a plain join misses them — without the
  JSONB-aware checks added alongside this test, a live catalogue item,
  category, or catalogue-record image would be classified as an orphan and
  queued for deletion by `DeleteOrphanedFileJob`.

  `phoenix_kit_cat_pdfs` references its source file through a plain
  `file_uuid` FK with `ON DELETE RESTRICT` instead — the same shape as
  `phoenix_kit_post_media`. Missing that check would let
  `DeleteOrphanedFileJob` delete the physical file data for a PDF still in
  use, then crash on the FK-RESTRICT violation while deleting the
  `phoenix_kit_files` row, leaving a dangling record and a broken PDF.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.Fixtures

  alias PhoenixKit.Test.ModuleFixtureTables

  alias PhoenixKit.Modules.Storage

  setup do
    ModuleFixtureTables.create!([
      :cat_catalogues,
      :cat_categories,
      :cat_items,
      :cat_pdfs,
      :post_media
    ])
  end

  defp make_file(owner_uuid) do
    checksum = "cs_#{System.unique_integer([:positive])}"

    {:ok, file} =
      Storage.create_file(%{
        original_file_name: "photo.jpg",
        file_name: "photo.jpg",
        mime_type: "image/jpeg",
        file_type: "image",
        ext: "jpg",
        file_checksum: checksum,
        user_file_checksum: "u_#{checksum}",
        size: 1234,
        status: "active",
        user_uuid: owner_uuid
      })

    file
  end

  defp insert_catalogue!(data \\ %{}) do
    %{rows: [[uuid]]} =
      Repo.query!(
        """
        INSERT INTO phoenix_kit_cat_catalogues (uuid, name, data, inserted_at, updated_at)
        VALUES (gen_random_uuid(), 'Test catalogue', $1, now(), now())
        RETURNING uuid
        """,
        [data]
      )

    uuid
  end

  defp insert_category!(catalogue_uuid, data) do
    %{rows: [[uuid]]} =
      Repo.query!(
        """
        INSERT INTO phoenix_kit_cat_categories (uuid, name, catalogue_uuid, data, inserted_at, updated_at)
        VALUES (gen_random_uuid(), 'Test category', $1, $2, now(), now())
        RETURNING uuid
        """,
        [catalogue_uuid, data]
      )

    uuid
  end

  defp insert_item!(data) do
    %{rows: [[uuid]]} =
      Repo.query!(
        """
        INSERT INTO phoenix_kit_cat_items (uuid, name, data, inserted_at, updated_at)
        VALUES (gen_random_uuid(), 'Test item', $1, now(), now())
        RETURNING uuid
        """,
        [data]
      )

    uuid
  end

  defp insert_pdf!(file_uuid) do
    Repo.query!(
      """
      INSERT INTO phoenix_kit_cat_pdfs (uuid, file_uuid, original_filename, inserted_at, updated_at)
      VALUES (gen_random_uuid(), $1, 'test.pdf', now(), now())
      """,
      [Ecto.UUID.dump!(file_uuid)]
    )

    :ok
  end

  setup do
    user = confirmed_user_fixture()
    %{user: user}
  end

  describe "phoenix_kit_cat_items" do
    test "featured_image_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_item!(%{"featured_image_uuid" => file.uuid})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "media_order keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_item!(%{"media_order" => [file.uuid, Ecto.UUID.generate()]})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "ecommerce.file_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_item!(%{"ecommerce" => %{"file_uuid" => file.uuid}})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "an item referencing a different file does not protect this one", %{user: user} do
      file = make_file(user.uuid)
      insert_item!(%{"featured_image_uuid" => Ecto.UUID.generate()})

      assert Storage.file_orphaned?(file.uuid)
    end
  end

  describe "phoenix_kit_cat_categories" do
    test "featured_image_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!()
      insert_category!(catalogue_uuid, %{"featured_image_uuid" => file.uuid})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "media_order keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!()
      insert_category!(catalogue_uuid, %{"media_order" => [file.uuid, Ecto.UUID.generate()]})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "ecommerce.image_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!()
      insert_category!(catalogue_uuid, %{"ecommerce" => %{"image_uuid" => file.uuid}})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "a category referencing a different file does not protect this one", %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!()
      insert_category!(catalogue_uuid, %{"ecommerce" => %{"image_uuid" => Ecto.UUID.generate()}})

      assert Storage.file_orphaned?(file.uuid)
    end
  end

  describe "phoenix_kit_cat_catalogues" do
    test "featured_image_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_catalogue!(%{"featured_image_uuid" => file.uuid})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "media_order keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_catalogue!(%{"media_order" => [file.uuid, Ecto.UUID.generate()]})

      refute Storage.file_orphaned?(file.uuid)
    end

    test "a catalogue referencing a different file does not protect this one", %{user: user} do
      file = make_file(user.uuid)
      insert_catalogue!(%{"featured_image_uuid" => Ecto.UUID.generate()})

      assert Storage.file_orphaned?(file.uuid)
    end
  end

  # The media_order checks read each row's list once and hash-join the file
  # uuids against it, instead of testing every file against every row with
  # `@>` (8 s for 3k files x 700 items on a live shop). Expanding the list
  # must not trip over a value that is not an array, nor over elements that
  # are not strings — the old `@>` form simply didn't match those.
  describe "media_order of any shape" do
    test "a media_order that is not an array neither breaks the check nor protects",
         %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!(%{"media_order" => file.uuid})
      insert_category!(catalogue_uuid, %{"media_order" => %{"0" => file.uuid}})
      insert_item!(%{"media_order" => file.uuid})
      insert_item!(%{"media_order" => nil})

      assert Storage.file_orphaned?(file.uuid)
      assert file.uuid in Enum.map(Storage.find_orphaned_files(), & &1.uuid)
    end

    test "only a top-level string element protects a file", %{user: user} do
      file = make_file(user.uuid)
      catalogue_uuid = insert_catalogue!(%{"media_order" => [nil, 7, [file.uuid]]})
      insert_category!(catalogue_uuid, %{"media_order" => [%{"uuid" => file.uuid}]})
      insert_item!(%{"media_order" => [nil, 42, %{"uuid" => file.uuid}, [file.uuid]]})

      assert Storage.file_orphaned?(file.uuid)

      insert_item!(%{"media_order" => [nil, 42, file.uuid]})

      refute Storage.file_orphaned?(file.uuid)
    end
  end

  describe "phoenix_kit_cat_pdfs" do
    test "file_uuid keeps a file from being orphaned", %{user: user} do
      file = make_file(user.uuid)
      insert_pdf!(file.uuid)

      refute Storage.file_orphaned?(file.uuid)
    end

    test "a pdf referencing a different file does not protect this one", %{user: user} do
      file = make_file(user.uuid)
      other_file = make_file(user.uuid)
      insert_pdf!(other_file.uuid)

      assert Storage.file_orphaned?(file.uuid)
    end
  end
end
