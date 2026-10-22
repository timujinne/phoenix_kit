defmodule PhoenixKit.Integration.Storage.FileReferenceSourcesTest do
  @moduledoc """
  `config :phoenix_kit, :file_reference_sources` lets a host app tell orphan
  detection about its own tables.

  Without this hook, every file referenced only through a host-owned table
  (e.g. a host app's `orders.data->>'featured_image_uuid'`, and by extension every
  file sitting in an order/project folder) looks orphaned to
  `Storage.orphaned_files_query/0` — one cleanup run away from data loss.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.Test.Fixtures

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Users.Auth

  defmodule MfaSource do
    @moduledoc false
    import Ecto.Query

    def sources do
      [
        dynamic(
          [f],
          fragment(
            "NOT EXISTS (SELECT 1 FROM phoenix_kit_users u WHERE u.custom_fields->>'test_ref_uuid' = ?::text)",
            f.uuid
          )
        )
      ]
    end
  end

  defmodule BadSource do
    @moduledoc false
    def sources, do: raise("boom")
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

  setup do
    user = confirmed_user_fixture()

    on_exit(fn -> Application.delete_env(:phoenix_kit, :file_reference_sources) end)

    %{user: user}
  end

  describe "{module, function} source" do
    test "a file referenced only through the host source is not orphaned", %{user: user} do
      file = make_file(user.uuid)

      {:ok, _} =
        Auth.update_user_custom_fields(user, %{
          "test_ref_uuid" => file.uuid
        })

      Application.put_env(:phoenix_kit, :file_reference_sources, [{MfaSource, :sources}])

      refute Storage.file_orphaned?(file.uuid)
    end

    test "without the config the same file is orphaned", %{user: user} do
      file = make_file(user.uuid)

      {:ok, _} =
        Auth.update_user_custom_fields(user, %{
          "test_ref_uuid" => file.uuid
        })

      assert Storage.file_orphaned?(file.uuid)
    end

    # Fail closed: skipping a broken source would drop the host's guard and
    # mark every file only the host references as an orphan.
    test "a raising source fails closed: nothing is orphaned", %{user: user} do
      unreferenced = make_file(user.uuid)

      Application.put_env(:phoenix_kit, :file_reference_sources, [{BadSource, :sources}])

      log =
        capture_log(fn ->
          refute Storage.file_orphaned?(unreferenced.uuid)
          assert Storage.find_orphaned_files() == []
          assert Storage.count_orphaned_files() == 0
        end)

      assert log =~ "file_reference_sources"
      assert log =~ "BadSource"
    end
  end

  describe "{table, column} and {table, :jsonb_key, key} shorthands" do
    setup do
      Repo.query!("""
      CREATE TABLE test_host_orders (
        uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        cover_file_uuid uuid,
        data jsonb NOT NULL DEFAULT '{}'::jsonb
      )
      """)

      on_exit(fn ->
        Repo.query("DROP TABLE IF EXISTS test_host_orders")
      end)

      :ok
    end

    test "plain column shorthand protects a referenced file", %{user: user} do
      file = make_file(user.uuid)

      Repo.query!("INSERT INTO test_host_orders (cover_file_uuid) VALUES ($1)", [
        Ecto.UUID.dump!(file.uuid)
      ])

      Application.put_env(:phoenix_kit, :file_reference_sources, [
        {"test_host_orders", "cover_file_uuid"}
      ])

      refute Storage.file_orphaned?(file.uuid)
    end

    test "jsonb_key shorthand protects a referenced file", %{user: user} do
      file = make_file(user.uuid)

      Repo.query!("INSERT INTO test_host_orders (data) VALUES ($1)", [
        %{"featured_image_uuid" => file.uuid}
      ])

      Application.put_env(:phoenix_kit, :file_reference_sources, [
        {"test_host_orders", :jsonb_key, "featured_image_uuid"}
      ])

      refute Storage.file_orphaned?(file.uuid)
    end

    test "a nonexistent table fails closed: nothing is orphaned", %{user: user} do
      file = make_file(user.uuid)

      Application.put_env(:phoenix_kit, :file_reference_sources, [
        {"table_that_does_not_exist", "some_column"}
      ])

      log =
        capture_log(fn ->
          refute Storage.file_orphaned?(file.uuid)
        end)

      assert log =~ "file_reference_sources"
      assert log =~ "table_that_does_not_exist"
    end

    test "a malformed entry fails closed: nothing is orphaned", %{user: user} do
      file = make_file(user.uuid)

      Application.put_env(:phoenix_kit, :file_reference_sources, [:not_a_source])

      log = capture_log(fn -> refute Storage.file_orphaned?(file.uuid) end)

      assert log =~ "invalid entry"
    end
  end
end
