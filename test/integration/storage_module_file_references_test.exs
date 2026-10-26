defmodule PhoenixKit.Integration.StorageModuleFileReferencesTest do
  @moduledoc """
  A module supplies the file references of its own tables
  (`PhoenixKit.Module.file_references/0`), and core's built-in copy of those
  checks steps aside only for the module that owns the table.

  The property that matters: a used file is never read as an orphan. A module
  that supplies its list takes over its own tables; a module that does not, or
  whose list is broken, leaves the file protected.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query, only: [dynamic: 2]
  import PhoenixKit.Test.Fixtures

  alias PhoenixKit.Migrations.ModuleOwnedTables
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Modules.Storage

  @post_media "phoenix_kit_post_media"

  defp make_file do
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
        user_uuid: user_fixture().uuid
      })

    file
  end

  # The simplest table core guards: `phoenix_kit_entity_data`, a LIKE on `data`.
  defp reference_in_entity_data!(file) do
    %{rows: [[entity_uuid]]} =
      Repo.query!(
        """
        INSERT INTO phoenix_kit_entities (name, display_name, created_by_uuid)
        VALUES ('e' || gen_random_uuid()::text, 'E', $1)
        RETURNING uuid
        """,
        [Ecto.UUID.dump!(user_fixture().uuid)]
      )

    Repo.query!(
      """
      INSERT INTO phoenix_kit_entity_data (entity_uuid, title, data)
      VALUES ($1, 't', $2)
      """,
      [entity_uuid, %{"cover" => file.uuid}]
    )
  end

  defp orphan?(file, supplied) do
    Storage.orphaned_files_query(supplied)
    |> Ecto.Query.where([f], f.uuid == ^file.uuid)
    |> Repo.exists?()
  end

  describe "with no module supplying anything" do
    test "core's own check protects a referenced file, as before" do
      file = make_file()
      assert orphan?(file, %{})

      reference_in_entity_data!(file)
      refute orphan?(file, %{})
    end
  end

  describe "a module that supplies its references" do
    test "takes over its own tables: core's copy for them is left out" do
      file = make_file()
      reference_in_entity_data!(file)

      # The entities module supplies an empty list (it claims no table holds a
      # reference): core's copy of `phoenix_kit_entity_data` steps aside, so
      # the file reads as an orphan. This is the hand-over, not a safe default;
      # a module must return every table of its own.
      assert orphan?(file, %{phoenix_kit_entities: {:ok, []}})
    end

    test "its own pairs apply, for a table that exists" do
      file = make_file()

      supplied = %{
        phoenix_kit_entities:
          {:ok,
           [
             {"phoenix_kit_entity_data",
              dynamic(
                [f],
                fragment(
                  "NOT EXISTS (SELECT 1 FROM phoenix_kit_entity_data ed WHERE ed.data::text LIKE '%' || ?::text || '%')",
                  f.uuid
                )
              )}
           ]}
      }

      assert orphan?(file, supplied)
      reference_in_entity_data!(file)
      refute orphan?(file, supplied)
    end

    test "a pair for a table that does not exist is left out" do
      file = make_file()

      supplied = %{
        phoenix_kit_entities:
          {:ok,
           [
             {"phoenix_kit_no_such_table",
              dynamic([f], fragment("false AND ? IS NOT NULL", f.uuid))}
           ]}
      }

      assert orphan?(file, supplied)
    end

    test "a table core never assigned an owner is taken over by the module that names it" do
      file = make_file()
      reference_in_entity_data!(file)

      # `phoenix_kit_entity_data` is entities'. Supplied by an unrelated app,
      # core's entry for it still steps aside because the pair names the table:
      # the supplier's (here: empty-condition) answer is what counts.
      supplied = %{
        phoenix_kit_projects:
          {:ok,
           [{"phoenix_kit_entity_data", dynamic([f], fragment("true AND ? IS NOT NULL", f.uuid))}]}
      }

      assert orphan?(file, supplied)
    end

    test "leaves other modules' tables to core" do
      file = make_file()
      reference_in_entity_data!(file)

      # Posts supplying an empty list does not touch entities' check.
      refute orphan?(file, %{phoenix_kit_posts: {:ok, []}})
    end

    test "an error fails closed: no file reads as orphaned" do
      file = make_file()
      assert orphan?(file, %{})
      refute orphan?(file, %{phoenix_kit_posts: {:error, "boom"}})
    end
  end

  describe "ModuleRegistry.file_reference_pairs/1" do
    defmodule Good do
      def file_references, do: [{"t", :cond}]
    end

    defmodule Raises do
      def file_references, do: raise("nope")
    end

    defmodule NotAList do
      def file_references, do: :nope
    end

    defmodule BadEntry do
      def file_references, do: [{:not_a_binary, :cond}]
    end

    test "accepts a list of {table, condition}" do
      assert {:ok, [{"t", :cond}]} = ModuleRegistry.file_reference_pairs(Good)
    end

    test "turns a raise, a non-list and a malformed entry into errors" do
      assert {:error, msg} = ModuleRegistry.file_reference_pairs(Raises)
      assert msg =~ "raised: nope"
      assert {:error, _} = ModuleRegistry.file_reference_pairs(NotAList)
      assert {:error, _} = ModuleRegistry.file_reference_pairs(BadEntry)
    end
  end

  test "a module without the callback supplies nothing, so core keeps its list" do
    refute function_exported?(PhoenixKit.Modules.Storage, :file_references, 0)
    refute Map.has_key?(ModuleRegistry.all_file_references(), :phoenix_kit)
    assert @post_media in ModuleOwnedTables.module_tables()
  end
end
