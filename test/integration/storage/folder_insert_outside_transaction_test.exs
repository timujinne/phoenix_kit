defmodule PhoenixKit.Modules.Storage.FolderInsertOutsideTransactionTest do
  @moduledoc """
  `create_folder/3` and `create_folder_link/4` called with no transaction of
  the caller's (Media's "New folder", a module laying out folders): the SQL
  sandbox wraps every test in a transaction and hides that case, so these run
  through `Sandbox.unboxed_run/2` and remove the rows they commit.
  """
  use PhoenixKit.DataCase, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Folder, FolderLink}
  alias PhoenixKit.Users.Auth

  defp unboxed(fun), do: Sandbox.unboxed_run(Repo, fun)

  defp tag, do: "outside-tx-#{System.unique_integer([:positive])}"

  defp file!(tag) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "#{tag}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, file} =
      Storage.create_file(%{
        original_file_name: "#{tag}.txt",
        file_name: "#{tag}.txt",
        mime_type: "text/plain",
        file_type: "document",
        ext: "txt",
        file_checksum: tag,
        user_file_checksum: tag,
        size: 1,
        status: "active",
        user_uuid: user.uuid
      })

    file
  end

  defp cleanup(tag) do
    Repo.delete_all(
      from(l in FolderLink,
        join: f in Folder,
        on: f.uuid == l.folder_uuid,
        where: like(f.name, ^"#{tag}%")
      )
    )

    Repo.delete_all(from(f in Storage.File, where: f.file_checksum == ^tag))
    Repo.delete_all(from(f in Folder, where: like(f.name, ^"#{tag}%")))

    Repo.delete_all(from(u in Auth.User, where: u.email == ^"#{tag}@example.com"))
  end

  test "create_folder works with no transaction, and a taken name is an error value" do
    tag = tag()

    try do
      unboxed(fn ->
        refute Repo.in_transaction?()
        assert {:ok, %Folder{} = parent} = Storage.create_folder(%{name: tag})
        assert {:error, changeset} = Storage.create_folder(%{name: tag})
        assert Keyword.has_key?(changeset.errors, :name)

        assert {:ok, %Folder{}} =
                 Storage.create_folder(%{name: "#{tag}-sub", parent_uuid: parent.uuid})

        assert {:error, _} =
                 Storage.create_folder(%{name: "#{tag}-sub", parent_uuid: parent.uuid})
      end)
    after
      unboxed(fn -> cleanup(tag) end)
    end
  end

  test "create_folder_link works with no transaction, and a link already there is an error value" do
    tag = tag()

    try do
      unboxed(fn ->
        file = file!(tag)
        {:ok, folder} = Storage.create_folder(%{name: tag})

        assert {:ok, %FolderLink{}} = Storage.create_folder_link(folder.uuid, file.uuid)
        assert {:error, %Ecto.Changeset{}} = Storage.create_folder_link(folder.uuid, file.uuid)
      end)
    after
      unboxed(fn -> cleanup(tag) end)
    end
  end

  test "inside a caller's transaction a taken name or link does not poison it" do
    tag = tag()

    try do
      unboxed(fn ->
        file = file!(tag)

        assert {:ok, {1, 1}} =
                 Repo.transaction(fn ->
                   {:ok, folder} = Storage.create_folder(%{name: tag})
                   {:error, _} = Storage.create_folder(%{name: tag})
                   {:ok, _} = Storage.create_folder_link(folder.uuid, file.uuid)
                   {:error, _} = Storage.create_folder_link(folder.uuid, file.uuid)

                   {Repo.aggregate(from(f in Folder, where: f.name == ^tag), :count),
                    Repo.aggregate(
                      from(l in FolderLink, where: l.file_uuid == ^file.uuid),
                      :count
                    )}
                 end)
      end)
    after
      unboxed(fn -> cleanup(tag) end)
    end
  end
end
