defmodule PhoenixKit.Modules.Storage.SortByCaptureDateTest do
  @moduledoc """
  The media browser's "Date taken" sorts: the order the photo timeline shows
  (by `taken_at`), not upload order. A file with no capture date goes last
  whichever way round.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query, only: [from: 2]

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  # `inserted_at` is set by hand, a second apart in the order the files are made:
  # the column has second precision, and four inserts in one second would tie.
  defp file!(name, owner, taken_at, uploaded_at) do
    n = System.unique_integer([:positive])

    {:ok, file} =
      Storage.create_file(%{
        original_file_name: name,
        file_name: "f-#{n}.png",
        file_path: "x/#{n}.png",
        mime_type: "image/png",
        file_type: "image",
        ext: "png",
        file_checksum: Ecto.UUID.generate(),
        user_file_checksum: Ecto.UUID.generate(),
        size: 1,
        status: "active",
        user_uuid: owner.uuid
      })

    Repo.update_all(from(f in StorageFile, where: f.uuid == ^file.uuid),
      set: [taken_at: taken_at, inserted_at: uploaded_at]
    )

    file
  end

  defp names(sort) do
    {files, _total} = Storage.list_files_in_scope(nil, sort: sort, per_page: 50)
    Enum.map(files, & &1.original_file_name)
  end

  setup do
    {:ok, owner} =
      Auth.register_user(%{
        "email" => "taken-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    # Uploaded in an order unlike the order they were taken in.
    file!("taken-2020", owner, ~U[2020-05-01 10:00:00Z], ~U[2026-10-26 12:00:00Z])
    file!("undated", owner, nil, ~U[2026-10-26 12:00:01Z])
    file!("taken-2018", owner, ~U[2018-07-14 08:00:00Z], ~U[2026-10-26 12:00:02Z])
    file!("taken-2024", owner, ~U[2024-01-02 09:00:00Z], ~U[2026-10-26 12:00:03Z])
    :ok
  end

  test "oldest first follows the date taken, undated last" do
    assert names("taken_oldest") == ["taken-2018", "taken-2020", "taken-2024", "undated"]
  end

  test "newest first follows the date taken, undated still last" do
    assert names("taken_newest") == ["taken-2024", "taken-2020", "taken-2018", "undated"]
  end

  test "the upload-time sorts are unchanged" do
    assert names("oldest") == ["taken-2020", "undated", "taken-2018", "taken-2024"]
  end
end
