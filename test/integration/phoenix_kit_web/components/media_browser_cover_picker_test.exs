defmodule PhoenixKitWeb.Components.MediaBrowserCoverPickerTest do
  @moduledoc """
  The folder header's cover/logo picker is bound by the same viewer rule as
  the browser around it: a holder of `media` without `media.view_all` is
  shown only their own files in the picker, and a file chosen through
  `media_selected` (which reaches the component by `update/2`, past the
  `handle_event` gates) is taken only when the viewer may see it and it is in
  the library on screen.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Components.MediaBrowser

  @id "media-browser"

  defp user!(permissions) do
    {:ok, role} = Roles.create_role(%{name: "Cover #{System.unique_integer([:positive])}"})
    for key <- permissions, do: {:ok, _} = Permissions.grant_permission(role.uuid, key)

    {:ok, user} =
      Auth.register_user(%{
        email: "cover-#{System.unique_integer([:positive])}@example.com",
        password: "TestPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  defp folder!(owner) do
    {:ok, folder} =
      Storage.create_folder(%{
        name: "cover_#{System.unique_integer([:positive])}",
        user_uuid: owner.uuid
      })

    folder
  end

  defp file!(owner, folder, name) do
    n = System.unique_integer([:positive])

    {:ok, file} =
      Repo.insert(%StorageFile{
        original_file_name: name,
        file_name: name,
        mime_type: "image/jpeg",
        file_type: "image",
        ext: "jpg",
        file_checksum: "sha256:cover-#{n}",
        user_file_checksum: "user-sha256:cover-#{n}",
        size: 1,
        status: "active",
        folder_uuid: folder.uuid,
        user_uuid: owner.uuid
      })

    file
  end

  # Opens the folder, its header editor and the cover picker as `user`.
  defp open_picker(conn, user, folder) do
    {:ok, view, _html} =
      live(log_in_user(conn, user), Routes.path("/admin/media") <> "?folder=#{folder.uuid}")

    browser = with_target(view, "##{@id}")
    render_hook(browser, "start_edit_folder_header", %{"folder-uuid" => folder.uuid})
    html = render_hook(browser, "open_cover_picker", %{})
    {view, html}
  end

  defp pick(view, uuid) do
    Phoenix.LiveView.send_update(view.pid, MediaBrowser, id: @id, media_selected: [uuid])
    # The component's flash goes to the page as a message of its own.
    _ = render(view)
    render(view)
  end

  defp cover(folder), do: Storage.get_folder(folder.uuid).cover_file_uuid

  describe "a viewer restricted to their own files" do
    setup do
      viewer = user!(["media"])
      folder = folder!(viewer)

      %{
        viewer: viewer,
        folder: folder,
        mine: file!(viewer, folder, "mine-#{System.unique_integer([:positive])}.jpg"),
        theirs:
          file!(user!(["media"]), folder, "theirs-#{System.unique_integer([:positive])}.jpg")
      }
    end

    test "the picker lists their file and not someone else's", ctx do
      {_view, html} = open_picker(ctx.conn, ctx.viewer, ctx.folder)

      assert html =~ ctx.mine.original_file_name
      refute html =~ ctx.theirs.original_file_name
      refute html =~ ctx.theirs.uuid
    end

    test "someone else's file is not set as the cover or the logo", ctx do
      {view, _} = open_picker(ctx.conn, ctx.viewer, ctx.folder)

      assert pick(view, ctx.theirs.uuid) =~ "Failed to set the image"
      assert cover(ctx.folder) == nil

      browser = with_target(view, "##{@id}")
      render_hook(browser, "open_logo_picker", %{})
      pick(view, ctx.theirs.uuid)
      assert Storage.get_folder(ctx.folder.uuid).logo_file_uuid == nil
    end

    test "a file of another library is not set, their own file is", ctx do
      {view, _} = open_picker(ctx.conn, ctx.viewer, ctx.folder)

      other = file!(ctx.viewer, ctx.folder, "other-lib.jpg")

      {:ok, library} =
        Storage.Libraries.create_system_library(%{name: "L#{System.unique_integer([:positive])}"})

      Repo.update_all(from_file(other.uuid), set: [library_uuid: library.uuid])

      pick(view, other.uuid)
      assert cover(ctx.folder) == nil

      pick(view, ctx.mine.uuid)
      assert to_string(cover(ctx.folder)) == to_string(ctx.mine.uuid)
    end
  end

  describe "a viewer who sees everything" do
    test "a holder of media.view_all sees and can pick any file of the folder", ctx do
      viewer = user!(["media", "media.view_all"])
      folder = folder!(viewer)
      theirs = file!(user!(["media"]), folder, "all-#{System.unique_integer([:positive])}.jpg")

      {view, html} = open_picker(ctx.conn, viewer, folder)
      assert html =~ theirs.original_file_name

      pick(view, theirs.uuid)
      assert to_string(cover(folder)) == to_string(theirs.uuid)
    end

    test "an Admin sees and can pick any file of the folder", ctx do
      {admin, _token} = create_admin_user()
      folder = folder!(admin)
      theirs = file!(user!(["media"]), folder, "adm-#{System.unique_integer([:positive])}.jpg")

      {view, html} = open_picker(ctx.conn, admin, folder)
      assert html =~ theirs.original_file_name

      pick(view, theirs.uuid)
      assert to_string(cover(folder)) == to_string(theirs.uuid)
    end
  end

  # A browser scoped to `scope`, as a host embeds it; the picker is for `folder`.
  defp open_scoped_picker(conn, user, scope, folder) do
    {:ok, view, _html} =
      live(log_in_user(conn, user), Routes.path("/admin/media") <> "?folder=#{folder.uuid}")

    browser = with_target(view, "##{@id}")
    Phoenix.LiveView.send_update(view.pid, MediaBrowser, id: @id, scope_folder_id: scope.uuid)
    _ = render(view)
    render_hook(browser, "start_edit_folder_header", %{"folder-uuid" => folder.uuid})
    render_hook(browser, "open_cover_picker", %{})
    view
  end

  defp link!(file, folder) do
    {:ok, _} =
      Repo.insert(%Storage.FolderLink{folder_uuid: folder.uuid, file_uuid: file.uuid})
  end

  defp from_file(uuid), do: Ecto.Query.from(f in StorageFile, where: f.uuid == ^uuid)

  describe "a file the picker lists although it lives outside the browser's scope" do
    test "a file linked into the folder is set as the cover (Admin, and a viewer's own)", ctx do
      {admin, _token} = create_admin_user()
      viewer = user!(["media"])

      for user <- [admin, viewer] do
        scope = folder!(user)
        folder = folder!(user)
        {:ok, folder} = Storage.update_folder(folder, %{parent_uuid: scope.uuid})
        elsewhere = folder!(user)
        file = file!(user, elsewhere, "linked-#{System.unique_integer([:positive])}.jpg")
        link!(file, folder)

        view = open_scoped_picker(ctx.conn, user, scope, folder)
        pick(view, file.uuid)

        assert to_string(cover(folder)) == to_string(file.uuid)
      end
    end
  end

  describe "a browser locked to another file type" do
    test "an image is still set as the cover", ctx do
      {admin, _token} = create_admin_user()
      folder = folder!(admin)
      file = file!(admin, folder, "typed-#{System.unique_integer([:positive])}.jpg")

      {view, _} = open_picker(ctx.conn, admin, folder)
      Phoenix.LiveView.send_update(view.pid, MediaBrowser, id: @id, only_file_type: "video")
      _ = render(view)

      pick(view, file.uuid)
      assert to_string(cover(folder)) == to_string(file.uuid)
    end
  end
end
