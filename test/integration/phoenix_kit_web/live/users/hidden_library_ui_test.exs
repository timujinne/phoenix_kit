defmodule PhoenixKitWeb.Live.Users.HiddenLibraryUITest do
  @moduledoc """
  A hidden system library through the real pages, as a holder of `media` +
  `media.view_all` (who sees every file of the site's libraries): `/admin/media`
  does not offer it in its switcher nor open it by its slug, a file or folder of it
  is not opened by its URL, and the media picker does not list its files.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.Libraries
  alias PhoenixKit.Users.{Auth, Permissions}
  alias PhoenixKit.Utils.Routes

  @media_path Routes.path("/admin/media")

  defmodule PickerHost do
    @moduledoc false
    use Phoenix.LiveView

    def render(assigns) do
      ~H"""
      <.live_component
        module={PhoenixKitWeb.Live.Components.MediaSelectorModal}
        id="picker"
        show={true}
        mode={:single}
        selected_uuids={[]}
        file_type_filter={:all}
        phoenix_kit_current_user={nil}
      />
      """
    end
  end

  setup do
    n = System.unique_integer([:positive])

    {:ok, role} = Roles.create_role(%{name: "Managers #{n}"})

    for key <- ~w(media media.view_all media.manage),
        do: {:ok, _} = Permissions.grant_permission(role.uuid, key)

    {:ok, manager} =
      Auth.register_user(%{
        "email" => "hidden-ui-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, manager} = Auth.admin_confirm_user(manager)
    {:ok, _} = Roles.assign_role(manager, role.name)
    {uploader, _token} = create_admin_user()

    {:ok, hidden} =
      Libraries.create_system_library(%{name: "Assistant #{n}", slug: "assistant-#{n}"},
        hidden: true
      )

    {:ok, folder} =
      Storage.create_folder(%{name: "HIDDEN-FOLDER-#{n}", library_uuid: hidden.uuid})

    {:ok, media_folder} = Storage.create_folder(%{name: "MEDIA-FOLDER-#{n}"})

    %{
      n: n,
      manager: Repo.get!(Auth.User, manager.uuid),
      hidden: hidden,
      folder: folder,
      media_folder: media_folder,
      uploader: uploader,
      hidden_file: file!("HIDDEN-FILE-#{n}", uploader, hidden.uuid, folder),
      media_file: file!("MEDIA-FILE-#{n}", uploader, nil, media_folder)
    }
  end

  defp file!(name, owner, library_uuid, folder) do
    n = System.unique_integer([:positive])

    attrs = %{
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
      user_uuid: owner.uuid,
      folder_uuid: folder.uuid
    }

    attrs = if library_uuid, do: Map.put(attrs, :library_uuid, library_uuid), else: attrs
    {:ok, file} = Storage.create_file(attrs)
    file
  end

  describe "/admin/media" do
    test "with Media and a hidden library the page still says nothing about libraries", %{
      conn: conn,
      manager: manager,
      hidden: hidden,
      folder: folder,
      media_folder: media_folder
    } do
      {:ok, _view, html} = live(log_in_user(conn, manager), @media_path)

      refute html =~ "pk-title-switcher"
      refute html =~ hidden.name
      assert html =~ media_folder.name
      refute html =~ folder.name
    end

    test "next to a second site library, the switcher lists that one and not the hidden one", %{
      conn: conn,
      manager: manager,
      hidden: hidden,
      n: n
    } do
      {:ok, site} = Libraries.create_system_library(%{name: "Brand #{n}"})

      {:ok, view, html} = live(log_in_user(conn, manager), @media_path)

      assert html =~ "pk-title-switcher"
      assert has_element?(view, "#pk-title-switcher-list a", site.name)
      refute has_element?(view, "#pk-title-switcher-list a", hidden.name)
      refute html =~ hidden.name
    end

    test "its slug is not a library the page opens", %{
      conn: conn,
      manager: manager,
      hidden: hidden
    } do
      assert {:error, {kind, %{to: to, flash: flash}}} =
               live(
                 log_in_user(conn, manager),
                 Routes.path("/admin/media/library/#{hidden.slug}")
               )

      assert kind in [:redirect, :live_redirect]
      assert to == @media_path
      assert flash["error"] == "Library not found"
    end

    test "a folder or a file of it is not opened by its URL", %{
      conn: conn,
      manager: manager,
      folder: folder,
      media_folder: media_folder,
      hidden_file: hidden_file,
      media_file: media_file
    } do
      conn = log_in_user(conn, manager)

      # The same addresses open a Media folder and file.
      {:ok, _view, html} = live(conn, @media_path <> "?folder=#{media_folder.uuid}")
      assert html =~ media_file.uuid

      {:ok, _view, html} = live(conn, @media_path <> "?file=#{media_file.uuid}")
      assert html =~ media_file.original_file_name

      {:ok, _view, html} = live(conn, @media_path <> "?folder=#{folder.uuid}")
      refute html =~ folder.name
      refute html =~ hidden_file.uuid

      {:ok, _view, html} = live(conn, @media_path <> "?file=#{hidden_file.uuid}")
      refute html =~ hidden_file.original_file_name
    end

    test "the file's storage page is not found", %{
      conn: conn,
      manager: manager,
      hidden_file: hidden_file,
      media_file: media_file
    } do
      conn = log_in_user(conn, manager)

      {:ok, _view, html} = live(conn, Routes.path("/admin/media/#{media_file.uuid}/storage"))
      assert html =~ media_file.original_file_name

      {:ok, _view, html} = live(conn, Routes.path("/admin/media/#{hidden_file.uuid}/storage"))
      refute html =~ hidden_file.original_file_name
    end

    test "a file of it named in an event is refused, not trashed", %{
      conn: conn,
      manager: manager,
      hidden_file: hidden_file,
      media_file: media_file
    } do
      {:ok, view, _html} = live(log_in_user(conn, manager), @media_path)

      {_html, log} =
        ExUnit.CaptureLog.with_log(fn ->
          view
          |> with_target("#media-browser")
          |> render_hook("trash_file", %{"file_uuid" => hidden_file.uuid})
        end)

      assert log =~ "refused"
      assert Storage.get_file(hidden_file.uuid).status == "active"

      # The same event trashes a Media file.
      view
      |> with_target("#media-browser")
      |> render_hook("trash_file", %{"file_uuid" => media_file.uuid})

      assert Storage.get_file(media_file.uuid).status == "trashed"
    end

    test "its file's old address opens Media, not the hidden library's slug", %{
      conn: conn,
      uploader: uploader,
      hidden: hidden,
      hidden_file: hidden_file
    } do
      assert {:error, {:live_redirect, %{to: to}}} =
               live(log_in_user(conn, uploader), Routes.path("/admin/media/#{hidden_file.uuid}"))

      assert to == @media_path <> "?file=#{hidden_file.uuid}"
      refute to =~ hidden.slug
    end

    test "an Admin's storage page of its file links to no library page", %{
      conn: conn,
      uploader: uploader,
      hidden: hidden,
      hidden_file: hidden_file
    } do
      {:ok, view, _html} =
        live(log_in_user(conn, uploader), Routes.path("/admin/media/#{hidden_file.uuid}/storage"))

      refute has_element?(view, ~s(a[href*="/admin/media/library/#{hidden.slug}"]))
      refute has_element?(view, ~s(a[href*="/admin/settings/media/libraries/#{hidden.uuid}"]))
    end
  end

  describe "Settings → Media → Health" do
    test "does not name a stale file of it", %{
      conn: conn,
      manager: manager,
      hidden: hidden,
      hidden_file: hidden_file
    } do
      Repo.update!(Ecto.Changeset.change(hidden_file, placed_revision: 0))

      {:ok, view, _html} =
        live(log_in_user(conn, manager), Routes.path("/admin/settings/media?tab=health"))

      assert has_element?(view, "#media-health")
      refute has_element?(view, "#media-health a[href*='#{hidden_file.uuid}']")
      refute view |> element("#media-health") |> render() =~ hidden_file.original_file_name
      refute view |> element("#media-health") |> render() =~ hidden.name
    end
  end

  describe "the media picker" do
    test "lists the site's files and not the hidden library's", %{
      conn: conn,
      manager: manager,
      media_file: media_file,
      hidden_file: hidden_file
    } do
      {:ok, view, _html} =
        live(
          log_in_user(conn, manager),
          Routes.path("/admin/media/selector") <> "?return_to=%2Fadmin&filter=all"
        )

      assert has_element?(view, ~s([phx-value-file-uuid="#{media_file.uuid}"]))
      refute has_element?(view, ~s([phx-value-file-uuid="#{hidden_file.uuid}"]))
    end

    test "the picker modal a host embeds does not list them either", %{
      conn: conn,
      media_file: media_file,
      hidden_file: hidden_file
    } do
      {:ok, view, _html} = live_isolated(conn, PickerHost)

      assert has_element?(view, ~s([phx-value-file-uuid="#{media_file.uuid}"]))
      refute has_element?(view, ~s([phx-value-file-uuid="#{hidden_file.uuid}"]))
    end
  end
end
