defmodule PhoenixKitWeb.Live.Users.MediaManagedLibraryTest do
  @moduledoc """
  A hidden library that its module shows in Media and keeps read-only, through
  the real pages: who finds it in the switcher and at
  `/admin/media/library/<slug>` (the table of `media_listing`), that the page
  is read-only for everyone, that events forged from its view and from Media's
  view change nothing, that its file's storage page repairs nothing, and where a
  file of it is browsed from.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Modules.Storage.Libraries
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Components.{MediaBrowser, MediaCanvasViewer}
  alias PhoenixKitWeb.Live.Users.MediaDetail

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

  # Any host may embed the browser on a library, and say nothing about
  # `readonly`.
  defmodule EmbedHost do
    @moduledoc false
    use Phoenix.LiveView
    use PhoenixKitWeb.Components.MediaBrowser.Embed

    def mount(_params, session, socket),
      do: {:ok, Phoenix.Component.assign(socket, :library_uuid, session["library_uuid"])}

    def render(assigns) do
      ~H"""
      <.live_component
        module={PhoenixKitWeb.Components.MediaBrowser}
        id="media-browser"
        library_uuid={@library_uuid}
        admin={true}
        phoenix_kit_current_user={nil}
        parent_uploads={@uploads}
      />
      """
    end
  end

  setup do
    n = System.unique_integer([:positive])

    {:ok, role} = Roles.create_role(%{name: "Media holders #{n}"})
    {:ok, _} = Permissions.grant_permission(role.uuid, "media")

    {:ok, viewer_role} = Roles.create_role(%{name: "Media viewers #{n}"})

    for key <- ~w(media media.view_all),
        do: {:ok, _} = Permissions.grant_permission(viewer_role.uuid, key)

    {admin, _token} = create_admin_user()

    {:ok, library} =
      Libraries.create_system_library(%{name: "Mail files #{n}", slug: "mail-files-#{n}"},
        hidden: true,
        media_listing: :uploaders,
        managed: true
      )

    holder = media_user!("holder", n, role)
    viewer = media_user!("viewer", n, viewer_role)

    {:ok, mine_folder} =
      Storage.create_folder(%{name: "MINE-FOLDER-#{n}", library_uuid: library.uuid}, nil,
        managed: :owner
      )

    {:ok, theirs_folder} =
      Storage.create_folder(%{name: "THEIRS-FOLDER-#{n}", library_uuid: library.uuid}, nil,
        managed: :owner
      )

    {:ok, media_folder} = Storage.create_folder(%{name: "MEDIA-FOLDER-#{n}"})

    %{
      n: n,
      admin: Repo.get!(Auth.User, admin.uuid),
      holder: holder,
      viewer: viewer,
      library: library,
      mine_folder: mine_folder,
      theirs_folder: theirs_folder,
      media_folder: media_folder,
      mine: file!("MINE-FILE-#{n}", holder, library.uuid, mine_folder),
      theirs: file!("THEIRS-FILE-#{n}", admin, library.uuid, theirs_folder),
      media_file: file!("MEDIA-FILE-#{n}", holder, nil, media_folder)
    }
  end

  defp media_user!(tag, n, role) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "managed-ui-#{tag}-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
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

  defp library_path(library), do: Routes.path("/admin/media/library/#{library.slug}")

  defp with_listing(ctx, listing) do
    {:ok, library} = Libraries.update_system_library_listing(ctx.library, media_listing: listing)
    %{ctx | library: library}
  end

  defp scope(user), do: Scope.for_user(Repo.get!(Auth.User, user.uuid))

  defp event(view, name, params) do
    view |> with_target("#media-browser") |> render_hook(name, params)
  end

  describe "who opens it (test 9)" do
    test ":none: no one — the slug is not a library, the switcher does not name it", ctx do
      ctx = with_listing(ctx, :none)

      for user <- [ctx.admin, ctx.holder, ctx.viewer] do
        assert {:error, {_kind, %{to: to, flash: flash}}} =
                 live(log_in_user(ctx.conn, user), library_path(ctx.library))

        assert to == @media_path
        assert flash["error"] == "Library not found"

        {:ok, _view, html} = live(log_in_user(ctx.conn, user), @media_path)
        refute html =~ ctx.library.name
      end
    end

    test ":admins: an Owner/Admin opens it and sees everything; a holder of media does not",
         ctx do
      ctx = with_listing(ctx, :admins)

      {:ok, view, html} = live(log_in_user(ctx.conn, ctx.admin), library_path(ctx.library))
      assert html =~ ctx.mine_folder.name
      assert html =~ ctx.theirs_folder.name
      assert has_element?(view, "#pk-title-switcher-list a", ctx.library.name)

      for user <- [ctx.holder, ctx.viewer] do
        assert {:error, {_kind, %{flash: %{"error" => "Library not found"}}}} =
                 live(log_in_user(ctx.conn, user), library_path(ctx.library))

        {:ok, _view, html} = live(log_in_user(ctx.conn, user), @media_path)
        refute html =~ ctx.library.name
      end
    end

    test ":uploaders: an Admin sees everything, a holder of media only what he sent", ctx do
      ctx = with_listing(ctx, :uploaders)

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.admin), library_path(ctx.library))
      assert html =~ ctx.mine_folder.name
      assert html =~ ctx.theirs_folder.name

      {:ok, view, html} = live(log_in_user(ctx.conn, ctx.holder), library_path(ctx.library))
      assert has_element?(view, "#pk-title-switcher-list a", ctx.library.name)
      assert html =~ ctx.mine_folder.name
      refute html =~ ctx.theirs_folder.name

      {:ok, _view, html} =
        live(
          log_in_user(ctx.conn, ctx.holder),
          library_path(ctx.library) <> "?folder=#{ctx.mine_folder.uuid}"
        )

      assert html =~ ctx.mine.uuid

      {:ok, _view, html} =
        live(
          log_in_user(ctx.conn, ctx.holder),
          library_path(ctx.library) <> "?folder=#{ctx.theirs_folder.uuid}"
        )

      refute html =~ ctx.theirs.uuid
    end

    test ":uploaders: media.view_all does not widen a holder's view of it", ctx do
      ctx = with_listing(ctx, :uploaders)

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.viewer), library_path(ctx.library))
      refute html =~ ctx.mine_folder.name
      refute html =~ ctx.theirs_folder.name
    end

    test ":own_only: an Admin sees only his own too", ctx do
      ctx = with_listing(ctx, :own_only)

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.admin), library_path(ctx.library))
      assert html =~ ctx.theirs_folder.name
      refute html =~ ctx.mine_folder.name

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.holder), library_path(ctx.library))
      assert html =~ ctx.mine_folder.name
      refute html =~ ctx.theirs_folder.name
    end

    test "a user without media never opens it, whatever the listing", ctx do
      {:ok, nobody} =
        Auth.register_user(%{
          "email" => "managed-ui-nobody-#{ctx.n}@example.com",
          "password" => "ValidPassword123!"
        })

      {:ok, nobody} = Auth.admin_confirm_user(nobody)

      assert {:error, _} = live(log_in_user(ctx.conn, nobody), library_path(ctx.library))
    end
  end

  describe "the page is read-only" do
    test "it wears the badge and offers no write control, for an Admin too", ctx do
      {:ok, view, html} = live(log_in_user(ctx.conn, ctx.admin), library_path(ctx.library))

      assert html =~ "Read only"
      assert html =~ "cannot be changed here"
      assert has_element?(view, "#media-browser")

      for write <- ~w(toggle_upload open_new_folder_modal toggle_select_mode trash_file) do
        refute html =~ ~s(phx-click="#{write}")
      end
    end

    test "Media itself and a site library are not read-only", ctx do
      {:ok, site} = Libraries.create_system_library(%{name: "Brand #{ctx.n}"})

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.admin), @media_path)
      refute html =~ "cannot be changed here"
      assert html =~ ~s(phx-click="toggle_select_mode")

      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.admin), library_path(site))
      refute html =~ "cannot be changed here"
    end

    test "events forged from its own view change nothing", ctx do
      {:ok, view, _html} =
        live(
          log_in_user(ctx.conn, ctx.admin),
          library_path(ctx.library) <> "?folder=#{ctx.mine_folder.uuid}"
        )

      forged = [
        {"trash_folder", %{"folder_uuid" => ctx.mine_folder.uuid}},
        {"delete_folder", %{"id" => ctx.mine_folder.uuid}},
        {"restore_folder", %{"folder-uuid" => ctx.mine_folder.uuid}},
        {"rename_folder", %{"folder_uuid" => ctx.mine_folder.uuid, "name" => "Stolen"}},
        {"move_folder_to_folder",
         %{"folder_uuid" => ctx.mine_folder.uuid, "target_uuid" => ctx.theirs_folder.uuid}},
        {"submit_new_folder", %{"name" => "Forged"}},
        {"trash_file", %{"file_uuid" => ctx.mine.uuid}},
        {"delete_file", %{"file-uuid" => ctx.mine.uuid}},
        {"move_file_to_folder",
         %{"file_uuid" => ctx.mine.uuid, "folder_uuid" => ctx.theirs_folder.uuid}},
        {"rotate_file", %{"file-uuid" => ctx.mine.uuid, "dir" => "left"}},
        {"set_featured", %{"file-uuid" => ctx.mine.uuid}},
        {"toggle_select", %{"file-uuid" => ctx.mine.uuid}},
        {"open_image_editor", %{"file-uuid" => ctx.mine.uuid}}
      ]

      log =
        capture_log(fn ->
          for {name, params} <- forged, do: event(view, name, params)
          event(view, "delete_selected", %{})
          event(view, "move_selected_to_folder", %{"folder-uuid" => ctx.theirs_folder.uuid})
        end)

      assert log =~ "blocked — component is readonly"
      assert_untouched(ctx)
    end

    test "events forged from Media's view name a file or folder outside the library", ctx do
      {:ok, view, _html} = live(log_in_user(ctx.conn, ctx.admin), @media_path)

      forged = [
        {"trash_folder", %{"folder_uuid" => ctx.mine_folder.uuid}},
        {"delete_folder", %{"id" => ctx.mine_folder.uuid}},
        {"rename_folder", %{"folder_uuid" => ctx.mine_folder.uuid, "name" => "Stolen"}},
        {"move_folder_to_folder",
         %{"folder_uuid" => ctx.mine_folder.uuid, "target_uuid" => ctx.media_folder.uuid}},
        {"move_folder_to_folder",
         %{"folder_uuid" => ctx.media_folder.uuid, "target_uuid" => ctx.mine_folder.uuid}},
        {"trash_file", %{"file_uuid" => ctx.mine.uuid}},
        {"delete_file", %{"file-uuid" => ctx.mine.uuid}},
        {"move_file_to_folder",
         %{"file_uuid" => ctx.mine.uuid, "folder_uuid" => ctx.media_folder.uuid}},
        {"rotate_file", %{"file-uuid" => ctx.mine.uuid, "dir" => "right"}},
        {"set_featured", %{"file-uuid" => ctx.mine.uuid}},
        {"toggle_select", %{"file-uuid" => ctx.mine.uuid}},
        {"open_image_editor", %{"file-uuid" => ctx.mine.uuid}}
      ]

      log =
        capture_log(fn ->
          for {name, params} <- forged, do: event(view, name, params)
        end)

      assert log =~ "refused"
      assert_untouched(ctx)
    end

    test "a host that embeds the browser on it without readonly gets a read-only one", ctx do
      {:ok, view, html} =
        live_isolated(ctx.conn, EmbedHost, session: %{"library_uuid" => ctx.library.uuid})

      refute html =~ ~s(phx-click="open_new_folder_modal")

      log =
        capture_log(fn ->
          event(view, "trash_folder", %{"folder_uuid" => ctx.mine_folder.uuid})
          event(view, "trash_file", %{"file_uuid" => ctx.mine.uuid})
        end)

      assert log =~ "blocked — component is readonly"
      assert_untouched(ctx)

      # The same host on Media is not read-only.
      {:ok, _view, html} =
        live_isolated(ctx.conn, EmbedHost, session: %{"library_uuid" => Libraries.media_uuid()})

      assert html =~ ~s(phx-click="open_new_folder_modal")
    end

    test "the same events from a view that names no library hit the context's refusal", ctx do
      # A browser embedded with no library, as a host may: nothing above the
      # context stops these events, and each one must come back as a value.
      socket = fn ->
        %Phoenix.LiveView.Socket{
          assigns: %{
            __changed__: %{},
            id: "mb",
            flash: %{},
            readonly: false,
            library_uuid: nil,
            viewer_uuid: nil,
            own_files_only: nil,
            scope_folder_id: nil,
            current_folder: nil,
            expanded_stacks: [],
            filter_trash: false,
            filter_orphaned: false,
            file_view: "folders",
            current_page: 1,
            per_page: 50,
            search_query: "",
            sort_by: "newest",
            only_file_type: nil,
            uploaded_files: [],
            folders: [],
            stacks: [],
            expanded_stack: nil,
            total_count: 0,
            selected_files: MapSet.new(),
            selected_folders: MapSet.new()
          }
        }
      end

      capture_log(fn ->
        for {name, params} <- [
              {"trash_folder", %{"folder_uuid" => ctx.mine_folder.uuid}},
              {"delete_folder", %{"id" => ctx.mine_folder.uuid}},
              {"rename_folder", %{"folder_uuid" => ctx.mine_folder.uuid, "name" => "Stolen"}},
              {"move_folder_to_folder",
               %{"folder_uuid" => ctx.mine_folder.uuid, "target_uuid" => ctx.media_folder.uuid}},
              {"trash_file", %{"file_uuid" => ctx.mine.uuid}},
              {"delete_file", %{"file-uuid" => ctx.mine.uuid}},
              {"move_file_to_folder",
               %{"file_uuid" => ctx.mine.uuid, "folder_uuid" => ctx.media_folder.uuid}},
              {"rotate_file", %{"file-uuid" => ctx.mine.uuid, "dir" => "left"}}
            ] do
          assert {:noreply, %Phoenix.LiveView.Socket{}} =
                   MediaBrowser.handle_event(name, params, socket.())
        end
      end)

      assert_untouched(ctx)
    end

    test "the viewer's forged events (details, EXIF, shapes) change nothing", ctx do
      uuid = ctx.mine.uuid

      socket = %Phoenix.LiveView.Socket{
        assigns: %{
          __changed__: %{},
          id: "viewer",
          file: %{file_uuid: uuid},
          board: nil,
          can_annotate: true,
          details_path: "/admin/media/#{uuid}",
          edit_target: nil,
          write_scope: nil,
          own_files_only: nil,
          write_library_uuid: nil,
          viewer_uuid: nil,
          media_meta_lang: "en",
          media_meta_langs: [],
          media_meta_values: nil,
          viewer_annotations: []
        }
      }

      {:noreply, saved} =
        MediaCanvasViewer.handle_event(
          "save_media_details",
          %{"details" => %{"en" => %{"title" => "Forged title", "alt" => "x"}}},
          socket
        )

      assert saved.assigns.media_meta_status == :error
      refute inspect(Storage.get_file(uuid).metadata) =~ "Forged title"

      {:noreply, exif} = MediaCanvasViewer.handle_event("read_exif", %{}, socket)
      assert exif.assigns.exif_status == :error

      shape = %{"uuid" => Ecto.UUID.generate(), "kind" => "rectangle", "geometry" => %{}}

      assert {:noreply, _} =
               MediaCanvasViewer.handle_event(
                 "etcher:annotations-changed",
                 %{"annotations" => [shape]},
                 socket
               )

      assert PhoenixKit.Annotations.list_for_file(uuid) == []
    end

    defp assert_untouched(ctx) do
      assert %{trashed_at: nil, name: name} = Storage.get_folder(ctx.mine_folder.uuid)
      assert name == ctx.mine_folder.name
      assert Storage.get_folder(ctx.theirs_folder.uuid).trashed_at == nil
      assert Storage.get_folder(ctx.media_folder.uuid).parent_uuid == nil
      refute Repo.get_by(Storage.Folder, name: "Forged")

      mine = Storage.get_file(ctx.mine.uuid)
      assert mine.status == "active"
      assert mine.folder_uuid == ctx.mine_folder.uuid
      assert mine.metadata |> Kernel.||(%{}) |> Map.has_key?("rotation") == false
      assert Storage.get_file(ctx.theirs.uuid).status == "active"
      assert Storage.get_file(ctx.media_file.uuid).folder_uuid == ctx.media_folder.uuid
    end
  end

  describe "a file of it" do
    defp image!(user, library_uuid) do
      n = System.unique_integer([:positive])

      file =
        Repo.insert!(%StorageFile{
          original_file_name: "IMG_#{n}.jpeg",
          file_name: "IMG_#{n}.jpeg",
          mime_type: "image/jpeg",
          file_type: "image",
          ext: "jpeg",
          file_checksum: "sha256:managed-#{n}",
          user_file_checksum: "user-sha256:managed-#{n}",
          size: 2048,
          width: 800,
          height: 600,
          status: "active",
          user_uuid: user.uuid,
          library_uuid: library_uuid || Libraries.media_uuid()
        })

      Repo.insert!(%Storage.FileInstance{
        file_uuid: file.uuid,
        variant_name: "original",
        file_name: "IMG_#{n}.jpeg",
        mime_type: "image/jpeg",
        ext: "jpeg",
        checksum: "sha256:managed-#{n}",
        size: 2048,
        width: 800,
        height: 600,
        processing_status: "completed"
      })

      file
    end

    test "the storage page repairs and regenerates nothing for it", ctx do
      file = image!(ctx.admin, ctx.library.uuid)
      media = image!(ctx.admin, nil)
      path = fn f -> Routes.path("/admin/media/#{f.uuid}/storage") end

      {:ok, view, _html} = live(log_in_user(ctx.conn, ctx.admin), path.(file))

      for event <- ~w(verify fix regenerate_all revert retry_edit delete_unedited) do
        html = render_hook(view, event, %{})
        assert html =~ "You may not change storage."
      end

      assert render_hook(view, "make", %{"name" => "thumbnail"}) =~ "You may not change storage."
      assert Enum.map(Storage.list_file_instances(file.uuid), & &1.variant_name) == ["original"]

      # The same events on a file of Media are allowed to start.
      {:ok, view, _html} = live(log_in_user(ctx.conn, ctx.admin), path.(media))
      refute render_hook(view, "verify", %{}) =~ "You may not change storage."
    end

    test "browse_path and trail lead to the page that shows it, if it is shown to the viewer",
         ctx do
      file = Storage.get_file(ctx.mine.uuid)
      admin = scope(ctx.admin)
      holder = scope(ctx.holder)

      for viewer <- [admin, holder] do
        assert MediaDetail.browse_path(file, viewer) == "/admin/media/library/#{ctx.library.slug}"

        assert {_section, "/admin/media", [%{label: label, path: path}]} =
                 MediaDetail.trail(file, viewer)

        assert label == ctx.library.name
        assert path == Routes.path("/admin/media/library/#{ctx.library.slug}")
      end

      assert MediaDetail.view_path(file, admin) ==
               Routes.path("/admin/media/library/#{ctx.library.slug}") <>
                 "?file=#{file.uuid}"
    end

    test "…and to Media when it is not shown to that viewer", ctx do
      file = Storage.get_file(ctx.mine.uuid)

      admins_only = with_listing(ctx, :admins)
      assert MediaDetail.browse_path(file, scope(admins_only.holder)) == "/admin/media"
      assert {_, "/admin/media", []} = MediaDetail.trail(file, scope(admins_only.holder))

      none = with_listing(ctx, :none)
      assert MediaDetail.browse_path(file, scope(none.admin)) == "/admin/media"
      assert {_, "/admin/media", []} = MediaDetail.trail(file, scope(none.admin))
    end

    test "its old address opens the page that shows it", ctx do
      assert {:error, {:live_redirect, %{to: to}}} =
               live(
                 log_in_user(ctx.conn, ctx.holder),
                 Routes.path("/admin/media/#{ctx.mine.uuid}")
               )

      assert to == library_path(ctx.library) <> "?file=#{ctx.mine.uuid}"
    end

    test "Media's nameless listings and the media picker leave it out", ctx do
      {:ok, _view, html} = live(log_in_user(ctx.conn, ctx.admin), @media_path)
      refute html =~ ctx.mine.uuid

      {:ok, _view, html} =
        live(log_in_user(ctx.conn, ctx.admin), @media_path <> "?folder=#{ctx.mine_folder.uuid}")

      refute html =~ ctx.mine.uuid

      {:ok, picker, _html} = live_isolated(ctx.conn, PickerHost)
      assert has_element?(picker, ~s([phx-value-file-uuid="#{ctx.media_file.uuid}"]))
      refute has_element?(picker, ~s([phx-value-file-uuid="#{ctx.mine.uuid}"]))
      refute has_element?(picker, ~s([phx-value-file-uuid="#{ctx.theirs.uuid}"]))
    end
  end
end
