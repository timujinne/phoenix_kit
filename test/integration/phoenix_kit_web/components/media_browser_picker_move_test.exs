defmodule PhoenixKitWeb.Components.MediaBrowserPickerMoveTest do
  @moduledoc """
  `allow_move` on the media browser's picker: the picked files can be dragged
  to a folder of the tree (or a folder tile) and are moved there, inside the
  scope, whatever `folder_actions` says. Without it the picker is as before,
  and outside a picker the attribute changes nothing.

  The pick is the server's: a batch moves what the browser holds as picked,
  not a list the client sends, and every file passes the same check as a
  click (`pickable?`). Folders are never dragged; the Trash takes no drop;
  every other folder write stays refused under `folder_actions: false`.
  """

  use PhoenixKitWeb.ConnCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKit.Users.Auth
  alias PhoenixKitWeb.Components.MediaBrowser

  @buckets_cache :phoenix_kit_buckets_cache

  defmodule Host do
    @moduledoc false
    use Phoenix.LiveView
    import Plug.Conn, only: []

    alias PhoenixKitWeb.Components.MediaBrowser

    def mount(_params, session, socket) do
      {:ok,
       socket
       |> assign(:phoenix_kit_current_user, session["user"])
       |> MediaBrowser.setup_uploads()
       |> assign(
         test_pid: session["test_pid"],
         scope: session["scope"],
         opts: session["opts"] || %{},
         selected: session["selected"] || []
       )}
    end

    def render(assigns) do
      ~H"""
      <div>
        <.live_component
          :if={Map.get(@opts, :plain, false)}
          module={MediaBrowser}
          id="files"
          scope_folder_id={@scope}
          folder_actions={Map.get(@opts, :folder_actions, true)}
          allow_move={Map.get(@opts, :allow_move, false)}
          parent_uploads={@uploads}
          phoenix_kit_current_user={@phoenix_kit_current_user}
        />
        <.live_component
          :if={not Map.get(@opts, :plain, false)}
          module={MediaBrowser}
          id="pick"
          picker
          selected={@selected}
          folder_actions={Map.get(@opts, :folder_actions, true)}
          allow_move={Map.get(@opts, :allow_move, false)}
          readonly={Map.get(@opts, :readonly, false)}
          own_files_only={@opts[:own_files_only]}
          scope_folder_id={@scope}
          parent_uploads={@uploads}
          phoenix_kit_current_user={@phoenix_kit_current_user}
        />
      </div>
      """
    end

    def handle_event("validate", _params, socket), do: {:noreply, socket}

    def handle_info({MediaBrowser, id, {:picked, uuids}}, socket) do
      send(socket.assigns.test_pid, {:picked, id, uuids})
      {:noreply, socket}
    end

    def handle_info({MediaBrowser, _, _} = msg, socket),
      do: MediaBrowser.handle_parent_info(msg, socket)

    def handle_info(_msg, socket), do: {:noreply, socket}
  end

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_picker_move_#{n}")

    {:ok, _bucket} =
      Storage.create_bucket(%{
        name: "picker-move-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true,
        priority: 0
      })

    start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    on_exit(fn ->
      :persistent_term.erase(@buckets_cache)
      File.rm_rf(root)
    end)

    {:ok, user} =
      Auth.register_user(%{
        email: "picker-move-#{n}@example.com",
        password: "ValidPassword123!"
      })

    Process.put(:owner_uuid, user.uuid)
    scope = folder!("Order")
    kitchen = folder!("Kitchen", scope)
    hall = folder!("Hall", scope)
    %{user: user, scope: scope, kitchen: kitchen, hall: hall}
  end

  defp folder!(name, parent \\ nil) do
    {:ok, folder} =
      Storage.create_folder(%{
        name: "#{name}-#{System.unique_integer([:positive])}",
        parent_uuid: parent && parent.uuid
      })

    folder
  end

  defp file!(folder, attrs \\ %{}) do
    n = System.unique_integer([:positive])

    Repo.insert!(
      struct(
        %StorageFile{
          original_file_name: "kitchen-#{n}.png",
          file_name: "kitchen-#{n}.png",
          mime_type: "image/png",
          file_type: "image",
          ext: "png",
          file_checksum: "picker-move-#{n}",
          user_file_checksum: "picker-move-u-#{n}",
          size: 1,
          status: "active",
          folder_uuid: folder && folder.uuid,
          user_uuid: Process.get(:owner_uuid)
        },
        attrs
      )
    )
  end

  defp open(conn, ctx, opts, selected \\ []) do
    {:ok, view, _html} =
      live_isolated(conn, Host,
        session: %{
          "test_pid" => self(),
          "scope" => ctx.scope.uuid,
          "user" => ctx.user,
          "opts" => opts,
          "selected" => selected
        }
      )

    view
  end

  defp hook(view, event, params \\ %{}, browser \\ "pick") do
    view |> element("##{browser}") |> render_hook(event, params)
  end

  defp click_file(view, file) do
    view
    |> element(~s(#pick [phx-click="click_file"][phx-value-file-uuid="#{file.uuid}"]))
    |> render_click()
  end

  defp move_batch(view, folder_uuid, extra \\ %{}),
    do: hook(view, "move_selected_to_folder", Map.merge(%{"folder-uuid" => folder_uuid}, extra))

  defp confirm(view),
    do: view |> element(~s(#pick button[phx-click="pick_confirm"])) |> render_click()

  # The browser's flash (a component's `put_flash` is held in its own assigns).
  defp flash(view) do
    {components, _, _} = :sys.get_state(view.pid).components

    components
    |> Map.values()
    |> Enum.find_value("", fn
      {MediaBrowser, _id, assigns, _private, _prints} ->
        assigns.flash |> Map.values() |> Enum.join(" ")

      {MediaBrowser, assigns, _private, _prints} ->
        assigns.flash |> Map.values() |> Enum.join(" ")

      _ ->
        nil
    end)
  end

  defp home(file), do: Repo.get(StorageFile, file.uuid).folder_uuid

  describe "without allow_move" do
    test "the picker has no drag and drop at all", %{conn: conn} = ctx do
      file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false})

      refute has_element?(view, "#pick [data-draggable-file]")
      refute has_element?(view, "#pick [data-draggable-folder]")
      refute has_element?(view, "#pick-media-browser-sidebar [data-drop-folder]")
      refute has_element?(view, "#pick [data-drop-trash]")
      refute has_element?(view, "#pick [data-pick-count]")
    end

    test "a move is refused on the server", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false}, [a.uuid])

      capture_log(fn ->
        hook(view, "move_file_to_folder", %{
          "file_uuid" => a.uuid,
          "folder_uuid" => ctx.kitchen.uuid
        })

        move_batch(view, ctx.kitchen.uuid)
      end)

      assert home(a) == ctx.scope.uuid
    end
  end

  describe "with allow_move" do
    test "the files and the folders of the tree take part; folders and the Trash do not",
         %{conn: conn} = ctx do
      a = file!(ctx.scope)

      for folder_actions <- [false, true] do
        view = open(conn, ctx, %{folder_actions: folder_actions, allow_move: true})

        assert has_element?(view, ~s(#pick [data-draggable-file="#{a.uuid}"]))
        assert has_element?(view, ~s(#pick-media-browser-sidebar [data-drop-folder="root"]))

        assert has_element?(
                 view,
                 ~s(#pick-media-browser-sidebar [data-drop-folder="#{ctx.kitchen.uuid}"])
               )

        assert has_element?(
                 view,
                 ~s(#pick [data-media-grid] [data-drop-folder="#{ctx.hall.uuid}"])
               )

        refute has_element?(view, "#pick [data-draggable-folder]")
        refute has_element?(view, "#pick [data-drop-trash]")
        refute has_element?(view, "#pick [data-box-area]")
      end
    end

    test "the root carries how many files are picked", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.scope)
      view = open(conn, ctx, %{allow_move: true})

      assert has_element?(view, ~s(#pick[data-pick-count="0"]))
      click_file(view, a)
      click_file(view, b)
      assert has_element?(view, ~s(#pick[data-pick-count="2"]))
    end

    test "a picked card is marked for the drag script", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.scope)
      view = open(conn, ctx, %{allow_move: true}, [a.uuid])

      assert has_element?(view, ~s(#pick [data-draggable-file="#{a.uuid}"][data-pick-order="1"]))
      refute has_element?(view, ~s(#pick [data-draggable-file="#{b.uuid}"][data-pick-order]))
    end

    test "one file moves, and the pick stays", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      hook(view, "move_file_to_folder", %{
        "file_uuid" => a.uuid,
        "folder_uuid" => ctx.kitchen.uuid
      })

      assert flash(view) =~ "File moved"
      assert home(a) == ctx.kitchen.uuid

      confirm(view)
      assert_receive {:picked, "pick", [uuid]}
      assert uuid == a.uuid
    end

    test "a file that is not picked moves alone", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      hook(view, "move_file_to_folder", %{
        "file_uuid" => b.uuid,
        "folder_uuid" => ctx.kitchen.uuid
      })

      assert home(b) == ctx.kitchen.uuid
      assert home(a) == ctx.scope.uuid
    end

    test "a drop on the top level of a scoped browser moves into the scope folder",
         %{conn: conn} = ctx do
      a = file!(ctx.kitchen)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true})

      hook(view, "move_file_to_folder", %{"file_uuid" => a.uuid, "folder_uuid" => ""})

      assert home(a) == ctx.scope.uuid
    end

    test "the whole pick moves, the others stay, and the pick keeps its order",
         %{conn: conn} = ctx do
      [a, b, c, d] = for _ <- 1..4, do: file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true})

      click_file(view, c)
      click_file(view, a)
      click_file(view, d)

      move_batch(view, ctx.kitchen.uuid)

      assert flash(view) =~ "3 items moved"
      assert [home(a), home(c), home(d)] == List.duplicate(ctx.kitchen.uuid, 3)
      assert home(b) == ctx.scope.uuid

      confirm(view)
      assert_receive {:picked, "pick", uuids}
      assert uuids == [c.uuid, a.uuid, d.uuid]
    end

    test "a pick made in another folder moves too", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.hall)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid, b.uuid])

      move_batch(view, ctx.kitchen.uuid)

      assert flash(view) =~ "2 items moved"
      assert home(a) == ctx.kitchen.uuid
      assert home(b) == ctx.kitchen.uuid
    end

    test "a file that is in the target already is left, and not counted", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.kitchen)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid, b.uuid])

      move_batch(view, ctx.kitchen.uuid)

      assert flash(view) =~ "1 item moved"
      assert home(a) == ctx.kitchen.uuid
      assert home(b) == ctx.kitchen.uuid
    end

    test "the drop of the batch on the top level moves into the scope folder",
         %{conn: conn} = ctx do
      a = file!(ctx.kitchen)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      move_batch(view, "")

      assert home(a) == ctx.scope.uuid
    end

    test "the files the client names are not the pick", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      c = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      move_batch(view, ctx.kitchen.uuid, %{"files" => [c.uuid], "file_uuid" => c.uuid})

      assert home(a) == ctx.kitchen.uuid
      assert home(c) == ctx.scope.uuid
    end

    test "a picked file that went to the trash is not moved", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      b = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid, b.uuid])

      {:ok, _} = Storage.update_file(Repo.get(StorageFile, b.uuid), %{status: "trashed"})
      move_batch(view, ctx.kitchen.uuid)

      assert home(a) == ctx.kitchen.uuid
      assert home(b) == ctx.scope.uuid
    end

    test "a contributor moves only the files they uploaded", %{conn: conn, user: user} = ctx do
      {:ok, other} =
        Auth.register_user(%{
          email: "other-#{System.unique_integer([:positive])}@example.com",
          password: "ValidPassword123!"
        })

      mine = file!(ctx.scope)
      theirs = file!(ctx.scope, %{user_uuid: other.uuid})

      view =
        open(
          conn,
          ctx,
          %{folder_actions: false, allow_move: true, own_files_only: user.uuid},
          [mine.uuid, theirs.uuid]
        )

      move_batch(view, ctx.kitchen.uuid)

      assert home(mine) == ctx.kitchen.uuid
      assert home(theirs) == ctx.scope.uuid
    end
  end

  describe "with allow_move, what is outside the scope" do
    test "a file outside the scope is not moved into it", %{conn: conn} = ctx do
      outside = folder!("Elsewhere")
      stranger = file!(outside)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true})

      capture_log(fn ->
        hook(view, "move_file_to_folder", %{
          "file_uuid" => stranger.uuid,
          "folder_uuid" => ctx.kitchen.uuid
        })
      end)

      assert home(stranger) == outside.uuid
    end

    test "a file is not moved out of the scope", %{conn: conn} = ctx do
      outside = folder!("Elsewhere")
      a = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      hook(view, "move_file_to_folder", %{
        "file_uuid" => a.uuid,
        "folder_uuid" => outside.uuid
      })

      assert flash(view) =~ "Cannot move file outside the allowed scope"
      assert home(a) == ctx.scope.uuid

      move_batch(view, outside.uuid)

      assert flash(view) =~ "Cannot move file outside the allowed scope"
      assert home(a) == ctx.scope.uuid
    end

    test "a picked file that has left the scope since stays where it is", %{conn: conn} = ctx do
      outside = folder!("Elsewhere")
      a = file!(ctx.scope)
      b = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid, b.uuid])

      Repo.update_all(from(f in StorageFile, where: f.uuid == ^b.uuid),
        set: [folder_uuid: outside.uuid]
      )

      move_batch(view, ctx.kitchen.uuid)

      assert home(a) == ctx.kitchen.uuid
      assert home(b) == outside.uuid
    end
  end

  describe "with allow_move, the rest of the folder actions" do
    test "the folder writes are still refused", %{conn: conn} = ctx do
      a = file!(ctx.kitchen)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true}, [a.uuid])

      capture_log(fn ->
        hook(view, "move_folder_to_folder", %{
          "folder_uuid" => ctx.hall.uuid,
          "target_uuid" => ctx.kitchen.uuid
        })

        hook(view, "trash_folder", %{"folder_uuid" => ctx.hall.uuid})
        hook(view, "rename_folder", %{"folder_uuid" => ctx.hall.uuid, "name" => "Renamed"})
        hook(view, "prepare_move_file", %{"file-uuid" => a.uuid})
        hook(view, "show_move_modal")
        hook(view, "toggle_select_folder", %{"folder-uuid" => ctx.hall.uuid})
        hook(view, "toggle_trash_filter")
      end)

      assert Storage.get_folder(ctx.hall.uuid).parent_uuid == ctx.scope.uuid
      assert is_nil(Storage.get_folder(ctx.hall.uuid).trashed_at)
      assert Storage.get_folder(ctx.hall.uuid).name == ctx.hall.name
      refute has_element?(view, "#pick-move-modal")
    end

    test "every folder event but the two moves of files is refused with the socket untouched" do
      for event <- MediaBrowser.folder_action_events(),
          event not in ~w(move_file_to_folder move_selected_to_folder) do
        socket = %Phoenix.LiveView.Socket{
          assigns: %{
            __changed__: %{},
            id: "mb",
            folder_actions: false,
            picker: true,
            allow_move: true
          }
        }

        assert {:noreply, ^socket} =
                 capture_log_result(fn -> MediaBrowser.handle_event(event, %{}, socket) end),
               "expected #{event} to be refused with folder actions off"
      end
    end

    test "readonly refuses the moves, and shows nothing to drag", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      view = open(conn, ctx, %{folder_actions: false, allow_move: true, readonly: true}, [a.uuid])

      refute has_element?(view, "#pick [data-draggable-file]")
      refute has_element?(view, "#pick-media-browser-sidebar [data-drop-folder]")

      capture_log(fn ->
        hook(view, "move_file_to_folder", %{
          "file_uuid" => a.uuid,
          "folder_uuid" => ctx.kitchen.uuid
        })

        move_batch(view, ctx.kitchen.uuid)
      end)

      assert home(a) == ctx.scope.uuid
    end
  end

  describe "outside a picker" do
    test "allow_move changes nothing", %{conn: conn} = ctx do
      a = file!(ctx.scope)
      view = open(conn, ctx, %{plain: true, folder_actions: false, allow_move: true})

      refute has_element?(view, "#files-media-browser-sidebar [data-drop-folder]")
      refute has_element?(view, "#files [data-drop-folder=\"#{ctx.kitchen.uuid}\"]")
      refute has_element?(view, "#files [data-pick-count]")

      capture_log(fn ->
        hook(
          view,
          "move_file_to_folder",
          %{"file_uuid" => a.uuid, "folder_uuid" => ctx.kitchen.uuid},
          "files"
        )
      end)

      assert home(a) == ctx.scope.uuid
    end
  end

  defp capture_log_result(fun) do
    ref = make_ref()
    capture_log(fn -> send(self(), {ref, fun.()}) end)

    receive do
      {^ref, result} -> result
    end
  end
end
