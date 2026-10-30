defmodule PhoenixKitWeb.Components.MediaBrowserPickerSubtreeTest do
  @moduledoc """
  The picker's "Include subfolders" switch (`subtree_toggle`), its page size
  (`per_page`) and its denser grid.

  Off (the default) the picker is what it was. On, it lists the files of the
  folder it stands in and of every folder below it, flat, paged; at the top
  of the scope that is the whole scope. The scope is never widened, and a
  file listed from a subfolder is picked and moved as a file of that
  subfolder.
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
          subtree_toggle={Map.get(@opts, :subtree_toggle, false)}
          parent_uploads={@uploads}
          phoenix_kit_current_user={@phoenix_kit_current_user}
        />
        <.live_component
          :if={not Map.get(@opts, :plain, false)}
          module={MediaBrowser}
          id="pick"
          picker
          selected={@selected}
          scope_folder_id={Map.get(@opts, :unscoped, false) |> then(&if(&1, do: nil, else: @scope))}
          subtree_toggle={Map.get(@opts, :subtree_toggle, false)}
          per_page={Map.get(@opts, :per_page)}
          allow_move={Map.get(@opts, :allow_move, false)}
          only_file_type={@opts[:only_file_type]}
          on_navigate={@opts[:on_navigate]}
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

    def handle_info({MediaBrowser, _id, {:picker_uploading, _}}, socket), do: {:noreply, socket}

    def handle_info({:opts, opts}, socket),
      do: {:noreply, assign(socket, :opts, Map.merge(socket.assigns.opts, opts))}

    # What a controlled host does with {:navigate, _}: hands the page back.
    def handle_info({:nav_back, params}, socket) do
      Phoenix.LiveView.send_update(MediaBrowser, id: "pick", nav_params: params)
      {:noreply, socket}
    end

    def handle_info({MediaBrowser, _id, {:navigate, params}}, socket) do
      send(socket.assigns.test_pid, {:navigate, params})
      {:noreply, socket}
    end

    def handle_info({MediaBrowser, _, _} = msg, socket),
      do: MediaBrowser.handle_parent_info(msg, socket)

    def handle_info(_msg, socket), do: {:noreply, socket}
  end

  setup do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    root = Path.join(System.tmp_dir!(), "pk_picker_subtree_#{n}")

    {:ok, _bucket} =
      Storage.create_bucket(%{
        name: "picker-subtree-#{n}",
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
        email: "picker-subtree-#{n}@example.com",
        password: "ValidPassword123!"
      })

    Process.put(:owner_uuid, user.uuid)

    # Order
    # ├── Kitchen
    # │   └── Cabinets
    # └── Hall
    # Elsewhere (outside the scope)
    scope = folder!("Order")
    kitchen = folder!("Kitchen", scope)
    cabinets = folder!("Cabinets", kitchen)
    hall = folder!("Hall", scope)
    elsewhere = folder!("Elsewhere")

    %{
      user: user,
      scope: scope,
      kitchen: kitchen,
      cabinets: cabinets,
      hall: hall,
      elsewhere: elsewhere
    }
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
          original_file_name: "subtree-#{n}.png",
          file_name: "subtree-#{n}.png",
          mime_type: "image/png",
          file_type: "image",
          ext: "png",
          file_checksum: "picker-subtree-#{n}",
          user_file_checksum: "picker-subtree-u-#{n}",
          size: 1,
          status: "active",
          folder_uuid: folder && folder.uuid,
          user_uuid: Process.get(:owner_uuid)
        },
        attrs
      )
    )
  end

  defp open(conn, ctx, opts \\ %{}, selected \\ []) do
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

  defp switch(view, on), do: hook(view, "set_subtree_view", %{"on" => to_string(on)})
  defp enter(view, folder), do: hook(view, "navigate_folder", %{"folder-uuid" => folder.uuid})

  defp card(file), do: ~s(#pick [phx-click="click_file"][phx-value-file-uuid="#{file.uuid}"])
  defp listed?(view, file), do: has_element?(view, card(file))

  defp tile?(view, folder),
    do: has_element?(view, ~s(#pick [data-media-grid] [data-drop-folder="#{folder.uuid}"]))

  defp cards(view),
    do: view |> render() |> String.split(~s(phx-click="click_file")) |> length() |> Kernel.-(1)

  defp home(file), do: Repo.get(StorageFile, file.uuid).folder_uuid

  # The fixture: one file per folder, a doc in the Cabinets, one outside the
  # scope, one homed outside and linked into the Cabinets.
  defp fixture(ctx) do
    outside = file!(ctx.elsewhere)
    linked = file!(ctx.elsewhere)
    {:ok, _} = Storage.create_folder_link(ctx.cabinets.uuid, linked.uuid)

    %{
      top: file!(ctx.scope),
      kitchen: file!(ctx.kitchen),
      cabinets: file!(ctx.cabinets),
      hall: file!(ctx.hall),
      outside: outside,
      linked: linked
    }
  end

  describe "without the attribute" do
    test "no switch, and the picker lists the folder it stands in", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx)

      refute has_element?(view, "#pick-subtree-toggle")
      assert listed?(view, f.top)
      refute listed?(view, f.kitchen)
      assert tile?(view, ctx.kitchen)
    end

    test "the event is refused and lists nothing more", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx)

      log = capture_log(fn -> switch(view, true) end)

      assert log =~ "set_subtree_view refused"
      refute listed?(view, f.kitchen)
      assert tile?(view, ctx.kitchen)
    end

    test "outside a picker the attribute and the event change nothing", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{plain: true, subtree_toggle: true})

      refute has_element?(view, "#files-subtree-toggle")
      refute has_element?(view, "#files-tile-size")

      capture_log(fn -> switch_plain(view) end)

      html = render(view)
      assert html =~ f.top.uuid
      refute html =~ f.kitchen.uuid
    end

    test "a browser that is not a picker keeps its grid", %{conn: conn} = ctx do
      view = open(conn, ctx, %{plain: true})
      html = view |> element("#files [data-media-grid]") |> render()

      assert html =~
               ~s|class="grid grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-[repeat(auto-fill,minmax(9rem,1fr))] gap-3 [transform:translateZ(0)]"|

      refute html =~ "data-tile-size"
    end
  end

  defp switch_plain(view),
    do: view |> element("#files") |> render_hook("set_subtree_view", %{"on" => "true"})

  describe "the switch" do
    test "is in the bar, off, and turns on", %{conn: conn} = ctx do
      view = open(conn, ctx, %{subtree_toggle: true})

      assert has_element?(view, "#pick-subtree-toggle:not([checked])")
      view |> element("#pick-subtree-toggle") |> render_click()
      assert has_element?(view, "#pick-subtree-toggle[checked]")
    end

    test "at the top of the scope lists the whole scope, flat", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})

      assert listed?(view, f.top)
      refute listed?(view, f.kitchen)

      switch(view, true)

      for file <- [f.top, f.kitchen, f.cabinets, f.hall, f.linked],
          do: assert(listed?(view, file))

      refute listed?(view, f.outside)

      for folder <- [ctx.kitchen, ctx.cabinets, ctx.hall], do: refute(tile?(view, folder))

      switch(view, false)
      refute listed?(view, f.kitchen)
      assert tile?(view, ctx.kitchen)
    end

    test "in a folder lists its subtree, not the neighbours or the parent", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})

      enter(view, ctx.kitchen)
      refute listed?(view, f.cabinets)

      switch(view, true)

      for file <- [f.kitchen, f.cabinets, f.linked], do: assert(listed?(view, file))
      for file <- [f.top, f.hall, f.outside], do: refute(listed?(view, file))
    end

    test "holds while the person walks the tree", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      enter(view, ctx.kitchen)
      assert has_element?(view, "#pick-subtree-toggle[checked]")
      assert listed?(view, f.cabinets)
      refute listed?(view, f.hall)

      enter(view, ctx.hall)
      assert listed?(view, f.hall)
      refute listed?(view, f.kitchen)

      hook(view, "navigate_root")
      assert listed?(view, f.cabinets) and listed?(view, f.hall)
    end

    test "a file homed and linked inside the subtree is listed once", %{conn: conn} = ctx do
      f = fixture(ctx)
      {:ok, _} = Storage.create_folder_link(ctx.hall.uuid, f.cabinets.uuid)
      view = open(conn, ctx, %{subtree_toggle: true})

      switch(view, true)

      assert cards(view) == 5
    end

    test "the search runs in the subtree", %{conn: conn} = ctx do
      f = fixture(ctx)
      deep = file!(ctx.cabinets, %{original_file_name: "oak-door.png"})
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      hook(view, "search", %{"q" => "oak-door"})

      assert listed?(view, deep)
      refute listed?(view, f.kitchen)
    end

    test "the locked file type applies", %{conn: conn} = ctx do
      f = fixture(ctx)

      doc =
        file!(ctx.cabinets, %{file_type: "document", mime_type: "application/pdf", ext: "pdf"})

      view = open(conn, ctx, %{subtree_toggle: true, only_file_type: "image"})
      switch(view, true)

      assert listed?(view, f.cabinets)
      refute listed?(view, doc)
    end

    test "a trashed file is not listed", %{conn: conn} = ctx do
      f = fixture(ctx)

      Repo.update_all(from(x in StorageFile, where: x.uuid == ^f.cabinets.uuid),
        set: [status: "trashed"]
      )

      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      refute listed?(view, f.cabinets)
    end

    test "the Trash is the Trash whatever the switch says", %{conn: conn} = ctx do
      f = fixture(ctx)
      {:ok, _} = Storage.trash_folder(ctx.hall)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      hook(view, "toggle_trash_filter")

      assert tile?(view, ctx.hall)
      assert listed?(view, f.hall)
      refute render(view) =~ "Trash is empty"
      refute has_element?(view, "#pick-subtree-toggle")
    end

    test "All Files is All Files whatever the switch says", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      hook(view, "navigate_view_all")

      assert listed?(view, f.top)
      refute listed?(view, f.kitchen)
      refute has_element?(view, "#pick-subtree-toggle")
    end

    test "leaving the Trash or All Files, the switch is still on", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      hook(view, "toggle_trash_filter")
      hook(view, "toggle_trash_filter")
      assert listed?(view, f.cabinets)
      refute tile?(view, ctx.kitchen)

      hook(view, "navigate_view_all")
      refute listed?(view, f.cabinets)
      enter(view, ctx.kitchen)
      assert listed?(view, f.cabinets)
      assert has_element?(view, "#pick-subtree-toggle[checked]")
    end

    test "an unscoped picker lists every file at the top, orphans too", %{conn: conn} = ctx do
      f = fixture(ctx)
      orphan = file!(nil)
      view = open(conn, ctx, %{subtree_toggle: true, unscoped: true})

      switch(view, true)

      for file <- [f.top, f.kitchen, f.cabinets, f.hall, f.outside, orphan],
          do: assert(listed?(view, file))

      enter(view, ctx.elsewhere)
      assert listed?(view, f.outside)
      refute listed?(view, f.top)
    end

    test "a file trashed from a subfolder goes the way it would go from there",
         %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      # Homed in the Cabinets and linked into another folder: it moves home
      # there rather than into the Trash (a removal from the Cabinets).
      {:ok, _} = Storage.create_folder_link(ctx.hall.uuid, f.cabinets.uuid)
      hook(view, "trash_file", %{"file_uuid" => f.cabinets.uuid})

      moved = Repo.get(StorageFile, f.cabinets.uuid)
      assert moved.status == "active"
      assert moved.folder_uuid == ctx.hall.uuid

      # Homed outside the scope and linked into the Cabinets: only the link goes.
      hook(view, "trash_file", %{"file_uuid" => f.linked.uuid})

      kept = Repo.get(StorageFile, f.linked.uuid)
      assert kept.status == "active"
      assert kept.folder_uuid == ctx.elsewhere.uuid
      refute Storage.folder_link(ctx.cabinets.uuid, f.linked.uuid)
    end

    test "a file outside the scope is not trashed by its uuid", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      capture_log(fn -> hook(view, "trash_file", %{"file_uuid" => f.outside.uuid}) end)

      assert Repo.get(StorageFile, f.outside.uuid).status == "active"
    end

    test "a forged folder outside the scope lists nothing of it", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      hook(view, "navigate_folder", %{"folder-uuid" => ctx.elsewhere.uuid})

      refute listed?(view, f.outside)
      assert listed?(view, f.top)
    end

    test "a non-boolean value is refused", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})

      capture_log(fn -> hook(view, "set_subtree_view", %{"on" => "yes"}) end)

      refute listed?(view, f.kitchen)
    end

    test "restarts off on a new mount", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)
      assert listed?(view, f.kitchen)

      view = open(conn, ctx, %{subtree_toggle: true})
      refute listed?(view, f.kitchen)
    end

    test "works in a controlled browser: applied here, kept by the page that comes back",
         %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true, on_navigate: true})

      switch(view, true)
      assert listed?(view, f.kitchen)
      refute_received {:navigate, _}

      # The host navigates the browser into the Kitchen, as the URL would.
      send(view.pid, {:nav_back, %{folder: ctx.kitchen.uuid, q: "", page: 1, view: nil}})
      render(view)

      assert has_element?(view, "#pick-subtree-toggle[checked]")
      for file <- [f.kitchen, f.cabinets, f.linked], do: assert(listed?(view, file))
      for file <- [f.top, f.hall], do: refute(listed?(view, file))

      hook(view, "set_page", %{"page" => "1"})
      assert_receive {:navigate, %{page: 1, folder: folder}}
      assert folder == ctx.kitchen.uuid
    end
  end

  describe "paging" do
    test "pages the subtree with the browser's own pagination", %{conn: conn} = ctx do
      files =
        for folder <- [ctx.scope, ctx.kitchen, ctx.cabinets, ctx.hall, ctx.cabinets],
            do: file!(folder)

      view = open(conn, ctx, %{subtree_toggle: true, per_page: 2})
      switch(view, true)

      assert cards(view) == 2
      assert render(view) =~ "1 / 3"

      view
      |> element(~s(#pick button[phx-click="set_page"][phx-value-page="2"]))
      |> render_click()

      assert cards(view) == 2
      assert render(view) =~ "2 / 3"

      view
      |> element(~s(#pick button[phx-click="set_page"][phx-value-page="3"]))
      |> render_click()

      assert cards(view) == 1

      seen =
        for page <- 1..3, reduce: [] do
          acc ->
            hook(view, "set_page", %{"page" => to_string(page)})
            acc ++ Enum.filter(files, &listed?(view, &1))
        end

      assert length(Enum.uniq(seen)) == 5
    end

    test "turning it on returns to the first page", %{conn: conn} = ctx do
      for _ <- 1..4, do: file!(ctx.scope)
      view = open(conn, ctx, %{subtree_toggle: true, per_page: 2})
      hook(view, "set_page", %{"page" => "2"})
      assert render(view) =~ "2 / 2"

      switch(view, true)
      assert render(view) =~ "1 / 2"
    end
  end

  describe "per_page" do
    test "gives the picker its page size", %{conn: conn} = ctx do
      for _ <- 1..5, do: file!(ctx.scope)
      view = open(conn, ctx, %{per_page: 3})

      assert cards(view) == 3
      assert render(view) =~ "1 / 2"
    end

    test "a change on a mounted picker lists again from the first page", %{conn: conn} = ctx do
      for _ <- 1..5, do: file!(ctx.scope)
      view = open(conn, ctx, %{per_page: 3})
      hook(view, "set_page", %{"page" => "2"})
      assert render(view) =~ "2 / 2"

      send(view.pid, {:opts, %{per_page: 2}})

      assert cards(view) == 2
      assert render(view) =~ "1 / 3"

      send(view.pid, {:opts, %{per_page: 2}})
      hook(view, "set_page", %{"page" => "2"})
      assert render(view) =~ "2 / 3"
    end

    test "falls back to 50 for anything that is not a positive integer", %{conn: conn} = ctx do
      for _ <- 1..52, do: file!(ctx.scope)

      for bad <- ["many", 0, -4, 2.5, nil] do
        view = open(conn, ctx, %{per_page: bad})
        assert cards(view) == 50
        assert render(view) =~ "1 / 2"
      end
    end
  end

  describe "the grid" do
    test "a picker's tiles are small, a browser's are not", %{conn: conn} = ctx do
      file!(ctx.scope)
      picker = open(conn, ctx)
      plain = open(conn, ctx, %{plain: true})

      assert has_element?(
               picker,
               ~s|#pick [data-media-grid][data-tile-size="large"][class*="minmax(7rem,1fr)"][class*="gap-2"]|
             )

      refute has_element?(picker, ~s|#pick [data-media-grid][class*="minmax(9rem,1fr)"]|)
      assert has_element?(plain, ~s|#files [data-media-grid][class*="minmax(9rem,1fr)"]|)
    end

    test "Small makes them smaller still, and Large brings them back", %{conn: conn} = ctx do
      file!(ctx.scope)
      view = open(conn, ctx)

      view |> element(~s(#pick-tile-size button[phx-value-size="small"])) |> render_click()

      assert has_element?(
               view,
               ~s|#pick [data-media-grid][data-tile-size="small"][class*="minmax(5rem,1fr)"]|
             )

      assert has_element?(
               view,
               ~s(#pick-tile-size button[phx-value-size="small"][aria-pressed="true"])
             )

      view |> element(~s(#pick-tile-size button[phx-value-size="large"])) |> render_click()
      assert has_element?(view, ~s(#pick [data-media-grid][data-tile-size="large"]))
    end

    test "a size that is not offered is refused, and a browser that is not a picker has none",
         %{conn: conn} = ctx do
      file!(ctx.scope)
      view = open(conn, ctx)
      capture_log(fn -> hook(view, "set_tile_size", %{"size" => "huge"}) end)
      assert has_element?(view, ~s(#pick [data-media-grid][data-tile-size="large"]))

      plain = open(conn, ctx, %{plain: true})
      capture_log(fn -> hook(plain, "set_tile_size", %{"size" => "small"}, "files") end)
      refute has_element?(plain, "#files [data-tile-size]")
    end
  end

  describe "picking and moving from the subtree" do
    test "a file of a subfolder is picked and confirmed", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true})
      switch(view, true)

      view |> element(card(f.cabinets)) |> render_click()
      view |> element(~s(#pick button[phx-click="pick_confirm"])) |> render_click()

      assert_receive {:picked, "pick", [uuid]}
      assert uuid == f.cabinets.uuid
    end

    test "a pick made before the switch stays picked", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true}, [f.top.uuid])
      switch(view, true)

      view |> element(card(f.hall)) |> render_click()
      view |> element(~s(#pick button[phx-click="pick_confirm"])) |> render_click()

      assert_receive {:picked, "pick", picked}
      assert picked == [f.top.uuid, f.hall.uuid]
    end

    test "a file of a subfolder is dragged from the folder that holds it", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true, allow_move: true})
      switch(view, true)

      assert has_element?(view, ~s(#pick [data-draggable-file="#{f.cabinets.uuid}"]))

      hook(view, "move_file_to_folder", %{
        "file_uuid" => f.cabinets.uuid,
        "folder_uuid" => ctx.hall.uuid
      })

      assert home(f.cabinets) == ctx.hall.uuid
      assert listed?(view, f.cabinets)
    end

    test "a file linked into a subfolder is moved from that link", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true, allow_move: true})
      switch(view, true)

      hook(view, "move_file_to_folder", %{
        "file_uuid" => f.linked.uuid,
        "folder_uuid" => ctx.hall.uuid
      })

      assert home(f.linked) == ctx.elsewhere.uuid
      assert Storage.folder_link(ctx.hall.uuid, f.linked.uuid)
      refute Storage.folder_link(ctx.cabinets.uuid, f.linked.uuid)
    end

    test "a file outside the scope is not moved by its uuid", %{conn: conn} = ctx do
      f = fixture(ctx)
      view = open(conn, ctx, %{subtree_toggle: true, allow_move: true})
      switch(view, true)

      capture_log(fn ->
        hook(view, "move_file_to_folder", %{
          "file_uuid" => f.outside.uuid,
          "folder_uuid" => ctx.hall.uuid
        })
      end)

      assert home(f.outside) == ctx.elsewhere.uuid
    end

    test "the pick moves whole from a folder where it was picked in the subtree",
         %{conn: conn} = ctx do
      f = fixture(ctx)

      view =
        open(conn, ctx, %{subtree_toggle: true, allow_move: true}, [
          f.cabinets.uuid,
          f.kitchen.uuid
        ])

      switch(view, true)

      hook(view, "move_selected_to_folder", %{"folder-uuid" => ctx.hall.uuid})

      assert home(f.cabinets) == ctx.hall.uuid
      assert home(f.kitchen) == ctx.hall.uuid
    end
  end

  describe "Storage.list_files_in_scope/2 :subtree" do
    test "walks the folder and everything below it, each file once", ctx do
      f = fixture(ctx)
      {:ok, _} = Storage.create_folder_link(ctx.hall.uuid, f.cabinets.uuid)

      {files, total} = Storage.list_files_in_scope(ctx.kitchen.uuid, subtree: true)
      assert total == 3

      assert Enum.sort(Enum.map(files, & &1.uuid)) ==
               Enum.sort([f.kitchen.uuid, f.cabinets.uuid, f.linked.uuid])

      {_, total} = Storage.list_files_in_scope(ctx.scope.uuid, subtree: true)
      assert total == 5

      {_, plain} = Storage.list_files_in_scope(ctx.scope.uuid, [])
      assert plain == 1
    end

    test "keeps the scope", ctx do
      fixture(ctx)

      assert {:error, :out_of_scope} =
               Storage.list_files_in_scope(ctx.scope.uuid,
                 folder_uuid: ctx.elsewhere.uuid,
                 subtree: true
               )

      {_, total} =
        Storage.list_files_in_scope(ctx.scope.uuid, folder_uuid: ctx.kitchen.uuid, subtree: true)

      assert total == 3
    end

    test "with neither scope nor folder it is every file", ctx do
      f = fixture(ctx)
      orphan = file!(nil)

      {files, _} = Storage.list_files_in_scope(nil, subtree: true, per_page: 1000)
      uuids = Enum.map(files, & &1.uuid)
      assert orphan.uuid in uuids and f.outside.uuid in uuids and f.top.uuid in uuids
    end
  end
end
