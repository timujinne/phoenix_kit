defmodule PhoenixKitWeb.Live.Components.MediaSelectorGroupByFolderTest do
  @moduledoc """
  `group_by_folder: true` on a scoped media selector: the files come sorted
  by the folder they sit in — the scope folder first, then its subfolders in
  path order — under one heading per folder, and a folder cut by a page break
  carries its heading onto the next page.
  """

  use PhoenixKitWeb.ConnCase, async: false

  import Phoenix.LiveViewTest

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.File, as: StorageFile
  alias PhoenixKitWeb.Live.Components.MediaSelectorModal

  defmodule Host do
    @moduledoc false
    use Phoenix.LiveView

    def mount(_params, session, socket) do
      # Only what the test passes, so the component's own defaults hold.
      opts =
        %{group_by_folder: session["group"], per_page: session["per_page"], size: session["size"]}
        |> Map.reject(fn {_key, value} -> is_nil(value) end)

      {:ok, assign(socket, scope: session["scope"], opts: opts)}
    end

    def render(assigns) do
      ~H"""
      <.live_component
        module={MediaSelectorModal}
        id="picker"
        show={true}
        mode={:multiple}
        selected_uuids={[]}
        scope_folder_id={@scope}
        file_type_filter={:image}
        lock_file_type
        phoenix_kit_current_user={nil}
        {@opts}
      />
      """
    end

    def handle_info(_message, socket), do: {:noreply, socket}
  end

  defp folder!(name, parent \\ nil) do
    {:ok, folder} =
      Storage.create_folder(%{
        name: "#{name}",
        parent_uuid: parent && parent.uuid
      })

    folder
  end

  defp file!(folder) do
    n = System.unique_integer([:positive])

    Repo.insert!(%StorageFile{
      original_file_name: "g#{n}.png",
      file_name: "g#{n}.png",
      mime_type: "image/png",
      file_type: "image",
      ext: "png",
      file_checksum: "gbf-#{n}",
      user_file_checksum: "gbf-u-#{n}",
      size: 1,
      status: "active",
      folder_uuid: folder.uuid,
      user_uuid: Process.get(:owner_uuid)
    })
  end

  defp open(conn, scope, opts \\ []) do
    live_isolated(conn, Host,
      session: %{
        "scope" => scope.uuid,
        "group" => Keyword.get(opts, :group, true),
        "per_page" => Keyword.get(opts, :per_page),
        "size" => Keyword.get(opts, :size)
      }
    )
  end

  defp group_id(folder), do: "#media-selector-group-picker-#{folder.uuid}"

  defp tile_in?(view, folder, file),
    do:
      has_element?(
        view,
        ~s(div[phx-value-file-uuid="#{file.uuid}"][data-media-group="#{folder.uuid}"])
      )

  defp headings(html) do
    html
    |> LazyHTML.from_fragment()
    |> LazyHTML.query("[data-media-group-label]")
    |> Enum.map(&(&1 |> LazyHTML.text() |> String.trim()))
  end

  setup do
    {user, _token} = create_admin_user()
    Process.put(:owner_uuid, user.uuid)

    scope = folder!("order-#{System.unique_integer([:positive])}")
    sub1 = folder!("sub-1", scope)
    tootmine = folder!("tootmine", sub1)
    sub2 = folder!("sub-2", scope)

    %{scope: scope, sub1: sub1, tootmine: tootmine, sub2: sub2}
  end

  test "files sit under their folder: the scope folder first, subfolders in path order",
       %{conn: conn} = ctx do
    root_file = file!(ctx.scope)
    sub1_file = file!(ctx.sub1)
    deep_file = file!(ctx.tootmine)
    sub2_file = file!(ctx.sub2)

    # A file living elsewhere, linked into sub-2: grouped where it is linked.
    outside = folder!("outside-#{System.unique_integer([:positive])}")
    linked = file!(outside)
    {:ok, _} = Storage.create_folder_link(ctx.sub2.uuid, linked.uuid)

    {:ok, view, html} = open(conn, ctx.scope)

    assert headings(html) == [ctx.scope.name, "sub-1", "sub-1 / tootmine", "sub-2"]

    assert tile_in?(view, ctx.scope, root_file)
    assert tile_in?(view, ctx.sub1, sub1_file)
    assert tile_in?(view, ctx.tootmine, deep_file)
    assert tile_in?(view, ctx.sub2, sub2_file)
    assert tile_in?(view, ctx.sub2, linked)

    # The heading counts the folder's files, not just the ones on this page.
    assert has_element?(view, "#{group_id(ctx.sub2)} [data-media-group-count]", "2 files")
  end

  test "a folder cut by the page break carries its heading onto the next page, marked continued",
       %{conn: conn} = ctx do
    sub1_files = for _ <- 1..3, do: file!(ctx.sub1)
    sub2_file = file!(ctx.sub2)

    {:ok, view, html} = open(conn, ctx.scope, per_page: 2)

    assert headings(html) == ["sub-1"]
    refute has_element?(view, "#{group_id(ctx.sub1)} [data-continued]")

    html =
      view
      |> with_target("#media-selector-modal-backdrop-picker")
      |> render_click("change_page", %{"page" => "2"})

    assert headings(html) == ["sub-1", "sub-2"]
    assert has_element?(view, "#{group_id(ctx.sub1)} [data-continued]")
    refute has_element?(view, "#{group_id(ctx.sub2)} [data-continued]")
    assert has_element?(view, "#{group_id(ctx.sub1)} [data-media-group-count]", "3 files")
    assert tile_in?(view, ctx.sub2, sub2_file)

    # Every sub-1 file is on page 1 or page 2, each exactly once.
    assert Enum.count(sub1_files, &tile_in?(view, ctx.sub1, &1)) == 1
  end

  test "without group_by_folder the picker keeps its flat, newest-first grid",
       %{conn: conn} = ctx do
    older = file!(ctx.sub1)
    newer = file!(ctx.scope)

    Repo.update_all(
      from(f in StorageFile, where: f.uuid == ^older.uuid),
      set: [inserted_at: ~U[2020-01-01 00:00:00Z]]
    )

    {:ok, view, html} = open(conn, ctx.scope, group: false)

    assert headings(html) == []
    refute has_element?(view, "[data-media-group]")

    uuids =
      html
      |> LazyHTML.from_fragment()
      |> LazyHTML.query("div[phx-value-file-uuid]")
      |> Enum.map(&(&1 |> LazyHTML.attribute("phx-value-file-uuid") |> List.first()))

    assert uuids == [newer.uuid, older.uuid]
  end

  test "size :full fills the viewport and lists 60 files a page", %{conn: conn} = ctx do
    for _ <- 1..35, do: file!(ctx.sub1)

    {:ok, view, html} = open(conn, ctx.scope, size: :full)

    assert has_element?(view, ~s{div[class*="h-[calc(100dvh-1rem)]"]})

    assert html
           |> LazyHTML.from_fragment()
           |> LazyHTML.query("div[phx-value-file-uuid]")
           |> Enum.count() == 35

    refute has_element?(view, ~s(button[phx-click="change_page"]))
  end
end
