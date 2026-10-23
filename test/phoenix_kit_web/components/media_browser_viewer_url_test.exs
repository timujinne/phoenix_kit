defmodule PhoenixKitWeb.Components.MediaBrowserViewerUrlTest do
  @moduledoc """
  The modal viewer's file rides the URL (`?file=<uuid>`) next to the
  folder, so a refresh lands back in the viewer on that file — not at
  root with the modal gone and the user hunting for the folder and file
  again. Three parts: the Embed helpers parse/build the param, the
  component's nav path syncs the viewer from it (fast-pathing when only
  the file changed, so opening a viewer never reloads the listing), and
  viewer events announce themselves so the URL follows.
  """

  use ExUnit.Case, async: true

  alias PhoenixKitWeb.Components.MediaBrowser
  alias PhoenixKitWeb.Components.MediaBrowser.Embed

  # ── Embed: the URL half ──────────────────────────────────────────────

  test "file survives the parse → build round trip" do
    params = %{"folder" => "f-1", "file" => "img-9"}
    nav = Embed.parse_nav_params(params)
    assert nav.file == "img-9"
    assert Embed.build_nav_query(nav) == %{"folder" => "f-1", "file" => "img-9"}
  end

  test "no viewer, no param — a closed viewer keeps the URL clean" do
    nav = Embed.parse_nav_params(%{"folder" => "f-1"})
    assert nav.file == nil
    refute Map.has_key?(Embed.build_nav_query(nav), "file")
  end

  # ── The component: nav params drive the viewer ───────────────────────

  @file_a %{file_uuid: "img-a", filename: "a.png"}
  @file_b %{file_uuid: "img-b", filename: "b.png"}

  # A socket whose listing already matches the nav params (root, page 1,
  # no search) — apply_nav_params takes its fast path and touches no
  # storage, which is also the assertion that opening a viewer does not
  # reload the listing.
  defp socket_with(assigns) do
    %Phoenix.LiveView.Socket{
      assigns:
        Map.merge(
          %{
            __changed__: %{},
            uploaded_files: [@file_a, @file_b],
            stack_files: %{},
            current_folder: nil,
            search_query: "",
            current_page: 1,
            filter_orphaned: false,
            file_view: nil,
            viewer_file: nil,
            viewer_siblings: [],
            upload_in_flight: false,
            show_upload: false
          },
          assigns
        )
    }
  end

  defp nav(file),
    do: %{folder: nil, q: "", page: 1, filter_orphaned: false, view: nil, file: file}

  test "?file= opens the viewer on that file, siblings from the listing" do
    {:ok, socket} = MediaBrowser.update(%{nav_params: nav("img-b")}, socket_with(%{}))
    assert socket.assigns.viewer_file.file_uuid == "img-b"
    assert socket.assigns.viewer_siblings == [@file_a, @file_b], "prev/next step the page"
  end

  test "no file in the URL closes an open viewer — Back closes what it opened" do
    {:ok, socket} =
      MediaBrowser.update(
        %{nav_params: nav(nil)},
        socket_with(%{viewer_file: @file_a, viewer_siblings: [@file_a]})
      )

    assert socket.assigns.viewer_file == nil
    assert socket.assigns.viewer_siblings == []
  end

  test "the already-open file is left alone — the feed-back after an open is a no-op" do
    original_siblings = [@file_a]

    {:ok, socket} =
      MediaBrowser.update(
        %{nav_params: nav("img-a")},
        socket_with(%{viewer_file: @file_a, viewer_siblings: original_siblings})
      )

    assert socket.assigns.viewer_file == @file_a

    assert socket.assigns.viewer_siblings == original_siblings,
           "re-locating would rebind the step list mid-session"
  end

  # A host that wired controlled mode by hand, before `file` existed, hands
  # back nav params with no such key. Reading that as "close" shut the viewer
  # on the echo of the very click that opened it.
  test "nav params with no file key leave the viewer alone" do
    {:ok, socket} =
      MediaBrowser.update(
        %{nav_params: Map.delete(nav(nil), :file)},
        socket_with(%{viewer_file: @file_a, viewer_siblings: [@file_a]})
      )

    assert socket.assigns.viewer_file == @file_a
  end

  # ── Echoes of the component's own steps ──────────────────────────────

  # Held ArrowRight: the component stepped to B, then to C, before B's echo
  # came back. Applying that echo as a command dragged the viewer back to B.
  test "the echo of a superseded step does not move the viewer backwards" do
    socket =
      socket_with(%{
        viewer_file: @file_b,
        viewer_siblings: [@file_a, @file_b],
        viewer_nav_echoes: ["img-a", "img-b"]
      })

    {:ok, socket} = MediaBrowser.update(%{nav_params: nav("img-a")}, socket)
    assert socket.assigns.viewer_file == @file_b
    assert socket.assigns.viewer_nav_echoes == ["img-b"]

    {:ok, socket} = MediaBrowser.update(%{nav_params: nav("img-b")}, socket)
    assert socket.assigns.viewer_file == @file_b
    assert socket.assigns.viewer_nav_echoes == []
  end

  test "a value the component did not emit still commands the viewer — Back mid-burst" do
    socket =
      socket_with(%{
        viewer_file: @file_b,
        viewer_siblings: [@file_a, @file_b],
        viewer_nav_echoes: ["img-a", "img-b"]
      })

    {:ok, socket} = MediaBrowser.update(%{nav_params: nav(nil)}, socket)

    assert socket.assigns.viewer_file == nil
    assert socket.assigns.viewer_nav_echoes == []
  end

  # An echo the host dropped leaves a stale entry. The newest echo is applied
  # like any outside value, so the stale entry cannot swallow a real command.
  test "a lone pending echo is applied, not skipped" do
    socket =
      socket_with(%{
        viewer_file: @file_b,
        viewer_siblings: [@file_a, @file_b],
        viewer_nav_echoes: ["img-a"]
      })

    {:ok, socket} = MediaBrowser.update(%{nav_params: nav("img-a")}, socket)

    assert socket.assigns.viewer_file.file_uuid == "img-a"
  end

  # ── Viewer events announce the file so the URL follows ───────────────

  defp controlled(assigns),
    do: socket_with(Map.merge(%{id: "mb", on_navigate: :navigate, select_mode: false}, assigns))

  test "opening a file announces it" do
    {:noreply, _} =
      MediaBrowser.handle_event("click_file", %{"file-uuid" => "img-b"}, controlled(%{}))

    assert_received {MediaBrowser, "mb", {:navigate, %{file: "img-b", folder: nil}}}
  end

  test "closing announces the file's absence" do
    {:noreply, _} =
      MediaBrowser.handle_event(
        "close_viewer",
        %{},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a]})
      )

    assert_received {MediaBrowser, "mb", {:navigate, %{file: nil}}}
  end

  test "stepping announces the neighbour" do
    {:noreply, _} =
      MediaBrowser.handle_event(
        "step_viewer",
        %{"dir" => "next"},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a, @file_b]})
      )

    assert_received {MediaBrowser, "mb", {:navigate, %{file: "img-b"}}}
  end

  test "each announcement is remembered until its echo returns" do
    {:noreply, socket} =
      MediaBrowser.handle_event(
        "step_viewer",
        %{"dir" => "next"},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a, @file_b]})
      )

    assert socket.assigns.viewer_nav_echoes == ["img-b"]
  end

  # ── Gallery mode: the strip settled, the hook names the file ─────────

  test "gallery_go opens a file of the sibling list and announces it" do
    {:noreply, socket} =
      MediaBrowser.handle_event(
        "gallery_go",
        %{"uuid" => "img-b"},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a, @file_b]})
      )

    assert socket.assigns.viewer_file.file_uuid == "img-b"
    assert_received {MediaBrowser, "mb", {:navigate, %{file: "img-b"}}}
  end

  test "gallery_go names a file outside the sibling list: nothing opens, nothing is announced" do
    {:noreply, socket} =
      MediaBrowser.handle_event(
        "gallery_go",
        %{"uuid" => "elsewhere"},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a, @file_b]})
      )

    assert socket.assigns.viewer_file.file_uuid == "img-a"
    refute_received {MediaBrowser, _, {:navigate, _}}
  end

  test "gallery_go for the file already open is answered with nothing (the hook re-asks)" do
    {:noreply, socket} =
      MediaBrowser.handle_event(
        "gallery_go",
        %{"uuid" => "img-a"},
        controlled(%{viewer_file: @file_a, viewer_siblings: [@file_a, @file_b]})
      )

    assert socket.assigns.viewer_file.file_uuid == "img-a"
    refute_received {MediaBrowser, _, {:navigate, _}}
  end

  test "an uncontrolled host hears nothing — local state only, as before" do
    {:noreply, _} =
      MediaBrowser.handle_event(
        "click_file",
        %{"file-uuid" => "img-a"},
        socket_with(%{id: "mb", on_navigate: nil, select_mode: false})
      )

    refute_received {MediaBrowser, _, {:navigate, _}}
  end
end
