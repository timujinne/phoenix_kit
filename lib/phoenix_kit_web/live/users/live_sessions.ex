defmodule PhoenixKitWeb.Live.Users.LiveSessions do
  @moduledoc """
  Real-time session monitoring dashboard for the PhoenixKit admin panel.

  This module provides comprehensive real-time monitoring of:
  - All active sessions (anonymous + authenticated)
  - Live session statistics and metrics
  - Real-time connection/disconnection events
  - Session geographic distribution
  - Page activity heatmaps
  - User behavior patterns

  Features real-time updates via Phoenix LiveView and WebSocket connectivity.
  Only accessible to users with Owner or Admin roles.
  """
  use PhoenixKitWeb, :live_view

  # Search, filter, sort and page live in the query string, so a filtered list
  # is a real URL: shareable, reload-proof, and Back returns to the previous
  # query instead of leaving the page. `filter_type` defaults to "all", which
  # is therefore what gets omitted from the URL.
  #
  # Sort is carried as two flat params and recombined into the compound
  # `%{by:, dir:}` map that <.sort_header_cell sort={@sort}> expects — see
  # handle_url_state/2. The template keeps reading @sort and needs no edit.
  use PhoenixKitWeb.Live.UrlState,
    params: [
      search_query: [default: "", url_key: "q"],
      filter_type: [default: "all", url_key: "type"],
      sort_by: [default: :connected_at, cast: :atom, in: [:type, :connected_at], url_key: "sort"],
      sort_dir: [default: :desc, cast: :atom, in: [:asc, :desc], url_key: "dir"],
      page: [default: 1, cast: :integer, min: 1]
    ]

  alias PhoenixKit.Admin.{Events, Presence}
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKit.Utils.Pagination
  alias PhoenixKit.Utils.Routes

  # Refresh every 5 seconds
  @refresh_interval 5_000
  @per_page 20

  def mount(_params, session, socket) do
    # Subscribe to presence events for real-time updates
    if connected?(socket) do
      Events.subscribe_to_presence()
      Events.subscribe_to_stats()

      # Start auto-refresh timer
      schedule_refresh()

      # Track authenticated user session if logged in
      track_authenticated_session(socket, session)
    end

    # Get project title from settings
    project_title = Settings.get_project_title()

    # :page, :search_query and :filter_type are assigned from the query string
    # by UrlState before mount/3 runs — re-assigning them here would overwrite
    # a shared link's state with the defaults.
    socket =
      socket
      |> assign(:per_page, @per_page)
      |> assign(:page_title, gettext("Live Sessions"))
      |> assign(:project_title, project_title)
      |> assign(:auto_refresh, true)
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_stats()

    {:ok, socket}
  end

  # The list is loaded here rather than in mount/3: UrlState calls this after
  # mount and on every change to the query string, so one code path serves the
  # first render, a shared link, and the Back button alike.
  #
  # Deliberately not annotated with @impl — a single @impl anywhere in a module
  # makes Elixir demand it on every other callback too, and this LiveView's
  # mount/handle_event/handle_params/handle_info carry none.
  def handle_url_state(state, socket) do
    socket
    |> assign(:sort, %{by: state.sort_by, dir: state.sort_dir})
    |> load_sessions()
  end

  def handle_params(_params, _url, socket) do
    {:noreply, socket}
  end

  # `replace: true` — the box is debounced, so a typed-out query would
  # otherwise leave one history entry per pause and Back would walk the search
  # string backwards instead of leaving the page.
  def handle_event("search", %{"search" => search_query}, socket) do
    {:noreply, push_url_state(socket, [search_query: search_query], replace: true)}
  end

  def handle_event("filter_by", %{"type" => filter_type}, socket) do
    {:noreply, push_url_state(socket, filter_type: filter_type)}
  end

  def handle_event("toggle_sort", %{"by" => by}, socket) do
    %{by: sort_by, dir: sort_dir} = toggle_sort(socket.assigns.sort, parse_sort_by(by))

    {:noreply, push_url_state(socket, sort_by: sort_by, sort_dir: sort_dir)}
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {page, ""} when page > 0 -> {:noreply, push_url_state(socket, page: page)}
      _ -> {:noreply, socket}
    end
  end

  def handle_event("toggle_auto_refresh", _params, socket) do
    auto_refresh = !socket.assigns.auto_refresh

    if auto_refresh do
      schedule_refresh()
    end

    socket = assign(socket, :auto_refresh, auto_refresh)
    {:noreply, socket}
  end

  def handle_event("refresh_now", _params, socket) do
    socket =
      socket
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_sessions()
      |> load_stats()

    {:noreply, socket}
  end

  def handle_info(:refresh, socket) do
    if socket.assigns.auto_refresh do
      socket =
        socket
        |> assign(:last_updated, UtilsDate.utc_now())
        |> load_sessions()
        |> load_stats()

      schedule_refresh()
      {:noreply, socket}
    else
      {:noreply, socket}
    end
  end

  # Handle real-time presence events
  def handle_info({:anonymous_session_connected, _session_id, _metadata}, socket) do
    socket =
      socket
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_sessions()
      |> load_stats()

    {:noreply, socket}
  end

  def handle_info({:anonymous_session_disconnected, _session_id}, socket) do
    socket =
      socket
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_sessions()
      |> load_stats()

    {:noreply, socket}
  end

  def handle_info({:user_session_connected, _user_uuid, _metadata}, socket) do
    socket =
      socket
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_sessions()
      |> load_stats()

    {:noreply, socket}
  end

  def handle_info({:user_session_disconnected, _user_uuid, _session_id}, socket) do
    socket =
      socket
      |> assign(:last_updated, UtilsDate.utc_now())
      |> load_sessions()
      |> load_stats()

    {:noreply, socket}
  end

  def handle_info({:presence_stats_updated, stats}, socket) do
    socket =
      socket
      |> assign(:presence_stats, stats)
      |> assign(:last_updated, UtilsDate.utc_now())

    {:noreply, socket}
  end

  # Ignore other messages
  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_sessions(socket) do
    sessions = Presence.list_active_sessions()

    # Apply filters
    filtered_sessions =
      sessions
      |> filter_by_search(socket.assigns.search_query)
      |> filter_by_type(socket.assigns.filter_type)
      |> sort_sessions(socket.assigns.sort.by, socket.assigns.sort.dir)

    # Calculate pagination
    total_count = length(filtered_sessions)
    total_pages = Pagination.total_pages(total_count, socket.assigns.per_page)
    page = min(socket.assigns.page, total_pages)

    # Get page sessions
    page_sessions =
      filtered_sessions
      |> Enum.drop((page - 1) * socket.assigns.per_page)
      |> Enum.take(socket.assigns.per_page)

    # Preload users for avatar display
    users_map = preload_users_for_sessions(page_sessions)

    socket
    |> assign(:sessions, page_sessions)
    |> assign(:users_map, users_map)
    |> assign(:total_sessions, total_count)
    |> assign(:total_pages, total_pages)
    |> assign(:page, page)
  end

  defp preload_users_for_sessions(sessions) do
    user_uuids =
      sessions
      |> Enum.filter(&(&1.type == :authenticated))
      |> Enum.map(& &1.user_uuid)
      |> Enum.uniq()

    case user_uuids do
      [] -> %{}
      uuids -> Auth.get_users_by_uuids(uuids) |> Map.new(&{&1.uuid, &1})
    end
  end

  defp load_stats(socket) do
    stats = Presence.get_presence_stats()
    assign(socket, :presence_stats, stats)
  end

  defp filter_by_search(sessions, "") do
    sessions
  end

  defp filter_by_search(sessions, search_query) do
    query = String.downcase(search_query)

    Enum.filter(sessions, fn session ->
      String.contains?(String.downcase(session.ip_address || ""), query) ||
        String.contains?(String.downcase(session.user_agent || ""), query) ||
        String.contains?(String.downcase(session.current_page || ""), query) ||
        (session.user_email && String.contains?(String.downcase(session.user_email), query))
    end)
  end

  defp filter_by_type(sessions, "all"), do: sessions
  defp filter_by_type(sessions, "anonymous"), do: Enum.filter(sessions, &(&1.type == :anonymous))

  defp filter_by_type(sessions, "authenticated"),
    do: Enum.filter(sessions, &(&1.type == :authenticated))

  defp sort_sessions(sessions, sort_by, sort_order) do
    sessions
    |> Enum.sort_by(fn session -> Map.get(session, sort_by) end, sort_order)
  end

  defp parse_sort_by("type"), do: :type
  defp parse_sort_by("connected_at"), do: :connected_at
  defp parse_sort_by(_), do: :connected_at

  defp toggle_sort(%{by: by, dir: dir}, by), do: %{by: by, dir: flip_dir(dir)}
  defp toggle_sort(_, new_by), do: %{by: new_by, dir: :asc}

  defp flip_dir(:asc), do: :desc
  defp flip_dir(:desc), do: :asc

  defp schedule_refresh do
    Process.send_after(self(), :refresh, @refresh_interval)
  end

  defp track_authenticated_session(socket, session) do
    scope = socket.assigns[:phoenix_kit_current_scope]

    if scope && Scope.authenticated?(scope) do
      user_email = Scope.user_email(scope)

      # Create a user map for tracking (uuid required by SimplePresence)
      user = %{uuid: scope.user.uuid, email: user_email}
      session_id = session["live_socket_id"] || generate_session_id()

      Presence.track_user(user, %{
        connected_at: UtilsDate.utc_now(),
        session_id: session_id,
        ip_address: IpAddress.extract_from_socket(socket),
        user_agent: get_connect_info(socket, :user_agent),
        current_page: Routes.path("/admin/users/live_sessions")
      })
    end
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.encode64()
  end
end
