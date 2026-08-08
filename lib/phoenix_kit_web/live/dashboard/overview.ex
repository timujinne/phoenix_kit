defmodule PhoenixKitWeb.Live.Dashboard.Overview do
  @moduledoc """
  The LiveView half of the dashboard overview — the data and the message
  handling that back `PhoenixKitWeb.Components.Core.DashboardOverview`.

  Used by `/admin` (`PhoenixKitWeb.Live.Dashboard`), whose operator half the
  overview is. The deprecated `/dashboard`
  (`PhoenixKitWeb.Live.Dashboard.Index`) is a separate page and does NOT use
  this.

  ## Gate the DATA, not only the markup

  Hiding a card in HEEx is cosmetic — the operator aggregates would still have
  run. `assign_scope_gates/1` therefore decides FIRST and works SECOND: a
  visitor who may not see the statistics causes

    * no `Roles.get_extended_stats/0`, `Sessions.get_session_stats/0` or
      `Presence.get_presence_stats/0`,
    * no migration-version read,
    * and no `Events.subscribe_to_*` at all,

  and the six statistics assigns are set to `nil`.

  ## One gate site, re-run on every scope change

  Every scope-derived assign on this page — `:can_access_admin_area?`, the six
  card gates, `:show_statistics`, the six statistics assigns — is computed in
  `assign_scope_gates/1` and NOWHERE else. Mount calls it through
  `assign_overview/3`; a mid-session permission change calls it through
  `phoenix_kit_scope_changed/1`, the callback `use` injects and
  `PhoenixKitWeb.Users.Auth`'s scope-refresh hook invokes right after it
  reassigns `:phoenix_kit_current_scope`. A gate added to that function is
  therefore recomputed for free, and cannot be the one that gets forgotten.

  This matters because `/admin` is the guaranteed landing: a visitor is NOT
  evicted from it when their rights change, so the page has to survive the
  change in place. Without recomputation a revoked operator kept a card
  pointing at a page that now rejects them, beside a sidebar (which re-derives
  every render) that disagreed.

  The statistics **subscriptions** move in both directions with the gate:
  `sync_statistics_subscription/2` subscribes a visitor who gains the rights
  mid-session and unsubscribes one who loses them. An unsubscribe, not just a
  hidden card — a hidden card still costs three aggregates per broadcast.
  `PhoenixKit.Admin.Events` had no unsubscribe counterpart before this page
  needed one; it does now (`unsubscribe_from_stats/0` and friends), because
  PhoenixKit runs its own PubSub instance and a caller cannot reach
  `Phoenix.PubSub.unsubscribe/2` for it.

  `refresh_statistics/1` re-derives the verdict from the CURRENT scope rather
  than trusting `:show_statistics`, because `phx-click` events are
  client-supplied — the button being hidden is not a guarantee that the event
  cannot arrive.

  ## Visibility rules

  | Block | Gate |
  |---|---|
  | Users / Roles / Sessions / Live Activity / Add User cards | `PhoenixKitWeb.Users.Auth.can_access_admin_view?/2` on each card's destination LiveView |
  | Email card | the module being loaded and enabled, AND `can_access_admin_view?/2` on its admin LiveView |
  | Platform Statistics, System Information, Refresh | `Scope.holds_all_enabled_permissions?/1` |

  The card rule is derived, never restated: the card and the page it links to
  ask the same function, so "a card is visible iff the visitor can open it"
  holds by construction. The statistics have no destination LiveView to derive
  from, so they use the role-agnostic "can reach everything" check — the same
  posture the unmapped-admin-view fallback takes.

  ## Usage

      use PhoenixKitWeb.Live.Dashboard.Overview

      def mount(_params, session, socket) do
        {:ok, Overview.assign_overview(socket, session, Routes.path("/admin"))}
      end

  `use` injects three things: `handle_event("refresh_stats", …)`, ONE
  `handle_info/2` clause guarded by `is_overview_message/1`, and the
  `phoenix_kit_scope_changed/1` callback described above.

  That single guarded clause replaced nine shape-matched ones deliberately. A
  socket can still be handed a message from a topic it has just left — the
  unsubscribe and the broadcast race — and it will also see any FUTURE arity of
  a message it does subscribe to. Nine exact-shape clauses turn either into an
  unmatched `handle_info` and a crashed LiveView. The guard matches on the
  message TAG alone and `apply_statistics_message/2` ends in a catch-all, so an
  in-flight or reshaped message is a no-op rather than a crash — and, because
  that function re-checks the gate first, never an operator query on behalf of
  someone who just lost the permission.

  The guard is deliberately narrow: it names ten tags and nothing else, so a
  host LiveView keeps full control of every other message. It does mean any
  additional `handle_event`/`handle_info` clauses must be defined together with
  these (Elixir warns when clauses of one function are not grouped, and
  `mix precommit` compiles with `--warnings-as-errors`).

  The attrs are passed to the component one by one rather than via a
  `Map.take/2` spread: an explicit attr keeps LiveView's change tracking, so a
  presence update re-sends only the tile that changed instead of the whole
  overview.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  import Phoenix.Component, only: [assign: 3]
  import Phoenix.LiveView, only: [connected?: 1, get_connect_info: 2, put_flash: 3]

  alias PhoenixKit.Admin.{Events, Presence}
  alias PhoenixKit.Migrations.Postgres, as: Migrations
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.{Roles, Sessions}
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKitWeb.Users.Auth

  # Assign name → the LiveView the card links to. The gate is the destination's
  # own admin-view gate, so this list carries no permission knowledge of its own
  # and cannot drift from what the destination enforces. Note `Add User` is
  # `PhoenixKitWeb.Users.UserForm` — NOT under `Live.Users`.
  @card_views [
    show_users_card: PhoenixKitWeb.Live.Users.Users,
    show_roles_card: PhoenixKitWeb.Live.Users.Roles,
    show_sessions_card: PhoenixKitWeb.Live.Users.Sessions,
    show_live_activity_card: PhoenixKitWeb.Live.Users.LiveSessions,
    show_add_user_card: PhoenixKitWeb.Users.UserForm
  ]

  # The Emails module ships as a separate package. Held as plain atoms (and
  # called through `apply/3`) so core still compiles when it is absent.
  @emails_module PhoenixKit.Modules.Emails
  @emails_admin_view PhoenixKit.Modules.Emails.Web.Emails

  # Assign tracking whether THIS socket currently holds the three statistics
  # subscriptions. `Phoenix.PubSub` subscriptions are idempotent, but the
  # unsubscribe direction is not knowable without it, and a bare
  # "subscribe again on every scope change" would leave a revoked visitor
  # subscribed forever.
  @subscribed_assign :phoenix_kit_overview_subscribed?

  # Every message tag the three statistics topics carry. The guard below matches
  # on the tag ALONE — never on arity — so a broadcast that grows a field stays
  # handled (as a no-op) instead of crashing the LiveView.
  @overview_message_tags [
    :stats_updated,
    :sessions_stats_updated,
    :session_created,
    :session_revoked,
    :user_sessions_revoked,
    :presence_stats_updated,
    :anonymous_session_connected,
    :anonymous_session_disconnected,
    :user_session_connected,
    :user_session_disconnected
  ]

  @doc """
  Whether `message` is a broadcast from one of the three statistics topics.

  Guards the single `handle_info/2` clause `use` injects. Tag-only by design:
  see the "Usage" section of the module documentation for why matching the
  full shape is a crash waiting for a downgrade or a schema change.
  """
  defguard is_overview_message(message)
           when is_tuple(message) and tuple_size(message) >= 1 and
                  elem(message, 0) in @overview_message_tags

  @doc """
  Whether `scope` may see the operator statistics — Platform Statistics, System
  Information and the Refresh button.

  These blocks have no destination LiveView to derive a gate from, so they use
  the role-agnostic "holds every grantable permission" check rather than a role
  name. `nil` scope → `false`.
  """
  @spec statistics_visible?(Scope.t() | nil) :: boolean()
  def statistics_visible?(scope), do: Scope.holds_all_enabled_permissions?(scope)

  @doc """
  Mount-time entry point: tracks the visitor's presence on `page_path`, then
  computes every gate through `assign_scope_gates/1`.

  `page_path` is the page the caller actually serves — it is reported to
  `Presence` as the visitor's `current_page`, and the Live Activity page reads
  it back, so it belongs to the caller rather than being hardcoded here. Pass
  an already-resolved path (`PhoenixKit.Utils.Routes.path/1`).

  Presence tracking is the one thing here that happens ONCE per mount rather
  than on every scope change — it reports where the socket is, which a
  permission change does not alter.
  """
  @spec assign_overview(Phoenix.LiveView.Socket.t(), map(), String.t()) ::
          Phoenix.LiveView.Socket.t()
  def assign_overview(socket, session, page_path) do
    if connected?(socket) do
      track_authenticated_session(socket, session, page_path)
    end

    assign_scope_gates(socket)
  end

  @doc """
  Computes EVERY scope-derived assign on the dashboard from
  `:phoenix_kit_current_scope`, and reconciles the statistics subscriptions
  with the verdict.

  The single gate site. Called from `assign_overview/3` at mount and from
  `phoenix_kit_scope_changed/1` whenever a permission change reassigns the
  scope under a live socket, so the page never renders a gate that predates the
  visitor's current rights. Idempotent: calling it with an unchanged scope
  re-derives the same values and leaves the subscriptions alone.
  """
  @spec assign_scope_gates(Phoenix.LiveView.Socket.t()) :: Phoenix.LiveView.Socket.t()
  def assign_scope_gates(socket) do
    scope = socket.assigns[:phoenix_kit_current_scope]
    show_statistics = statistics_visible?(scope)

    socket
    |> sync_statistics_subscription(show_statistics)
    |> assign_card_gates(scope)
    # The page's coarsest gate: it drives the header subtitle and is what
    # "this visitor sees the welcome block and nothing else" hangs off. It
    # lives here rather than in the page's own `mount/3` so that there is
    # exactly ONE function to add the next gate to.
    |> assign(:can_access_admin_area?, Scope.can_access_admin_area?(scope))
    |> assign(:show_statistics, show_statistics)
    |> assign_statistics(show_statistics)
  end

  @doc """
  Re-runs the operator aggregates behind the Refresh button.

  Re-derives the verdict from the current scope rather than reading
  `:show_statistics`: the button is hidden for everyone else, but a hidden
  button does not stop a crafted `phx-click` from arriving, and these are
  exactly the queries the gate exists to withhold. (The assign would answer the
  same today — it is recomputed on every scope change — but a gate fed by
  client-triggered input should not depend on that staying true.)
  """
  @spec refresh_statistics(Phoenix.LiveView.Socket.t()) :: Phoenix.LiveView.Socket.t()
  def refresh_statistics(socket) do
    if statistics_visible?(socket.assigns[:phoenix_kit_current_scope]) do
      socket
      |> assign(:stats, Roles.get_extended_stats())
      |> assign(:session_stats, Sessions.get_session_stats())
      |> assign(:presence_stats, Presence.get_presence_stats())
      |> put_flash(:info, gettext("Statistics refreshed successfully"))
    else
      socket
    end
  end

  @doc """
  Applies one statistics/session/presence broadcast to the socket.

  The body of the single `handle_info/2` clause `use` injects. Two guarantees
  a set of exact-shape `handle_info` clauses could not give:

    * **it never crashes.** Any message the guard admits is handled — including
      one whose shape changed and one that arrived after this socket left the
      topic (unsubscribe races a broadcast already in flight). The fallback is
      a stale tile, not a dead LiveView.
    * **it never queries for someone who may not see the result.** The gate is
      re-checked before anything runs, so a revoked operator's in-flight
      messages cost nothing, and the three `reload_*` aggregates stop with the
      permission rather than with the socket.
  """
  @spec apply_statistics_message(Phoenix.LiveView.Socket.t(), tuple()) ::
          Phoenix.LiveView.Socket.t()
  def apply_statistics_message(socket, message) do
    # `:show_statistics` is derived in exactly one place and recomputed on every
    # scope change, so it is the current verdict — not the mount-time snapshot
    # it used to be. Read here rather than re-deriving from the scope because
    # presence broadcasts are frequent and `statistics_visible?/1` walks the
    # enabled-module set.
    if socket.assigns[:show_statistics] do
      apply_visible_statistics_message(socket, message)
    else
      socket
    end
  end

  defp apply_visible_statistics_message(socket, {:stats_updated, stats}),
    do: assign(socket, :stats, stats)

  defp apply_visible_statistics_message(socket, {:sessions_stats_updated, session_stats}),
    do: assign(socket, :session_stats, session_stats)

  defp apply_visible_statistics_message(socket, {:presence_stats_updated, presence_stats}),
    do: assign(socket, :presence_stats, presence_stats)

  # Individual session mutations (a new login, a single revoke, or a "revoke
  # all/others") change the counts the dashboard shows but carry no aggregate of
  # their own, so the tiles are re-read.
  defp apply_visible_statistics_message(socket, {:session_created, _user, _token_info}),
    do: reload_session_stats(socket)

  defp apply_visible_statistics_message(socket, {:session_revoked, _token_uuid}),
    do: reload_session_stats(socket)

  defp apply_visible_statistics_message(socket, {:user_sessions_revoked, _user_uuid, _count}),
    do: reload_session_stats(socket)

  defp apply_visible_statistics_message(socket, {:anonymous_session_connected, _id, _metadata}),
    do: reload_presence_stats(socket)

  defp apply_visible_statistics_message(socket, {:anonymous_session_disconnected, _id}),
    do: reload_presence_stats(socket)

  defp apply_visible_statistics_message(socket, {:user_session_connected, _uuid, _metadata}),
    do: reload_presence_stats(socket)

  defp apply_visible_statistics_message(socket, {:user_session_disconnected, _uuid, _session_id}),
    do: reload_presence_stats(socket)

  # A tag we subscribe to, in a shape we do not know. Ignoring it leaves a tile
  # one broadcast stale until the next one; matching nothing would end the
  # LiveView.
  defp apply_visible_statistics_message(socket, _message), do: socket

  defp reload_session_stats(socket),
    do: assign(socket, :session_stats, Sessions.get_session_stats())

  defp reload_presence_stats(socket),
    do: assign(socket, :presence_stats, Presence.get_presence_stats())

  # Brings this socket's statistics subscriptions in line with
  # `show_statistics`. Both directions matter and neither is the mount case:
  #
  #   * a visitor GRANTED the rights mid-session subscribes here, so the tiles
  #     they can now see go live without a reload;
  #   * a visitor whose rights are REVOKED unsubscribes here — the messages stop
  #     arriving at all, rather than arriving and being dropped by a hidden card
  #     while three aggregates run per broadcast.
  #
  # Subscribing needs a connected socket (a dead render has no process worth
  # subscribing); unsubscribing does not check, so a socket that holds the
  # subscriptions always releases them.
  #
  # Exposed as `@doc false def` so both directions are unit-testable without a
  # database — the granted direction otherwise reaches `assign_scope_gates/1`'s
  # aggregates, which by definition need one. Not part of the public API.
  @doc false
  @spec sync_statistics_subscription(Phoenix.LiveView.Socket.t(), boolean()) ::
          Phoenix.LiveView.Socket.t()
  def sync_statistics_subscription(socket, show_statistics) do
    subscribed? = socket.assigns[@subscribed_assign] == true
    want? = show_statistics and connected?(socket)

    cond do
      want? and not subscribed? ->
        Events.subscribe_to_stats()
        Events.subscribe_to_sessions()
        Events.subscribe_to_presence()
        assign(socket, @subscribed_assign, true)

      subscribed? and not want? ->
        Events.unsubscribe_from_stats()
        Events.unsubscribe_from_sessions()
        Events.unsubscribe_from_presence()
        assign(socket, @subscribed_assign, false)

      true ->
        assign(socket, @subscribed_assign, subscribed?)
    end
  end

  defp assign_card_gates(socket, scope) do
    socket =
      Enum.reduce(@card_views, socket, fn {assign_key, view}, acc ->
        assign(acc, assign_key, Auth.can_access_admin_view?(scope, view))
      end)

    assign(socket, :show_email_card, show_email_card?(scope))
  end

  # The module has to be present and switched on (the check this card has always
  # carried), AND the visitor has to hold what its admin page requires.
  #
  # `apply/3` rather than a direct call (the form the template used, kept for
  # the same reason): a compile-time remote call to a module core does not
  # depend on warns "is not available or is yet to be defined", and
  # `mix precommit` compiles with `--warnings-as-errors`. Binding the module to
  # a variable first does NOT dodge it — the compiler constant-folds it back.
  defp show_email_card?(scope) do
    # credo:disable-for-next-line Credo.Check.Refactor.Apply
    Code.ensure_loaded?(@emails_module) and apply(@emails_module, :enabled?, []) and
      Auth.can_access_admin_view?(scope, @emails_admin_view)
  end

  defp assign_statistics(socket, true) do
    socket
    |> assign(:stats, Roles.get_extended_stats())
    |> assign(:session_stats, Sessions.get_session_stats())
    |> assign(:presence_stats, Presence.get_presence_stats())
    |> assign(:phoenix_kit_version, to_string(Application.spec(:phoenix_kit, :vsn)))
    |> assign(:migration_current, Migrations.current_version())
    |> assign(:migration_db, Migrations.migrated_version_runtime(%{prefix: "public"}))
  end

  defp assign_statistics(socket, false) do
    socket
    |> assign(:stats, nil)
    |> assign(:session_stats, nil)
    |> assign(:presence_stats, nil)
    |> assign(:phoenix_kit_version, nil)
    |> assign(:migration_current, nil)
    |> assign(:migration_db, nil)
  end

  defp track_authenticated_session(socket, session, page_path) do
    scope = socket.assigns[:phoenix_kit_current_scope]

    if scope && Scope.authenticated?(scope) do
      # Create a user map for tracking (uuid required by SimplePresence)
      user = %{uuid: Scope.user_uuid(scope), email: Scope.user_email(scope)}
      session_id = session["live_socket_id"] || generate_session_id()

      Presence.track_user(user, %{
        connected_at: UtilsDate.utc_now(),
        session_id: session_id,
        ip_address: IpAddress.extract_from_socket(socket),
        user_agent: get_connect_info(socket, :user_agent),
        current_page: page_path
      })
    end
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.encode64()
  end

  @doc """
  Injects the statistics event clause, the statistics message clause and the
  scope-change callback into a dashboard LiveView.

  See the module documentation for what this means for a host LiveView that
  defines `handle_event/3` or `handle_info/2` clauses of its own.
  """
  defmacro __using__(_opts) do
    quote do
      require unquote(__MODULE__)

      # Invoked by `PhoenixKitWeb.Users.Auth`'s scope-refresh hook right after
      # it reassigns `:phoenix_kit_current_scope`, so a permission change is
      # reflected on the page the visitor is already sitting on. Exporting this
      # function is the whole opt-in — the hook looks for nothing else.
      @doc false
      def phoenix_kit_scope_changed(socket) do
        unquote(__MODULE__).assign_scope_gates(socket)
      end

      @impl true
      def handle_event("refresh_stats", _params, socket) do
        {:noreply, unquote(__MODULE__).refresh_statistics(socket)}
      end

      @impl true
      def handle_info(message, socket)
          when unquote(__MODULE__).is_overview_message(message) do
        {:noreply, unquote(__MODULE__).apply_statistics_message(socket, message)}
      end
    end
  end
end
