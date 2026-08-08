defmodule PhoenixKitWeb.Live.Dashboard.OverviewTest do
  @moduledoc """
  The data half of `/admin`'s operator overview.

  The claim under test is "decide FIRST, query SECOND": a visitor who may not
  see the statistics must cost nothing — no aggregate, no migration read, no
  PubSub subscription. That is exactly what makes `/admin` safe as the landing
  page for every authenticated visitor.

  DB-free by construction: every scope here is denied the statistics, and the
  denial is what stops the queries. The permitted path is covered by the
  integration suite (it is, by definition, the one that talks to the database).
  """
  use ExUnit.Case, async: false

  alias Phoenix.LiveView.Socket
  alias PhoenixKit.PubSub.Manager
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Permissions
  alias PhoenixKitWeb.Live.Dashboard.Overview

  @stats_topic "phoenix_kit:admin:stats"

  # The three topics `sync_statistics_subscription/2` joins and leaves together.
  @all_topics [
    "phoenix_kit:admin:stats",
    "phoenix_kit:admin:sessions",
    "phoenix_kit:admin:presence"
  ]

  @statistics_assigns [
    :stats,
    :session_stats,
    :presence_stats,
    :phoenix_kit_version,
    :migration_current,
    :migration_db
  ]

  @card_assigns [
    :show_users_card,
    :show_roles_card,
    :show_sessions_card,
    :show_live_activity_card,
    :show_add_user_card,
    :show_email_card
  ]

  defp scope(roles, permissions, opts \\ []) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000b2", email: "gate@example.com"},
      authenticated?: Keyword.get(opts, :authenticated?, true),
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  defp plain_user_scope(opts \\ []), do: scope(["User"], [], opts)
  defp client_scope(opts \\ []), do: scope(["Client"], ["client_portal", "notifications"], opts)
  defp owner_scope, do: scope(["Owner"], Permissions.all_module_keys())

  # A disconnected socket: `connected?/1` is false, so `assign_overview/3`
  # takes neither the subscribe nor the presence-tracking branch. That is the
  # dead render every LiveView performs first.
  defp socket(scope) do
    %Socket{assigns: %{__changed__: %{}, phoenix_kit_current_scope: scope}}
  end

  describe "statistics_visible?/1" do
    test "a visitor with no permissions cannot see the operator statistics" do
      refute Overview.statistics_visible?(plain_user_scope())
      refute Overview.statistics_visible?(nil)
      refute Overview.statistics_visible?(%Scope{})
    end

    test "a partial permission holder cannot either — a Client is not an operator" do
      refute Overview.statistics_visible?(client_scope())
      refute Overview.statistics_visible?(scope(["Editor"], ["users", "media"]))
    end

    test "a full-access scope can" do
      assert Overview.statistics_visible?(owner_scope())
      assert Overview.statistics_visible?(scope(["Support"], ["*"]))
    end
  end

  describe "assign_overview/3 for a visitor who may not see the statistics" do
    test "a permission-less visitor gets no cards and no statistics" do
      socket = Overview.assign_overview(socket(plain_user_scope()), %{}, "/admin")

      refute socket.assigns.show_statistics

      for key <- @card_assigns do
        refute socket.assigns[key], "#{key} should be hidden from a permission-less visitor"
      end
    end

    test "a Client sees no operator card and no statistics either" do
      # `can_access_admin_area?/1` is TRUE for any single-permission holder, so
      # a Client passes the coarse gate and mounts. Every block below is
      # nonetheless withheld: the cards because it holds none of their keys,
      # the statistics because they need `holds_all_enabled_permissions?/1`.
      assert Scope.can_access_admin_area?(client_scope())

      socket = Overview.assign_overview(socket(client_scope()), %{}, "/admin")

      refute socket.assigns.show_statistics

      for key <- @card_assigns do
        refute socket.assigns[key], "#{key} should be hidden from a Client"
      end
    end

    test "the statistics assigns are nil, so nothing was queried to produce them" do
      for scope <- [plain_user_scope(), client_scope(), nil] do
        socket = Overview.assign_overview(socket(scope), %{}, "/admin")

        for key <- @statistics_assigns do
          assert socket.assigns[key] == nil, "#{key} was computed for a scope that cannot see it"
        end
      end
    end
  end

  describe "assign_overview/3 subscriptions" do
    test "a connected visitor who may not see the statistics subscribes to nothing" do
      # `transport_pid` is what `connected?/1` reads, so this exercises the live
      # branch. `authenticated?: false` keeps presence tracking out of it —
      # `get_connect_info/2` needs a real LiveView socket.
      connected = %Socket{
        socket(plain_user_scope(authenticated?: false))
        | transport_pid: self()
      }

      Overview.assign_overview(connected, %{}, "/admin")

      Manager.broadcast(@stats_topic, {:stats_updated, :should_not_arrive})
      refute_receive {:stats_updated, :should_not_arrive}, 100
    end

    test "control: the broadcast this test relies on does reach a subscriber" do
      Manager.subscribe(@stats_topic)
      on_exit(fn -> Manager.unsubscribe(@stats_topic) end)

      Manager.broadcast(@stats_topic, {:stats_updated, :control})
      assert_receive {:stats_updated, :control}, 100
    end
  end

  # A permission change under a live socket. `/admin` is the one admin page
  # nobody is evicted from, so a revoked operator keeps the page — and every
  # gate on it has to move with the permission instead of staying at its
  # mount-time value.
  describe "assign_scope_gates/1 after a downgrade" do
    test "every gate flips false and every statistic goes back to nil" do
      socket = Overview.assign_scope_gates(downgraded_socket())

      refute socket.assigns.can_access_admin_area?
      refute socket.assigns.show_statistics

      for key <- @card_assigns do
        refute socket.assigns[key], "#{key} survived the downgrade"
      end

      for key <- @statistics_assigns do
        assert socket.assigns[key] == nil, "#{key} still holds data the visitor may not see"
      end
    end

    test "the subscriptions are released, not just the cards hidden" do
      # Subscribe as the socket process would have, then hand the function a
      # socket that says so. A hidden card still costs three aggregates per
      # broadcast, so the messages have to stop arriving at all.
      for topic <- @all_topics, do: Manager.subscribe(topic)
      on_exit(fn -> for topic <- @all_topics, do: Manager.unsubscribe(topic) end)

      socket = Overview.assign_scope_gates(downgraded_socket())

      refute socket.assigns[:phoenix_kit_overview_subscribed?]

      for topic <- @all_topics do
        Manager.broadcast(topic, {:stats_updated, :after_downgrade})
        refute_receive {:stats_updated, :after_downgrade}, 100
      end
    end
  end

  # Both directions of the subscription, driven directly: the "gains the rights"
  # direction cannot go through `assign_scope_gates/1` here, because a scope that
  # may see the statistics is by definition the one that queries for them.
  describe "sync_statistics_subscription/2" do
    test "a visitor granted the rights mid-session starts receiving all three feeds" do
      on_exit(fn -> for topic <- @all_topics, do: Manager.unsubscribe(topic) end)

      socket = Overview.sync_statistics_subscription(connected_socket(), true)

      assert socket.assigns[:phoenix_kit_overview_subscribed?]

      for topic <- @all_topics do
        Manager.broadcast(topic, {:stats_updated, {:granted, topic}})
        assert_receive {:stats_updated, {:granted, ^topic}}, 100
      end
    end

    test "a visitor who loses them stops receiving them" do
      subscribed = Overview.sync_statistics_subscription(connected_socket(), true)
      socket = Overview.sync_statistics_subscription(subscribed, false)

      refute socket.assigns[:phoenix_kit_overview_subscribed?]

      for topic <- @all_topics do
        Manager.broadcast(topic, {:stats_updated, :revoked})
        refute_receive {:stats_updated, :revoked}, 100
      end
    end

    test "a dead render subscribes to nothing even for a permitted scope" do
      socket = Overview.sync_statistics_subscription(socket(owner_scope()), true)

      refute socket.assigns[:phoenix_kit_overview_subscribed?]

      Manager.broadcast(@stats_topic, {:stats_updated, :dead_render})
      refute_receive {:stats_updated, :dead_render}, 100
    end
  end

  describe "refresh_statistics/1" do
    test "asks the CURRENT scope, not the :show_statistics assign" do
      # The Refresh button is hidden for this visitor, but `phx-click` is client
      # supplied. A stale `true` must not buy them the three aggregates — and
      # this suite has no database, so a query here would fail loudly.
      socket = %Socket{
        socket(plain_user_scope())
        | assigns:
            Map.merge(socket(plain_user_scope()).assigns, %{
              show_statistics: true,
              stats: :stale,
              flash: %{}
            })
      }

      refreshed = Overview.refresh_statistics(socket)

      assert refreshed.assigns.stats == :stale
      assert refreshed.assigns.flash == %{}
    end
  end

  # The injected `handle_info/2` clause matches on the message TAG alone and
  # ends in a catch-all, because a socket can be handed a statistics message it
  # no longer wants: unsubscribing races a broadcast already in flight.
  describe "apply_statistics_message/2" do
    test "a message that arrives after the downgrade is dropped, not applied" do
      socket = gates_socket(plain_user_scope(), %{show_statistics: false, session_stats: nil})

      # `{:session_created, …}` would otherwise re-read the session aggregate.
      # No database here, so surviving this call is the assertion.
      assert Overview.apply_statistics_message(socket, {:session_created, :user, :info}) == socket
      assert Overview.apply_statistics_message(socket, {:stats_updated, %{total: 3}}) == socket
    end

    test "a permitted visitor still gets the broadcast applied" do
      socket = gates_socket(owner_scope(), %{show_statistics: true, stats: nil})

      applied = Overview.apply_statistics_message(socket, {:stats_updated, %{total_users: 4}})

      assert applied.assigns.stats == %{total_users: 4}
    end

    test "a known tag in an UNKNOWN shape is a no-op, never a crash" do
      # The nine exact-shape clauses this replaced would have raised
      # FunctionClauseError and taken the LiveView with them.
      socket = gates_socket(owner_scope(), %{show_statistics: true, session_stats: :untouched})

      assert Overview.apply_statistics_message(socket, {:session_created, 1, 2, 3, 4}) == socket
      assert Overview.apply_statistics_message(socket, {:session_revoked}) == socket
    end
  end

  # `PhoenixKitWeb.Live.Dashboard` is the one `use`r of this module, so the
  # injected clauses are pinned through it.
  describe "the clauses `use` injects" do
    alias PhoenixKitWeb.Live.Dashboard

    test "the scope-change callback the auth hook looks for is exported" do
      # `Code.ensure_loaded?/1` first, exactly as
      # `PhoenixKitWeb.Users.Auth.refresh_view_scope_assigns/1` does it:
      # `function_exported?/2` answers false for a module that has merely not
      # been loaded yet, which is a real condition under a release and — as this
      # test found the hard way — under a test run whose order happens not to
      # have touched the page first.
      assert Code.ensure_loaded?(Dashboard)
      assert function_exported?(Dashboard, :phoenix_kit_scope_changed, 1)
    end

    test "it routes to assign_scope_gates/1" do
      socket = Dashboard.phoenix_kit_scope_changed(downgraded_socket())

      refute socket.assigns.can_access_admin_area?
      refute socket.assigns.show_statistics
    end

    test "a statistics message of an unexpected arity does not crash the LiveView" do
      socket = gates_socket(owner_scope(), %{show_statistics: true})

      assert {:noreply, ^socket} =
               Dashboard.handle_info({:user_sessions_revoked, 1, 2, 3}, socket)
    end

    test "a message that is not ours is left to the host LiveView" do
      # The guard names ten tags and nothing else — no catch-all was injected,
      # so an unrelated message still falls through to the page's own clauses
      # (here: none, hence the raise).
      socket = gates_socket(owner_scope(), %{show_statistics: true})

      assert_raise FunctionClauseError, fn ->
        Dashboard.handle_info({:something_the_host_owns, :payload}, socket)
      end
    end
  end

  # A socket carrying the assigns a mount made while the visitor WAS an
  # operator, plus a scope that has since lost everything — the state
  # `handle_scope_refresh/2` hands to the page.
  defp downgraded_socket do
    gates_socket(plain_user_scope(), %{
      can_access_admin_area?: true,
      show_statistics: true,
      show_users_card: true,
      show_roles_card: true,
      stats: %{total_users: 12},
      session_stats: %{active: 3},
      presence_stats: %{online: 1},
      phoenix_kit_version: "1.0.0",
      migration_current: 1,
      migration_db: 1,
      phoenix_kit_overview_subscribed?: true
    })
  end

  defp gates_socket(scope, extra) do
    %Socket{
      assigns: Map.merge(%{__changed__: %{}, phoenix_kit_current_scope: scope}, extra)
    }
  end

  # `connected?/1` reads `transport_pid`; `Manager.subscribe/1` subscribes the
  # CALLING process, which in these tests is the test process itself.
  defp connected_socket do
    %Socket{socket(owner_scope()) | transport_pid: self()}
  end
end
