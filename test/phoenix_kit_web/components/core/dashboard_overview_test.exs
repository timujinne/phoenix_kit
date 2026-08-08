defmodule PhoenixKitWeb.Components.Core.DashboardOverviewTest do
  @moduledoc """
  The operator half of `/admin`, block by block.

  `/admin` is the landing page every authenticated visitor reaches, so the
  interesting case is the one where every gate is shut: the component must then
  render NOTHING — not an empty wrapper, and above all not a statistics block
  reading `nil` aggregates.

  DB-free: the component takes booleans and plain maps.
  """
  use ExUnit.Case, async: true

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  alias PhoenixKitWeb.Components.Core.DashboardOverview

  @stats %{
    owner_count: 1,
    admin_count: 2,
    total_users: 30,
    active_users: 25,
    inactive_users: 5,
    confirmed_users: 20,
    pending_users: 10,
    user_count: 27
  }

  @session_stats %{
    total_active: 7,
    unique_users: 4,
    sessions_today: 3,
    expired_sessions: 2
  }

  @presence_stats %{
    total_sessions: 9,
    anonymous_sessions: 6,
    authenticated_sessions: 3,
    unique_anonymous_visitors: 5,
    active_authenticated_users: 2
  }

  # The real caller (`PhoenixKitWeb.Live.Dashboard.Overview.assign_overview/3`)
  # always supplies all seven gates as strict booleans, so that is the default
  # here; `nil` is passed only by the test that pins nil-tolerance.
  defp render_overview(gates, unset \\ false) do
    gate = fn key -> Keyword.get(gates, key, unset) end
    assigns = %{gate: gate, stats: statistics_for(gates)}

    ~H"""
    <DashboardOverview.dashboard_overview
      show_users_card={@gate.(:users)}
      show_roles_card={@gate.(:roles)}
      show_sessions_card={@gate.(:sessions)}
      show_live_activity_card={@gate.(:live_activity)}
      show_add_user_card={@gate.(:add_user)}
      show_email_card={@gate.(:email)}
      show_statistics={@gate.(:statistics)}
      stats={@stats.stats}
      session_stats={@stats.session_stats}
      presence_stats={@stats.presence_stats}
      phoenix_kit_version={@stats.version}
      migration_current={@stats.migration_current}
      migration_db={@stats.migration_db}
    />
    """
    |> rendered_to_string()
  end

  # A caller that hides the statistics is expected to leave the data `nil` —
  # producing it costs three aggregates and a migration read. Mirror that here
  # so the "hidden" cases prove the component never touches the maps.
  defp statistics_for(gates) do
    if gates[:statistics] do
      %{
        stats: @stats,
        session_stats: @session_stats,
        presence_stats: @presence_stats,
        version: "1.7.0",
        migration_current: 159,
        migration_db: 159
      }
    else
      %{
        stats: nil,
        session_stats: nil,
        presence_stats: nil,
        version: nil,
        migration_current: nil,
        migration_db: nil
      }
    end
  end

  defp all_off, do: []

  test "every gate shut renders nothing at all — not even a wrapper" do
    assert render_overview(all_off()) |> String.trim() == ""
  end

  test "every gate shut with nil statistics does not read the aggregate maps" do
    # The regression this pins: moving a `nil` guard from the data half to the
    # markup would blow up here with a KeyError on `nil.owner_count`.
    assert render_overview(all_off()) |> String.trim() == ""
  end

  test "an unset (nil) gate hides its block instead of raising" do
    # `attr :boolean` is only type-checked for literals, so a caller can hand a
    # gate a nil assign. On the page every authenticated visitor lands on, that
    # must hide the block, not crash the mount.
    assert render_overview(all_off(), nil) |> String.trim() == ""
    assert render_overview([statistics: true], nil) =~ "Platform Statistics"
  end

  test "a single card renders alone, with no statistics and no refresh button" do
    html = render_overview(users: true)

    assert html =~ "User management"
    refute html =~ "Role management"
    refute html =~ "Active sessions"
    refute html =~ "Real-time visitors"
    refute html =~ "Create new account"
    refute html =~ "Email logs"
    refute html =~ "Platform Statistics"
    refute html =~ "System Information"
    refute html =~ "refresh_stats"
  end

  test "each card gate controls exactly its own card" do
    for {gate, label} <- [
          users: "User management",
          roles: "Role management",
          sessions: "Active sessions",
          live_activity: "Real-time visitors",
          add_user: "Create new account",
          email: "Email logs"
        ] do
      assert render_overview([{gate, true}]) =~ label
      refute render_overview(all_off()) =~ label
    end
  end

  test "the statistics gate carries Platform Statistics, System Information AND refresh" do
    html = render_overview(statistics: true)

    assert html =~ "Platform Statistics"
    assert html =~ "System Information"
    assert html =~ "refresh_stats"
    assert html =~ "1.7.0"

    # ...and nothing that belongs to a card gate.
    refute html =~ "User management"
    refute html =~ "Role management"
  end

  test "statistics values reach the tiles" do
    html = render_overview(statistics: true)

    for value <- ["30", "25", "7", "9"] do
      assert html =~ ">#{value}<" or html =~ "#{value}"
    end
  end
end
