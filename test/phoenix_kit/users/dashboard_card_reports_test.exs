defmodule PhoenixKit.Users.DashboardCardReportsTest do
  @moduledoc """
  Every number on the admin dashboard links to the list behind it, and this
  file pins the property that makes those links worth having: **the report
  returns exactly what the card counted.**

  A filter that disagreed with the card above it would be worse than no link —
  the reader would click "3 Inactive Users" and be shown four, or none, with
  nothing on screen explaining the difference. So each test asserts the count
  from `Roles.get_extended_stats/0` (what the card shows) against the filtered
  query the card's link uses, rather than asserting either one in isolation.

  Integration: the predicates being checked are SQL, so an in-memory stand-in
  would test nothing.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Users.Sessions
  alias PhoenixKit.Utils.SessionFingerprint

  defp user_fixture(email, attrs \\ %{}) do
    {:ok, user} = Auth.register_user(%{email: email, password: "ValidPassword123!"})

    if attrs == %{} do
      user
    else
      user |> Ecto.Changeset.change(attrs) |> Repo.update!()
    end
  end

  defp listed_count(opts) do
    %{total_count: total} = Auth.list_users_paginated(Keyword.put(opts, :page_size, 1000))
    total
  end

  describe "user cards link to a list holding exactly what they counted" do
    test "Active Users / Inactive Users" do
      user_fixture("cards-active-1@example.com")
      user_fixture("cards-active-2@example.com")
      user_fixture("cards-inactive-1@example.com", %{is_active: false})

      stats = Roles.get_extended_stats()

      assert listed_count(status: "active") == stats.active_users
      assert listed_count(status: "inactive") == stats.inactive_users

      # And the split is real, not two names for the same set.
      assert stats.inactive_users > 0
      assert stats.active_users > 0
    end

    test "Email Confirmed / Pending Email" do
      now = DateTime.utc_now() |> DateTime.truncate(:second)
      user_fixture("cards-confirmed@example.com", %{confirmed_at: now})
      user_fixture("cards-pending-1@example.com")
      user_fixture("cards-pending-2@example.com")

      stats = Roles.get_extended_stats()

      assert listed_count(confirmation: "confirmed") == stats.confirmed_users
      assert listed_count(confirmation: "pending") == stats.pending_users

      assert stats.confirmed_users > 0
      assert stats.pending_users > 0
    end

    test "Total Users — an unfiltered link shows everyone" do
      user_fixture("cards-total-1@example.com")
      user_fixture("cards-total-2@example.com")

      assert listed_count([]) == Roles.get_extended_stats().total_users
    end

    test "an unknown filter value falls back to unfiltered rather than empty" do
      # These arrive from a query string. A hand-edited `?status=nonsense`
      # showing zero users reads as "you have no users", which is a worse lie
      # than ignoring the filter.
      user_fixture("cards-unknown@example.com")

      assert listed_count(status: "nonsense") == listed_count([])
      assert listed_count(confirmation: "nonsense") == listed_count([])
    end
  end

  describe "session cards link to a list holding exactly what they counted" do
    defp session_for(user, ip) do
      fp = %SessionFingerprint{ip_address: ip, user_agent_hash: String.duplicate("a", 64)}
      Auth.generate_user_session_token(user, fingerprint: fp)
    end

    test "Active Sessions" do
      user = user_fixture("cards-sessions@example.com")
      session_for(user, "203.0.113.60")
      session_for(user, "203.0.113.61")

      stats = Sessions.get_session_stats()

      assert length(Sessions.list_active_sessions(:active)) == stats.total_active
    end

    test "Today's Sessions" do
      user = user_fixture("cards-sessions-today@example.com")
      session_for(user, "203.0.113.62")

      stats = Sessions.get_session_stats()

      assert length(Sessions.list_active_sessions(:today)) == stats.sessions_today
    end

    test "Expired Sessions — the scope that had no report at all before" do
      # Linking this card at the ACTIVE list would have shown a set that
      # cannot contain a single expired row, which is the failure mode the
      # scope exists to avoid.
      stats = Sessions.get_session_stats()

      assert length(Sessions.list_active_sessions(:expired)) == stats.expired_sessions
    end

    test "an unknown scope falls back to :active" do
      user = user_fixture("cards-sessions-bad-scope@example.com")
      session_for(user, "203.0.113.63")

      assert length(Sessions.list_active_sessions(:nonsense)) ==
               length(Sessions.list_active_sessions(:active))
    end

    test "the default scope is :active, so existing callers are unchanged" do
      user = user_fixture("cards-sessions-default@example.com")
      session_for(user, "203.0.113.64")

      assert Sessions.list_active_sessions() == Sessions.list_active_sessions(:active)
    end
  end
end
