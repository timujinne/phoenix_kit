defmodule PhoenixKitWeb.Live.Activity.AccessTest do
  @moduledoc """
  The shared audit log at `/admin/activity`.

  Two guarantees pinned here:

    * Render tolerance — a structural change event carries a nested
      `%{"from" => _, "to" => _}` diff map; the feed used to interpolate it as a
      scalar and crash the whole page with `Protocol.UndefinedError`
      (String.Chars for Map). Legacy rows whose scalar was `inspect`-serialised
      ("Decimal.new(\\"1\\")") must read cleanly too.

    * Authorization — the full log is administrators-only. A non-admin
      dashboard-holder sees only their OWN actions, in the list AND via a direct
      entry URL; someone else's entry is treated as not-found.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Activity
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  setup do
    # The first account in a fresh sandbox is auto-promoted to Owner; burn one
    # so the users built below get exactly the rank each test asks for.
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  defp unique_email, do: "u#{System.unique_integer([:positive])}@example.com"

  defp confirmed_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    Repo.get!(Auth.User, user.uuid)
  end

  defp admin_user do
    user = confirmed_user()
    {:ok, _} = Roles.assign_role(user, "Admin")
    Repo.get!(Auth.User, user.uuid)
  end

  # A non-admin who can reach /admin/activity (holds `dashboard`) but does not
  # hold every permission — so they are scoped to their own actions.
  defp dashboard_only_user do
    user = confirmed_user()

    {:ok, role} =
      Roles.create_role(%{
        name: "ActivityDashboardOnly#{System.unique_integer([:positive])}",
        description: "dashboard access, nothing else"
      })

    {:ok, _} = Permissions.grant_permission(role.uuid, "dashboard")
    {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  defp log!(actor, action, metadata) do
    {:ok, entry} =
      Activity.log(%{
        action: action,
        module: "orders",
        actor_uuid: actor.uuid,
        resource_type: "order",
        resource_uuid: Ecto.UUID.generate(),
        metadata: metadata
      })

    entry
  end

  # An action `actor` performed ON/FOR `target` — `target` is the subject, not
  # the author. Used to pin that "own" is authorship, not being targeted.
  defp log_targeting!(actor, target, action, metadata) do
    {:ok, entry} =
      Activity.log(%{
        action: action,
        module: "users",
        actor_uuid: actor.uuid,
        target_uuid: target.uuid,
        resource_type: "user",
        resource_uuid: target.uuid,
        metadata: metadata
      })

    entry
  end

  describe "render tolerance" do
    test "a qty field-change diff renders as 1 → 2 instead of crashing", %{conn: conn} do
      admin = admin_user()

      log!(admin, "orders.row_updated", %{
        "item_name" => "Widget",
        "changes" => %{"qty" => %{"from" => "1", "to" => "2"}}
      })

      {:ok, _lv, html} = live(log_in_user(conn, admin), Routes.path("/admin/activity"))
      assert html =~ "1 → 2"
    end

    test "a legacy inspect-serialised Decimal reads as the bare number", %{conn: conn} do
      admin = admin_user()

      log!(admin, "orders.row_updated", %{"qty" => "Decimal.new(\"5\")"})

      {:ok, _lv, html} = live(log_in_user(conn, admin), Routes.path("/admin/activity"))
      assert html =~ "qty: 5"
      refute html =~ "Decimal.new"
    end
  end

  describe "authorization — list" do
    test "an administrator sees every user's actions", %{conn: conn} do
      admin = admin_user()
      other = confirmed_user()

      log!(other, "orders.created", %{"title" => "THEIRS"})
      log!(admin, "orders.created", %{"title" => "MINE"})

      {:ok, _lv, html} = live(log_in_user(conn, admin), Routes.path("/admin/activity"))
      assert html =~ "THEIRS"
      assert html =~ "MINE"
    end

    test "a dashboard-only user sees only their own actions", %{conn: conn} do
      user = dashboard_only_user()
      other = admin_user()

      log!(other, "orders.created", %{"title" => "THEIRS"})
      log!(user, "orders.created", %{"title" => "MINE"})

      {:ok, _lv, html} = live(log_in_user(conn, user), Routes.path("/admin/activity"))
      assert html =~ "MINE"
      refute html =~ "THEIRS"
    end
  end

  describe "authorization — single entry (direct URL)" do
    test "an administrator may open anyone's entry", %{conn: conn} do
      admin = admin_user()
      other = confirmed_user()
      entry = log!(other, "orders.created", %{"title" => "THEIRS"})

      {:ok, _lv, html} =
        live(log_in_user(conn, admin), Routes.path("/admin/activity/#{entry.uuid}"))

      assert html =~ "THEIRS"
    end

    test "a dashboard-only user may open their OWN entry", %{conn: conn} do
      user = dashboard_only_user()
      entry = log!(user, "orders.created", %{"title" => "MINE"})

      {:ok, _lv, html} =
        live(log_in_user(conn, user), Routes.path("/admin/activity/#{entry.uuid}"))

      assert html =~ "MINE"
    end

    test "a dashboard-only user is bounced from someone else's entry", %{conn: conn} do
      user = dashboard_only_user()
      other = admin_user()
      entry = log!(other, "orders.created", %{"title" => "THEIRS"})

      assert {:error, {:live_redirect, %{to: to}}} =
               live(log_in_user(conn, user), Routes.path("/admin/activity/#{entry.uuid}"))

      assert to =~ "/admin/activity"
    end
  end

  # "Own" is authorship (actor), not being the subject (target). A record where
  # the user is only the target must stay hidden from a non-administrator, in
  # both the list and via the direct URL — the definition Activity.own_entry?/2
  # fixes for both views.
  describe "own == actor, not target" do
    test "a dashboard-only user does NOT see an action merely targeting them", %{conn: conn} do
      user = dashboard_only_user()
      other = admin_user()

      log_targeting!(other, user, "users.profile_updated", %{"note" => "TARGETED"})
      log!(user, "orders.created", %{"title" => "AUTHORED"})

      {:ok, _lv, html} = live(log_in_user(conn, user), Routes.path("/admin/activity"))
      assert html =~ "AUTHORED"
      refute html =~ "TARGETED"
    end

    test "a dashboard-only user is bounced from an entry that only targets them", %{conn: conn} do
      user = dashboard_only_user()
      other = admin_user()
      entry = log_targeting!(other, user, "users.profile_updated", %{"note" => "TARGETED"})

      assert {:error, {:live_redirect, %{to: to}}} =
               live(log_in_user(conn, user), Routes.path("/admin/activity/#{entry.uuid}"))

      assert to =~ "/admin/activity"
    end
  end
end
