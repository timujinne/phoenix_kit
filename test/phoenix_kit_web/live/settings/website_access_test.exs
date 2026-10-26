defmodule PhoenixKitWeb.Live.Settings.WebsiteAccessTest do
  @moduledoc "The settings page, and the LiveView side of the gate."
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Maintenance
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.ViewPrefs
  alias PhoenixKit.Utils.Date, as: DateUtils
  alias PhoenixKit.WebsiteAccess
  alias PhoenixKit.WebsiteAccess.{AllowedAddresses, Gate, Redirect}
  alias PhoenixKitWeb.Plugs.WebsiteAccess, as: AccessPlug

  @page "/phoenix_kit/admin/settings/website-access"
  @probe "/__test/crawlers-no-index-probe"

  # What the LiveView socket learns about the connection: `:peer_data`, and
  # `:x_headers` when the endpoint passes them.
  defp connect_from(conn, ip, x_headers \\ []) do
    Plug.Conn.put_private(conn, :live_view_connect_info, %{
      peer_data: %{address: ip, port: 1, ssl_cert: nil},
      x_headers: x_headers
    })
  end

  setup %{conn: conn} do
    {:ok, _} = Gate.set_enabled(false)
    {:ok, _} = WebsiteAccess.set(:redirect, false, [])
    {:ok, _} = Maintenance.set_active(false)
    {:ok, _} = Crawlers.update_no_index(false)
    Settings.update_setting(Gate.password_key(), "")
    Settings.update_setting(Gate.link_key(), "")
    Settings.update_boolean_setting(Gate.users_pass_key(), true)
    Settings.update_setting(Gate.keep_typed_key(), "all")
    Settings.update_setting(Redirect.url_key(), "")
    Gate.clear_attempts()
    {user, _} = create_admin_user()
    {:ok, conn: log_in_user(conn, user), user: user}
  end

  describe "the page" do
    test "lists every feature with a switch", %{conn: conn} do
      {:ok, _view, html} = live(conn, @page)

      for key <- ~w(gate redirect maintenance no_index allowed_addresses) do
        assert html =~ ~s(id="feature-#{key}"), key
      end

      assert html =~ "Password gate"
    end

    # The boss asked for all three off this page (2026-09-08). Pinned so a
    # revert is a deliberate edit to this test, not a quiet re-appearance.
    test "carries no presets, no visitor notice and no environment banner", %{conn: conn} do
      {:ok, _view, html} = live(conn, @page)

      refute html =~ ~s(phx-click="apply_preset"), "presets"
      refute html =~ ~s(id="feature-notice"), "the visitor notice feature"
      refute html =~ "pk-notice-form", "the notice's form"
      refute html =~ "This install runs as", "the environment banner"
    end

    test "switching the gate on without a password says what it needs", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)

      html =
        view |> element(~s(#feature-gate input[phx-click="toggle_feature"])) |> render_click()

      assert html =~ "needs a password"
      assert Gate.switched_on?()
      refute Gate.enabled?()
    end

    test "saving a password closes the gate and the actor lands in the history", %{
      conn: conn,
      user: user
    } do
      {:ok, view, _} = live(conn, @page)
      view |> element(~s(#feature-gate input[phx-click="toggle_feature"])) |> render_click()

      html =
        view
        |> form("#pk-gate-form", %{
          "gate" => %{
            "password" => "Secret42",
            "lockout_attempts" => "5",
            "lockout_minutes" => "10",
            "users_pass" => "true"
          }
        })
        |> render_submit()

      assert html =~ "Password gate settings saved."
      assert Gate.enabled?()
      assert Gate.lockout_attempts() == 5
      assert Gate.lockout_minutes() == 10

      [entry | _] = Settings.History.list(Gate.enabled_key(), limit: 1)
      assert entry.actor_uuid == user.uuid
    end

    test "junk numbers in the gate form become the defaults or the nearest bound", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)

      view
      |> form("#pk-gate-form", %{
        "gate" => %{
          "password" => "",
          "lockout_attempts" => "abc",
          "lockout_minutes" => "99999",
          "keep_typed" => "near"
        }
      })
      |> render_submit()

      assert Gate.lockout_attempts() == 0
      assert Gate.lockout_minutes() == 1440
      assert Gate.keep_typed() == "near"

      # a forged choice the select does not offer is not stored
      render_submit(view, "save_gate", %{
        "gate" => %{
          "password" => "",
          "lockout_attempts" => "2",
          "lockout_minutes" => "5",
          "keep_typed" => "everything"
        }
      })

      assert Gate.keep_typed() == "all"
      assert Gate.lockout_attempts() == 2
    end

    test "a blank password keeps the current one", %{conn: conn} do
      {:ok, _} = Gate.set_password("Secret42")
      {:ok, view, _} = live(conn, @page)

      view
      |> form("#pk-gate-form", %{
        "gate" => %{"password" => "", "lockout_attempts" => "0", "lockout_minutes" => "15"}
      })
      |> render_submit()

      assert Gate.password() == "Secret42"
    end

    test "the password is never shown, only that one is set", %{conn: conn} do
      {:ok, _} = Gate.set_password("Secret42")
      {:ok, view, html} = live(conn, @page)
      refute html =~ "Secret42"
      assert html =~ "••••••••"
      refute has_element?(view, ~s(button[phx-click="reveal_password"]))
    end

    test "the tries at the door are listed with what was typed", %{conn: conn} do
      {:ok, _} = Gate.set_password("Secret42")
      Gate.attempt("SECRET42", address: "203.0.113.7", user_agent: "Mozilla/5.0 Safari")
      Gate.attempt("my-other-password", address: "203.0.113.8")
      {:ok, _view, html} = live(conn, @page)
      assert html =~ "SECRET42"
      assert html =~ "203.0.113.7"
      assert html =~ "right letters, wrong case"
      assert html =~ "my-other-password"
    end

    test "the tries table's columns are each admin's own, kept as they change", %{
      conn: conn,
      user: user
    } do
      {:ok, _} = Gate.set_password("Secret42")
      Gate.attempt("SECRET42", address: "203.0.113.7")
      {:ok, view, html} = live(conn, @page)
      assert html =~ "SECRET42"

      view |> element(~s(button[phx-click="show_column_modal"])) |> render_click()
      html = render_click(view, "remove_column", %{"column_id" => "typed"})
      refute html =~ "SECRET42"

      # The admin's own choice, not the site's.
      assert ViewPrefs.get(user, "website_access.attempts")["columns"] ==
               ~w(when result address browser)

      assert Settings.get_setting("website_access_attempt_columns") == nil

      {:ok, _view2, html2} = live(conn, @page)
      refute html2 =~ "SECRET42", "the choice survives a reload"

      # Another admin still sees the default.
      {other, _} = create_admin_user()
      {:ok, _other_view, other_html} = live(log_in_user(build_conn(), other), @page)
      assert other_html =~ "SECRET42"

      html =
        render_click(view, "reorder_columns", %{"ordered_ids" => ["address", "when", "bogus"]})

      assert ViewPrefs.get(user, "website_access.attempts")["columns"] ==
               ~w(address when result browser)

      assert html =~ "203.0.113.7"

      html = render_click(view, "reset_columns", %{})
      assert html =~ "SECRET42"
      assert ViewPrefs.get(user, "website_access.attempts") == %{}

      # the last column cannot be removed
      for col <- ~w(when result typed address) do
        render_click(view, "remove_column", %{"column_id" => col})
      end

      html = render_click(view, "remove_column", %{"column_id" => "browser"})
      assert html =~ "Browser"

      # ill-shaped column events are ignored, not a crash
      for {event, params} <- [
            {"add_column", %{"column_id" => "bogus"}},
            {"add_column", %{}},
            {"remove_column", %{}},
            {"reorder_columns", %{"ordered_ids" => "when"}}
          ] do
        assert render_click(view, event, params) =~ "Browser"
      end
    end

    test "the site's setting is the default for an admin who has not chosen", %{conn: conn} do
      {:ok, _} = Gate.set_password("Secret42")
      Gate.attempt("SECRET42", address: "203.0.113.7")

      Settings.update_setting("website_access_attempt_columns", ~s(["address","when","bogus"]))
      {:ok, _view, html} = live(conn, @page)
      assert html =~ "203.0.113.7"
      refute html =~ "SECRET42"

      # A site default that names no column still offered shows every column.
      Settings.update_setting("website_access_attempt_columns", ~s(["bogus"]))
      {:ok, _view, html} = live(conn, @page)
      assert html =~ "SECRET42"
    end

    test "a forged toggle for the feature without a switch is refused, not a crash", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)
      html = render_click(view, "toggle_feature", %{"feature" => "allowed_addresses"})
      assert html =~ "Website access"
    end

    test "keep-typed is saved with the gate form", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)

      view
      |> form("#pk-gate-form", %{
        "gate" => %{
          "password" => "",
          "lockout_attempts" => "0",
          "lockout_minutes" => "15",
          "keep_typed" => "near"
        }
      })
      |> render_submit()

      assert Gate.keep_typed() == "near"
    end

    test "access link: make, show, revoke", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)
      html = view |> element(~s(button[phx-click="generate_link"])) |> render_click()
      token = Gate.access_link_token()
      assert html =~ "/phoenix_kit/access/link/" <> token
      html = view |> element(~s(button[phx-click="revoke_link"])) |> render_click()
      refute html =~ token
      assert Gate.access_link_token() == nil
    end

    test "redirect, maintenance and allowed addresses save", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)

      view
      |> form("#pk-redirect-form", %{
        "redirect" => %{"url" => "https://www.example.com/ ", "scope" => "crawlers"}
      })
      |> render_submit()

      assert Redirect.target_url() == "https://www.example.com"
      assert Redirect.scope() == "crawlers"

      view
      |> form("#pk-maintenance-form", %{
        "maintenance" => %{
          "header" => "Back soon",
          "subtext" => "Painting",
          "from" => "",
          "until" => Date.utc_today() |> Date.add(30) |> Date.to_iso8601() |> Kernel.<>("T10:00")
        }
      })
      |> render_submit()

      assert Maintenance.get_header() == "Back soon"
      assert %DateTime{hour: 10} = Maintenance.get_scheduled_end()
      assert Maintenance.get_scheduled_start() == nil

      view
      |> form("#pk-maintenance-form", %{
        "maintenance" => %{
          "header" => "Back soon",
          "subtext" => "Painting",
          "from" => "",
          "until" => ""
        }
      })
      |> render_submit()

      assert Maintenance.get_scheduled_end() == nil, "both blank clears the window"

      view
      |> form("#pk-allowed-form", %{
        "allowed" => %{"addresses" => "203.0.113.7, 203.0.113.7\n10.0.0.1"}
      })
      |> render_submit()

      assert AllowedAddresses.list() == ["203.0.113.7", "10.0.0.1"]
    end

    test "a window already open, or over, does not block a text edit", %{conn: conn} do
      zone = Settings.get_setting("time_zone", "0")
      # a window that opened an hour ago (time passed since it was saved)
      started = DateTime.utc_now() |> DateTime.add(-3600, :second)
      ends = DateTime.utc_now() |> DateTime.add(3600, :second)
      Settings.update_setting("maintenance_scheduled_start", DateTime.to_iso8601(started))
      Settings.update_setting("maintenance_scheduled_end", DateTime.to_iso8601(ends))
      assert Maintenance.active?()
      {:ok, view, html} = live(conn, @page)
      refute html =~ ~s(id="maintenance-from" ) <> "min=", "the server judges the window"

      submit = fn from, until, header ->
        view
        |> form("#pk-maintenance-form", %{
          "maintenance" => %{
            "header" => header,
            "subtext" => "y",
            "from" => from,
            "until" => until
          }
        })
        |> render_submit()
      end

      from = DateUtils.format_datetime_local(started, zone)
      until = DateUtils.format_datetime_local(ends, zone)

      # unchanged window, new heading: saved, window untouched
      html = submit.(from, until, "Back soon")
      assert html =~ "Closed page saved."
      assert Maintenance.get_header() == "Back soon"
      assert Maintenance.same_minute?(Maintenance.get_scheduled_start(), started)
      assert Maintenance.active?()

      # the open window's end moved: accepted although its start has passed
      later = DateTime.add(ends, 3600, :second)
      html = submit.(from, DateUtils.format_datetime_local(later, zone), "Back soon")
      assert html =~ "Closed page saved."
      assert Maintenance.same_minute?(Maintenance.get_scheduled_end(), later)

      # a window that is over, sent back unchanged: still only a text edit
      over = DateTime.utc_now() |> DateTime.add(-600, :second)
      Settings.update_setting("maintenance_scheduled_end", DateTime.to_iso8601(over))
      refute Maintenance.active?()
      html = submit.(from, DateUtils.format_datetime_local(over, zone), "Later")
      assert html =~ "Closed page saved."
      assert Maintenance.get_header() == "Later"

      # a NEW start in the past is still refused, and nothing is written
      html = submit.("2001-01-01T10:00", "", "Not this")
      assert html =~ "in the past"
      assert Maintenance.get_header() == "Later"
    end

    test "a window in the past is refused with a sentence", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)

      html =
        view
        |> form("#pk-maintenance-form", %{
          "maintenance" => %{
            "header" => "x",
            "subtext" => "y",
            "from" => "",
            "until" => "2001-01-01T10:00"
          }
        })
        |> render_submit()

      assert html =~ "in the past"
      assert Maintenance.get_scheduled_end() == nil
    end

    test "the closed page's area shows a status and a preview", %{conn: conn} do
      {:ok, _view, html} = live(conn, @page)
      assert html =~ "Open."
      assert html =~ "Site closed"
      refute html =~ "settings/maintenance"
    end

    test "hide from search engines is the crawlers switch", %{conn: conn} do
      {:ok, view, _} = live(conn, @page)
      view |> element(~s(#feature-no_index input[phx-click="toggle_feature"])) |> render_click()
      assert Crawlers.no_index_enabled?()
    end
  end

  describe "the gate on LiveViews" do
    setup do
      {:ok, _} = Gate.set_password("Secret42")
      {:ok, _} = Gate.set_enabled(true)
      :ok
    end

    test "a locked anonymous session cannot mount a public LiveView", %{conn: _} do
      conn = Phoenix.ConnTest.build_conn() |> init_test_session(%{})
      assert {:error, {:redirect, %{to: "/phoenix_kit/access"}}} = live(conn, @probe)
    end

    test "an allowed address can (the plug stamps its session)", %{conn: _conn} do
      Settings.update_setting(AllowedAddresses.key(), "203.0.113.7")

      conn =
        %{Phoenix.ConnTest.build_conn() | remote_ip: {203, 0, 113, 7}}
        |> init_test_session(%{})
        |> AccessPlug.call([])

      refute conn.halted
      assert {:ok, _view, _html} = live(conn, @probe)

      # taken off the list: the remembered address no longer passes a mount
      Settings.update_setting(AllowedAddresses.key(), "")
      assert {:error, {:redirect, %{to: "/phoenix_kit/access"}}} = live(conn, @probe)
    end

    test "the live connection has to come from the remembered address", %{conn: _conn} do
      Settings.update_setting(AllowedAddresses.key(), "203.0.113.7")

      conn =
        %{Phoenix.ConnTest.build_conn() | remote_ip: {203, 0, 113, 7}}
        |> init_test_session(%{})
        |> AccessPlug.call([])

      # the same tab, carried to another network: the socket says where it is now
      elsewhere = connect_from(conn, {198, 51, 100, 9})
      assert {:error, {:redirect, %{to: "/phoenix_kit/access"}}} = live(elsewhere, @probe)

      here = connect_from(conn, {203, 0, 113, 7})
      assert {:ok, _view, _html} = live(here, @probe)

      # behind a proxy the forwarded address is the one that counts
      proxied = connect_from(conn, {127, 0, 0, 1}, [{"x-forwarded-for", "203.0.113.7"}])
      assert {:ok, _view, _html} = live(proxied, @probe)

      moved = connect_from(conn, {127, 0, 0, 1}, [{"x-forwarded-for", "198.51.100.9"}])
      assert {:error, {:redirect, %{to: "/phoenix_kit/access"}}} = live(moved, @probe)

      # a proxied socket with no forwarded header cannot tell: the address stands
      blind = connect_from(conn, {172, 18, 0, 2})
      assert {:ok, _view, _html} = live(blind, @probe)
    end

    test "an allowed address's open page is relocked when the list changes", %{conn: admin} do
      Settings.update_setting(AllowedAddresses.key(), "203.0.113.7")

      conn =
        %{Phoenix.ConnTest.build_conn() | remote_ip: {203, 0, 113, 7}}
        |> init_test_session(%{})
        |> AccessPlug.call([])

      {:ok, visitor, _html} = live(conn, @probe)

      # the admin takes the address off the list on the settings page
      {:ok, settings, _} = live(admin, @page)

      settings
      |> form("#pk-allowed-form", %{"allowed" => %{"addresses" => ""}})
      |> render_submit()

      assert_redirect(visitor, "/phoenix_kit/access?to=%2F__test%2Fcrawlers-no-index-probe")
    end

    test "an allowed address's page opened while the gate was off survives it coming on",
         %{conn: _} do
      {:ok, _} = Gate.set_enabled(false)
      Settings.update_setting(AllowedAddresses.key(), "203.0.113.7")

      conn =
        %{Phoenix.ConnTest.build_conn() | remote_ip: {203, 0, 113, 7}}
        |> init_test_session(%{})
        |> AccessPlug.call([])

      {:ok, view, _html} = live(conn, @probe)
      {:ok, _} = Gate.set_enabled(true)
      assert render(view) =~ "probe"
    end

    test "an unlocked session can", %{conn: _conn} do
      conn = Phoenix.ConnTest.build_conn() |> init_test_session(%{}) |> Gate.unlock()
      assert {:ok, _view, _html} = live(conn, @probe)
    end

    test "an unlocked visitor's page survives an allowed-list edit, not a password change",
         %{conn: admin} do
      conn = Phoenix.ConnTest.build_conn() |> init_test_session(%{}) |> Gate.unlock()
      {:ok, visitor, _html} = live(conn, @probe)

      {:ok, settings, _} = live(admin, @page)

      settings
      |> form("#pk-allowed-form", %{"allowed" => %{"addresses" => "203.0.113.7"}})
      |> render_submit()

      assert render(visitor) =~ "probe", "the epoch did not change"

      {:ok, _} = Gate.set_password("Another42")
      assert_redirect(visitor, "/phoenix_kit/access?to=%2F__test%2Fcrawlers-no-index-probe")
    end

    test "a logged-in admin is sent to the gate on a relock once logged-in users no longer pass",
         %{conn: conn} do
      {:ok, view, _html} = live(conn, @page)
      {:ok, _} = Gate.set_users_pass(false)

      assert_redirect(
        view,
        "/phoenix_kit/access?to=%2Fphoenix_kit%2Fadmin%2Fsettings%2Fwebsite-access"
      )
    end

    test "a page opened while the gate was off is sent to the gate when it comes on", %{conn: _} do
      {:ok, _} = Gate.set_enabled(false)
      conn = Phoenix.ConnTest.build_conn() |> init_test_session(%{})
      {:ok, view, _html} = live(conn, @probe)

      {:ok, _} = Gate.set_enabled(true)
      assert_redirect(view, "/phoenix_kit/access?to=%2F__test%2Fcrawlers-no-index-probe")
    end

    test "a logged-in admin's open page survives a relock when logged-in users pass", %{
      conn: conn
    } do
      {:ok, view, _html} = live(conn, @page)
      {:ok, _} = Gate.relock_everyone()
      assert render(view) =~ "Password gate"
    end

    test "a logged-in user is turned away too when the setting is off", %{conn: conn} do
      {:ok, _} = Gate.set_users_pass(false)
      assert {:error, {:redirect, %{to: "/phoenix_kit/access"}}} = live(conn, @page)
    end
  end
end
