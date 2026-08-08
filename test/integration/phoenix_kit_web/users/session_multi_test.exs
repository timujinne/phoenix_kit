defmodule PhoenixKitWeb.Users.SessionMultiTest do
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.RoleAssignment
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Users.MultiSession

  defp unique_email, do: "smc_#{System.unique_integer([:positive])}@example.com"

  # The FIRST user registered in a fresh sandbox auto-becomes Owner
  # (`ensure_first_user_is_owner`, only when no active Owner exists). Seed a
  # throwaway Owner so `make/1` yields users with their INTENDED role rather than
  # an accidental Owner promotion just for being first.
  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  defp make(role) do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    assign_test_role(user, role)
    Repo.get!(Auth.User, user.uuid)
  end

  # `Roles.assign_role/3` refuses the Owner role (`:owner_role_protected`) — it's
  # only ever bootstrapped onto the first user — so insert the Owner assignment
  # directly. Other roles use the normal path; `nil` means "leave as default".
  defp assign_test_role(_user, nil), do: :ok

  defp assign_test_role(user, "Owner") do
    owner_role = Roles.get_role_by_name("Owner")

    {:ok, _} =
      %RoleAssignment{}
      |> RoleAssignment.changeset(%{user_uuid: user.uuid, role_uuid: owner_role.uuid})
      |> Repo.insert(on_conflict: :nothing, conflict_target: [:user_uuid, :role_uuid])

    :ok
  end

  defp assign_test_role(user, role) do
    {:ok, _} = Roles.assign_role(user, role)
    :ok
  end

  defp login(conn, user) do
    token = Auth.generate_user_session_token(user)

    conn
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Phoenix.Controller.fetch_flash()
    |> Plug.Conn.put_session(:user_token, token)
    |> Plug.Conn.put_session(:live_socket_id, "phoenix_kit_sessions:#{Base.url_encode64(token)}")
    |> Plug.Conn.put_session(:pk_session_accounts, [token])
  end

  # A `return_to` is no longer taken on trust. `redirect_back/2` hands it to
  # `Routes.safe_destination/2`, which drops any candidate that does not
  # resolve to a GET route in this application's router — so a destination
  # has to be a REAL one for "return_to was honoured" to be observable at all.
  #
  # The literal `"/admin/dashboard"` these tests used before never was a route:
  # the admin index is `/admin`, and every core route sits under the configured
  # `url_prefix`. It used to pass only because the old `redirect_back/2` echoed
  # back whatever `local_path?/1` accepted, 404 or not.
  #
  # Deliberately NOT `/admin` or `/dashboard`: those are what the resolver
  # itself falls back to, so an assertion against them would also hold when the
  # `return_to` was silently dropped.
  defp return_to, do: Routes.path("/admin/users")

  describe "add_account gate" do
    test "owner can add an account", %{conn: conn} do
      # Change 2: the gate requires multi_session_enabled — owner no longer bypasses.
      Settings.update_boolean_setting("multi_session_enabled", true)
      owner = make("Owner")
      other = make(nil)
      conn = login(conn, owner)

      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"},
          "return_to" => return_to()
        })

      assert redirected_to(conn) == return_to()
      assert length(get_session(conn)["pk_session_accounts"]) == 2
    end

    test "plain (non-admin) user can add an account when setting is on", %{conn: conn} do
      # Change 2: gate_allowed? no longer requires owner/admin — any authenticated user may
      # use the switcher when multi_session_enabled is on.
      Settings.update_boolean_setting("multi_session_enabled", true)
      user = make(nil)
      other = make(nil)
      conn = login(conn, user)

      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"},
          "return_to" => return_to()
        })

      assert redirected_to(conn) == return_to()
      assert length(get_session(conn)["pk_session_accounts"]) == 2
    end

    test "forbidden when setting is off", %{conn: conn} do
      Settings.update_boolean_setting("multi_session_enabled", false)
      owner = make("Owner")
      other = make(nil)
      conn = login(conn, owner)

      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"}
        })

      assert conn.status == 403 or redirected_to(conn) =~ "/"
      assert length(get_session(conn)["pk_session_accounts"]) == 1
    end
  end

  describe "switch / remove / logout" do
    setup %{conn: conn} do
      # These exercise the controller (gated) actions, so the feature must be on.
      # Tests that specifically assert the "off" behaviour flip it back themselves.
      Settings.update_boolean_setting("multi_session_enabled", true)
      owner = make("Owner")
      other = make(nil)
      conn = login(conn, owner)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")
      %{conn: Phoenix.Controller.fetch_flash(conn), owner: owner, other: other}
    end

    test "set_active_account switches by ref", %{conn: conn, owner: owner} do
      [root | _] = MultiSession.list_accounts(get_session(conn))

      conn =
        put(conn, Routes.path("/users/session/active"), %{
          "ref" => root.ref,
          "return_to" => return_to()
        })

      assert redirected_to(conn) == return_to()
      assert Auth.get_user_by_session_token(get_session(conn)["user_token"]).uuid == owner.uuid
    end

    test "logout active falls back to root", %{conn: conn, owner: owner} do
      conn = delete(conn, Routes.path("/users/log-out"))
      # Still signed in — as the ROOT account, which is the Owner — so the
      # destination is resolved for that account, not for the one just logged
      # out and not for the host's `/` (which core does not route: this router
      # is `PhoenixKitWeb.Router`, and that was the bug).
      assert redirected_to(conn) == Routes.path("/admin")
      assert get_session(conn)["user_token"]
      assert Auth.get_user_by_session_token(get_session(conn)["user_token"]).uuid == owner.uuid
    end

    test "logout all clears the session", %{conn: conn} do
      tokens = get_session(conn)["pk_session_accounts"]
      conn = delete(conn, Routes.path("/users/log-out") <> "?all=1")
      # Nobody is signed in any more and this router declares no `/`, so the
      # anonymous chain ends on core's own sign-in page rather than on a bare
      # `"/"` that nothing here serves.
      assert redirected_to(conn) == Routes.path("/users/log-in")
      refute get_session(conn)["user_token"]
      assert Enum.all?(tokens, &is_nil(Auth.get_user_by_session_token(&1)))
    end

    test "set_active_account works for a plain user when setting is on", %{conn: _conn} do
      # Change 2: gate_allowed? now allows any authenticated user when the setting is on.
      Settings.update_boolean_setting("multi_session_enabled", true)
      plain = make(nil)
      other = make(nil)
      conn = login(build_conn(), plain)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")
      conn = Phoenix.Controller.fetch_flash(conn)

      [_, second | _] = MultiSession.list_accounts(get_session(conn))

      conn =
        put(conn, Routes.path("/users/session/active"), %{
          "ref" => second.ref,
          "return_to" => return_to()
        })

      assert redirected_to(conn) == return_to()
    end

    test "set_active_account is forbidden when multi_session setting is off", %{conn: conn} do
      Settings.update_boolean_setting("multi_session_enabled", false)
      [root | _] = MultiSession.list_accounts(get_session(conn))

      conn =
        put(conn, Routes.path("/users/session/active"), %{
          "ref" => root.ref
        })

      assert conn.status == 403 or redirected_to(conn) =~ "/"
    end

    test "remove_account works for a plain user when setting is on", %{conn: _conn} do
      # Change 2: gate_allowed? now allows any authenticated user when the setting is on.
      Settings.update_boolean_setting("multi_session_enabled", true)
      plain = make(nil)
      other = make(nil)
      conn = login(build_conn(), plain)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")
      conn = Phoenix.Controller.fetch_flash(conn)

      [_, second | _] = MultiSession.list_accounts(get_session(conn))

      conn = delete(conn, Routes.path("/users/session/accounts/#{second.ref}"))
      # Removing the ACTIVE account falls back to root — a plain user here — so
      # the destination is resolved for them: `/dashboard`, not `/admin`.
      assert redirected_to(conn) == Routes.path("/dashboard")
    end

    test "remove_account is forbidden when multi_session setting is off", %{conn: conn} do
      Settings.update_boolean_setting("multi_session_enabled", false)
      [_, second | _] = MultiSession.list_accounts(get_session(conn))

      conn =
        delete(conn, Routes.path("/users/session/accounts/#{second.ref}"))

      assert conn.status == 403 or redirected_to(conn) =~ "/"
    end
  end

  describe "return_to open-redirect guard" do
    setup %{conn: conn} do
      # The gate must be open for the safe-path case to reach redirect_back;
      # the reject cases fall through to the resolved destination either way.
      Settings.update_boolean_setting("multi_session_enabled", true)
      owner = make("Owner")
      conn = login(conn, owner)
      other = make(nil)
      %{conn: Phoenix.Controller.fetch_flash(conn), owner: owner, other: other}
    end

    # `add_account/3` ACTIVATES the account it adds, so the destination is
    # resolved for `other` — a plain user — even though the root account
    # (still in `conn.assigns`) is an Owner. Landing on `/admin` here would
    # send the newly active user somewhere they are denied.
    test "protocol-relative redirect is rejected (falls back to a core landing)", %{
      conn: conn,
      other: other
    } do
      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"},
          "return_to" => "//evil.com"
        })

      assert redirected_to(conn) == Routes.path("/dashboard")
    end

    test "absolute URL redirect is rejected (falls back to a core landing)", %{
      conn: conn,
      other: other
    } do
      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"},
          "return_to" => "https://evil.com/steal"
        })

      assert redirected_to(conn) == Routes.path("/dashboard")
    end

    test "a safe relative path is accepted", %{conn: conn, other: other} do
      conn =
        post(conn, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"},
          "return_to" => return_to()
        })

      assert redirected_to(conn) == return_to()
    end
  end
end
