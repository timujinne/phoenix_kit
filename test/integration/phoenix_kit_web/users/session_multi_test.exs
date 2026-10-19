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

  defp unique_ip do
    n = System.unique_integer([:positive])
    {127, 1, n |> div(256) |> rem(256), rem(n, 256)}
  end

  defp with_peer(conn, ip) do
    {adapter, payload} = conn.adapter
    peer = %{address: ip, port: 111_317, ssl_cert: nil}
    %{conn | adapter: {adapter, Map.put(payload, :peer_data, peer)}, remote_ip: ip}
  end

  defp login(conn, user) do
    token = Auth.generate_user_session_token(user)

    conn
    # `add_account/3` now counts against the per-IP login bucket too, and the
    # test adapter reports one peer for every conn — give each conn its own
    # peer (see `with_peer/2` in auth_flows_test.exs) so a login-heavy suite
    # ordering cannot exhaust this file's bucket.
    |> with_peer(unique_ip())
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
      # the destination is resolved for them. That is `/admin`, the guaranteed
      # landing every authenticated visitor is admitted to; the deprecated
      # `/dashboard` is no longer routed by default.
      assert redirected_to(conn) == Routes.path("/admin")
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

      assert redirected_to(conn) == Routes.path("/admin")
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

      assert redirected_to(conn) == Routes.path("/admin")
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

  # The stack lives in the Plug session, which on a stock `mix phx.new` endpoint
  # is a browser-session cookie — so these go through the real HTTP stack rather
  # than `init_test_session/2`: the bug being fixed was invisible to any test
  # that hands the session in directly. `post/3` on an already-sent conn recycles
  # cookies like a browser, and dropping the session cookie while keeping the
  # persistent ones is exactly what a browser restart looks like.
  describe "durable stack" do
    @remember_me_cookie "_phoenix_kit_web_user_remember_me"
    @accounts_cookie "_phoenix_kit_web_session_accounts"

    defp log_in_via_form(user, opts) do
      params = %{"email_or_username" => user.email, "password" => "ValidPassword123!"}

      params =
        if Keyword.get(opts, :remember_me, true),
          do: Map.put(params, "remember_me", "true"),
          else: params

      post(with_peer(build_conn(), unique_ip()), Routes.path("/users/log-in"), %{"user" => params})
    end

    defp cookie_value(conn, name) do
      case conn.resp_cookies[name] do
        %{value: value} when is_binary(value) and value != "" -> value
        _ -> nil
      end
    end

    # A browser restart: the session cookie is gone, the persistent ones remain.
    defp restart_browser(cookies) do
      cookies
      |> Enum.reject(fn {_name, value} -> is_nil(value) end)
      |> Enum.reduce(with_peer(build_conn(), unique_ip()), fn {name, value}, conn ->
        put_req_cookie(conn, name, value)
      end)
      |> get(Routes.path("/users/log-in"))
    end

    defp added_account_conn(root, other) do
      logged_in = log_in_via_form(root, [])

      added =
        post(logged_in, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"}
        })

      {logged_in, added}
    end

    test "an added account survives losing the session cookie" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      {logged_in, added} = added_account_conn(root, other)
      assert length(get_session(added)["pk_session_accounts"]) == 2

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie => cookie_value(added, @accounts_cookie)
        })

      # Both accounts are back, root first, and the session resumes on the
      # account that was ACTIVE (the one just added), not on the root.
      assert [root_token, second_token] = get_session(restarted)["pk_session_accounts"]
      assert get_session(restarted)["user_token"] == second_token
      assert Auth.get_user_by_session_token(root_token).uuid == root.uuid
      assert Auth.get_user_by_session_token(second_token).uuid == other.uuid
    end

    test "the account switched to is the one a lost session resumes on" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      {logged_in, added} = added_account_conn(root, other)
      [root_row, other_row] = MultiSession.list_accounts(get_session(added))

      cookies = fn conn ->
        %{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie =>
            cookie_value(conn, @accounts_cookie) || cookie_value(added, @accounts_cookie)
        }
      end

      # Back to the root: the marker is cleared, so the restore lands on the root.
      to_root = put(added, Routes.path("/users/session/active"), %{"ref" => root_row.ref})
      restarted = restart_browser(cookies.(to_root))
      assert [root_token, _] = get_session(restarted)["pk_session_accounts"]
      assert get_session(restarted)["user_token"] == root_token

      # And forward again to the second account.
      to_other = put(to_root, Routes.path("/users/session/active"), %{"ref" => other_row.ref})
      restarted = restart_browser(cookies.(to_other))
      assert [_, other_token] = get_session(restarted)["pk_session_accounts"]
      assert get_session(restarted)["user_token"] == other_token
    end

    for invalidation <- [:revoked, :expired, :deactivated] do
      test "a #{invalidation} root cannot restore the active added account" do
        Settings.update_boolean_setting("multi_session_enabled", true)
        root = make(nil)
        other = make(nil)
        {logged_in, added} = added_account_conn(root, other)
        [root_token, other_token] = get_session(added)["pk_session_accounts"]

        case unquote(invalidation) do
          :revoked ->
            Auth.delete_user_session_token(root_token)

          :expired ->
            root_token
            |> Auth.get_session_token_record()
            |> Ecto.Changeset.change(
              inserted_at:
                DateTime.utc_now() |> DateTime.add(-61, :day) |> DateTime.truncate(:second)
            )
            |> Repo.update!()

          :deactivated ->
            root |> Ecto.Changeset.change(is_active: false) |> Repo.update!()
        end

        assert Auth.get_user_by_session_token(other_token).uuid == other.uuid

        restarted =
          restart_browser(%{
            @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
            @accounts_cookie => cookie_value(added, @accounts_cookie)
          })

        refute restarted.assigns.phoenix_kit_current_user
        refute get_session(restarted)["pk_session_accounts"]
        assert %{max_age: 0} = restarted.resp_cookies[@accounts_cookie]
      end
    end

    test "a revoked active added account falls back to the valid root" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)
      {logged_in, added} = added_account_conn(root, other)
      [root_token, other_token] = get_session(added)["pk_session_accounts"]
      Auth.delete_user_session_token(other_token)

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie => cookie_value(added, @accounts_cookie)
        })

      assert restarted.assigns.phoenix_kit_current_user.uuid == root.uuid
      assert get_session(restarted)["user_token"] == root_token
      refute get_session(restarted)["pk_session_accounts"]
      assert %{max_age: 0} = restarted.resp_cookies[@accounts_cookie]
    end

    test "removing the active account resumes on the root" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      {logged_in, added} = added_account_conn(root, other)
      [_, second] = MultiSession.list_accounts(get_session(added))
      removed = delete(added, Routes.path("/users/session/accounts/#{second.ref}"))

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie => cookie_value(removed, @accounts_cookie)
        })

      assert Auth.get_user_by_session_token(get_session(restarted)["user_token"]).uuid ==
               root.uuid
    end

    test "a session-only login persists nothing" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      logged_in = log_in_via_form(root, remember_me: false)

      added =
        post(logged_in, Routes.path("/users/session/accounts"), %{
          "user" => %{"email_or_username" => other.email, "password" => "ValidPassword123!"}
        })

      # The account joined the session stack, but nothing outlives the browser:
      # an account must not get more persistence than the login it was added to.
      assert length(get_session(added)["pk_session_accounts"]) == 2
      assert cookie_value(added, @accounts_cookie) == nil
    end

    test "a fresh login does not inherit the previous user's stack" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)
      newcomer = make(nil)

      {_logged_in, added} = added_account_conn(root, other)
      assert cookie_value(added, @accounts_cookie)

      # Same browser, different person signing in.
      second_login =
        post(added, Routes.path("/users/log-in"), %{
          "user" => %{
            "email_or_username" => newcomer.email,
            "password" => "ValidPassword123!",
            "remember_me" => "true"
          }
        })

      assert %{max_age: 0, secure: true} = second_login.resp_cookies[@accounts_cookie]

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(second_login, @remember_me_cookie),
          @accounts_cookie => cookie_value(added, @accounts_cookie)
        })

      # Even handed the stale cookie, the new login stands alone — the old stack
      # was drained at login, so nothing in it resolves any more.
      assert [only_token] = MultiSession.list_accounts(get_session(restarted))
      assert only_token.user.uuid == newcomer.uuid
    end

    test "removing an account stops persisting it" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      {logged_in, added} = added_account_conn(root, other)
      [_, second | _] = MultiSession.list_accounts(get_session(added))

      removed = delete(added, Routes.path("/users/session/accounts/#{second.ref}"))

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie => cookie_value(removed, @accounts_cookie)
        })

      assert [only_token] = MultiSession.list_accounts(get_session(restarted))
      assert only_token.user.uuid == root.uuid
    end

    test "an impersonation is not persisted" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      admin = make("Admin")
      target = make(nil)

      logged_in = log_in_via_form(admin, [])

      impersonated =
        post(logged_in, Routes.path("/users/session/impersonate/#{target.uuid}"), %{})

      assert length(get_session(impersonated)["pk_session_accounts"]) == 2

      # Borrowing an account is support access, not an account of the operator's:
      # it must end with the browser session.
      assert cookie_value(impersonated, @accounts_cookie) == nil
    end

    test "turning multi-session off drops the persisted stack" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      root = make(nil)
      other = make(nil)

      {logged_in, added} = added_account_conn(root, other)
      Settings.update_boolean_setting("multi_session_enabled", false)

      restarted =
        restart_browser(%{
          @remember_me_cookie => cookie_value(logged_in, @remember_me_cookie),
          @accounts_cookie => cookie_value(added, @accounts_cookie)
        })

      refute get_session(restarted)["pk_session_accounts"]
      assert %{max_age: 0} = restarted.resp_cookies[@accounts_cookie]
    end
  end
end
