defmodule PhoenixKit.API.PublicApiEndToEndTest do
  @moduledoc """
  The public API through the real endpoint, router and database: nothing is
  called as a function, every check is an HTTP request (or a web login) against
  `PhoenixKitWeb.Endpoint`.

  One `describe` per behaviour that depends on several parts working together. The pieces have
  their own unit tests; this file is where they are shown to work together, so
  a test here fails when two correct parts are wired wrongly.

  Requests carry an `X-Forwarded-For` address of their own (believed because the
  test peer is loopback), so no test shares a rate-limit bucket with another.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Keys.Cache
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.ServiceUsers
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.MagicLink
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @read_tool "apikeytest.list_things"
  @identity_tool "system.get_identity"

  setup %{conn: conn} do
    KeyTestSupport.register_fake_module!()
    KeyTestSupport.start_key_cache!()
    {:ok, _} = Settings.update_boolean_setting("api_admin_enabled", true)

    # A person who holds `api` and `media`, and a key of theirs that may read.
    {user, role} = KeyTestSupport.user_with(["api", "media"])
    scope = KeyTestSupport.scope_of(user)

    {:ok, key, token} =
      Keys.create_key(user, scope, %{
        "name" => "End to end",
        "scopes" => [KeyTestSupport.read_scope()]
      })

    %{conn: conn, user: user, role: role, scope: scope, key: key, token: token}
  end

  # --- requests ---------------------------------------------------------

  defp api_path(tool \\ ""), do: Routes.path("/api/admin/v1/" <> tool)
  defp shop_path(tool), do: Routes.path("/api/public/v1/" <> tool)

  defp from_ip(conn, ip \\ KeyTestSupport.unique_ip()),
    do: put_req_header(conn, "x-forwarded-for", ip)

  defp bearer(conn, nil), do: conn
  defp bearer(conn, token), do: put_req_header(conn, "authorization", "Bearer " <> token)

  defp call_tool(conn, token, tool, body \\ %{}, ip \\ KeyTestSupport.unique_ip()) do
    conn
    |> from_ip(ip)
    |> bearer(token)
    |> post_json(api_path(tool), JSON.encode!(body))
  end

  # A JSON body is a binary, which ConnTest only sends with a content type.
  defp post_json(conn, path, body \\ "{}") do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, body)
  end

  defp problem_code(conn), do: conn.resp_body |> JSON.decode!() |> Map.fetch!("code")

  defp problem?(conn) do
    conn
    |> get_resp_header("content-type")
    |> Enum.any?(&String.starts_with?(&1, "application/problem+json"))
  end

  # `Phoenix.LiveView.Logger` and the endpoint log at :debug and `config/test.exs`
  # sets the primary level to :warning: raise it for real or a `refute log =~ x`
  # passes without having looked at anything.
  defp capture_debug_log(fun) do
    original = Logger.level()
    Logger.configure(level: :debug)

    try do
      with_log([level: :debug], fun)
    after
      Logger.configure(level: original)
    end
  end

  defp count_queries(fun) do
    counter = :counters.new(1, [])
    test_pid = self()
    handler = "api-e2e-queries-#{System.unique_integer([:positive])}"

    :telemetry.attach(
      handler,
      [:phoenix_kit, :test, :repo, :query],
      fn _event, _measurements, _metadata, _config ->
        if self() == test_pid, do: :counters.add(counter, 1, 1)
      end,
      nil
    )

    try do
      result = fun.()
      {result, :counters.get(counter, 1)}
    after
      :telemetry.detach(handler)
    end
  end

  test "a valid key reads its own identity", %{conn: conn, token: token, user: user, key: key} do
    conn = call_tool(conn, token, @identity_tool)

    assert conn.status == 200
    body = JSON.decode!(conn.resp_body)
    assert body["key"]["prefix"] == key.prefix
    assert body["owner"]["id"] == user.uuid
    assert body["owner"]["service_user"] == false
    assert body["scopes"] == [KeyTestSupport.read_scope()]
    assert Enum.any?(body["tools"], &(&1["name"] == @read_tool))
  end

  describe "a bad Authorization header is a 401 problem, never a 500" do
    test "empty, blank, truncated and non-pk_ bearer values", %{conn: conn, token: token} do
      headers = [
        "Bearer",
        "Bearer ",
        "Bearer pk_",
        "Bearer pk_ab",
        "Bearer " <> String.slice(token, 0, 12),
        "Bearer " <> String.slice(token, 0, byte_size(token) - 5),
        "Bearer " <> String.replace(token, "pk_", "xx_", global: false),
        "Bearer not-a-key-at-all",
        "Basic dXNlcjpwYXNz",
        "bearer"
      ]

      for header <- headers do
        conn =
          conn
          |> from_ip()
          |> put_req_header("authorization", header)
          |> post_json(api_path(@identity_tool))

        assert conn.status == 401, "#{inspect(header)} answered #{conn.status}"
        assert problem?(conn), "#{inspect(header)} did not answer problem+json"
        assert problem_code(conn) == "unauthorized"
      end
    end

    test "no Authorization header at all", %{conn: conn} do
      conn = conn |> from_ip() |> post_json(api_path(@identity_tool))

      assert conn.status == 401
      assert problem_code(conn) == "unauthorized"
      assert get_resp_header(conn, "www-authenticate") != []
    end

    test "the discovery path answers the same way", %{conn: conn} do
      conn = conn |> from_ip() |> put_req_header("authorization", "Bearer") |> get(api_path())

      assert conn.status == 401
      assert problem_code(conn) == "unauthorized"
    end
  end

  describe "a key stops with its owner's rights, while its row is cached" do
    setup %{conn: conn, token: token, key: key} do
      assert call_tool(conn, token, @read_tool).status == 200
      # The proof that the row is cached: the fetcher must not run.
      assert %{} = Cache.fetch(key.prefix, fn -> flunk("the key row is not cached") end)
      :ok
    end

    test "a blocked owner", %{conn: conn, token: token, user: user} do
      {:ok, _} = Auth.update_user_status(user, %{"is_active" => false})

      conn = call_tool(conn, token, @read_tool)

      assert conn.status == 401
      assert problem_code(conn) == "unauthorized"
    end

    test "a deleted owner", %{conn: conn, token: token, user: user} do
      {:ok, _} = Auth.delete_user(user, %{current_user: KeyTestSupport.owner_user()})

      conn = call_tool(conn, token, @read_tool)

      assert conn.status == 401
    end

    test "an owner who lost the permission", %{conn: conn, token: token, role: role} do
      :ok = Permissions.revoke_permission(role.uuid, "media")

      conn = call_tool(conn, token, @read_tool)

      assert conn.status == 403
      assert problem_code(conn) == "forbidden"
    end

    test "an owner who lost the role", %{conn: conn, token: token, user: user, role: role} do
      {:ok, _} = Roles.remove_role(user, role.name)

      conn = call_tool(conn, token, @read_tool)

      assert conn.status == 403
    end
  end

  describe "a credential in the URL is refused and never logged" do
    # A host gets this filter from `PhoenixKit.boot/1` (`harden_filter_parameters/0`
    # in lib/phoenix_kit.ex); the test environment does not run boot, so the
    # test runs it, and without the filter `Phoenix.Logger` prints the request's
    # query parameters.
    setup do
      original = Application.fetch_env(:phoenix, :filter_parameters)
      Application.delete_env(:phoenix, :filter_parameters)
      PhoenixKit.boot({:ok, self()})

      on_exit(fn ->
        case original do
          {:ok, value} -> Application.put_env(:phoenix, :filter_parameters, value)
          :error -> Application.delete_env(:phoenix, :filter_parameters)
        end
      end)
    end

    test "api_key, token, access_token and a pk_ value are 400 token_in_url", %{
      conn: conn,
      token: token
    } do
      for query <- ["api_key=#{token}", "token=#{token}", "access_token=#{token}", "x=#{token}"] do
        conn =
          conn
          |> from_ip()
          |> bearer(token)
          |> post_json(api_path(@identity_tool) <> "?" <> query)

        assert conn.status == 400, "?#{String.slice(query, 0, 12)}... answered #{conn.status}"
        assert problem_code(conn) == "token_in_url"
      end
    end

    test "it is refused before the key is looked at", %{conn: conn} do
      conn =
        conn
        |> from_ip()
        |> put_req_header("authorization", "Bearer nothing")
        |> post_json(api_path(@identity_tool) <> "?token=whatever")

      assert conn.status == 400
      assert problem_code(conn) == "token_in_url"
    end

    test "the token appears in no log line, at debug level, under any credential name", %{
      conn: conn,
      token: token
    } do
      [_pk, _prefix, secret] = String.split(token, "_", parts: 3)

      for name <- PhoenixKit.API.Auth.credential_params() do
        {conn, log} =
          capture_debug_log(fn ->
            conn
            |> from_ip()
            |> bearer(token)
            |> post_json(api_path(@identity_tool) <> "?#{name}=#{token}")
          end)

        # Not vacuous: the endpoint's own request lines were captured, and the
        # call was refused for the URL, not for something else.
        assert conn.status == 400, "?#{name}= answered #{conn.status}"
        assert log =~ "Sent 400"
        refute log =~ token, "?#{name}= put the key in the log"
        refute log =~ secret, "?#{name}= put the key secret in the log"
      end
    end

    test "nor does a normal authenticated call log it", %{conn: conn, token: token} do
      [_pk, _prefix, secret] = String.split(token, "_", parts: 3)

      {conn, log} = capture_debug_log(fn -> call_tool(conn, token, @identity_tool) end)

      assert conn.status == 200
      assert log =~ "Sent 200"
      refute log =~ token
      refute log =~ secret
    end
  end

  describe "failed authentications are throttled, a valid key is not" do
    test "many failures from one address end in 429, and a valid key from it still works", %{
      conn: conn,
      token: token
    } do
      ip = KeyTestSupport.unique_ip()
      wrong = "pk_00000000_" <> String.duplicate("A", 43)

      statuses = for _ <- 1..50, do: call_tool(conn, wrong, @identity_tool, %{}, ip).status

      # Failures are 401 until the bucket is full, then 429; never anything else.
      assert Enum.all?(statuses, &(&1 in [401, 429]))
      assert 429 in statuses
      assert hd(statuses) == 401

      throttled = call_tool(conn, wrong, @identity_tool, %{}, ip)
      assert throttled.status == 429
      assert problem_code(throttled) == "rate_limited"
      assert get_resp_header(throttled, "retry-after") != []

      # The valid key, from the very same address, passes.
      ok = call_tool(conn, token, @identity_tool, %{}, ip)
      assert ok.status == 200
    end

    test "the failures of one address do not slow another", %{conn: conn, token: token} do
      noisy = KeyTestSupport.unique_ip()
      wrong = "pk_00000000_" <> String.duplicate("B", 43)
      for _ <- 1..50, do: call_tool(conn, wrong, @identity_tool, %{}, noisy)

      assert call_tool(conn, wrong, @identity_tool).status == 401
      assert call_tool(conn, token, @identity_tool).status == 200
    end
  end

  describe "the body guard answers problem+json on /api and touches nothing else" do
    defp raw_post(conn, path, body), do: conn |> from_ip() |> post_json(path, body)

    test "a body over 2 MB is 413 payload_too_large", %{conn: conn, token: token} do
      body = ~s({"padding":"#{String.duplicate("a", 2_097_152)}"})

      conn =
        conn |> bearer(token) |> raw_post(api_path(@identity_tool), body)

      assert conn.status == 413
      assert problem?(conn)
      assert problem_code(conn) == "payload_too_large"
    end

    test "malformed JSON is 400 invalid_json", %{conn: conn, token: token} do
      conn = conn |> bearer(token) |> raw_post(api_path(@identity_tool), ~s({"a":))

      assert conn.status == 400
      assert problem?(conn)
      assert problem_code(conn) == "invalid_json"
    end

    test "the same holds for the public path", %{conn: conn} do
      {:ok, _} = Settings.update_boolean_setting("api_public_enabled", true)

      conn = raw_post(conn, shop_path("shop.search_products"), ~s({"a":))

      assert conn.status == 400
      assert problem_code(conn) == "invalid_json"
    end

    test "/apiary is not an API path: malformed JSON there is Plug.Parsers' own 400", %{
      conn: conn
    } do
      {status, headers, _body} =
        assert_error_sent(400, fn -> raw_post(conn, Routes.path("/apiary"), ~s({"a":)) end)

      refute Enum.any?(headers, fn {name, value} ->
               name == "content-type" and String.contains?(value, "problem+json")
             end)

      assert status == 400
    end

    test "/apiary is not an API path: a big body is no 413 either", %{conn: conn} do
      body = ~s({"padding":"#{String.duplicate("a", 2_097_152)}"})

      # Past the guard and the parsers (their own limit is 8 MB): the router
      # answers, and it has no such route.
      conn = raw_post(conn, Routes.path("/apiary"), body)

      assert conn.status == 404
      refute problem?(conn)
    end
  end

  describe "a service user gets no web session" do
    @password "ServicePassw0rd!"

    setup %{scope: scope} do
      roles = scope |> ServiceUsers.allowed_roles() |> Enum.take(1) |> Enum.map(& &1.name)
      {:ok, bot} = ServiceUsers.create(scope, %{name: "End to end bot", roles: roles})

      # Someone sets a password on the account anyway: the guard, not the lack of
      # a password, is what must keep it out.
      Repo.update_all(
        from(u in PhoenixKit.Users.Auth.User, where: u.uuid == ^bot.uuid),
        set: [hashed_password: Bcrypt.hash_pwd_salt(@password)]
      )

      %{bot: Auth.get_user(bot.uuid)}
    end

    defp login_params(user, password),
      do: %{"user" => %{"email_or_username" => user.email, "password" => password}}

    test "password login: a person gets a session, the service user does not", %{
      conn: conn,
      bot: bot
    } do
      {:ok, person} =
        Auth.register_user(%{
          email: "person_#{System.unique_integer([:positive])}@example.com",
          password: @password
        })

      {:ok, person} = Auth.admin_confirm_user(person)

      ok =
        conn |> from_ip() |> post(Routes.path("/users/log-in"), login_params(person, @password))

      assert get_session(ok, :user_token), "the control login did not open a session"

      refused =
        conn |> from_ip() |> post(Routes.path("/users/log-in"), login_params(bot, @password))

      assert get_session(refused, :user_token) == nil
    end

    test "a session token of a service user opens no admin page", %{conn: conn, bot: bot} do
      token = Auth.generate_user_session_token(bot)

      conn =
        conn
        |> from_ip()
        |> init_test_session(%{user_token: token})
        |> get(Routes.path("/admin"))

      assert redirected_to(conn) =~ "/users/log-in"
    end

    test "a magic link is not sent to a service user", %{bot: bot} do
      refute match?({:ok, _user, _token}, MagicLink.generate_magic_link(bot.email))
    end
  end

  describe "upgrading does not give Admin the api permission" do
    test "the boot sweep that grants new keys to Admin skips api" do
      assert "api" in Permissions.opt_in_admin_keys()

      :ok = Permissions.auto_grant_new_keys_to_admin()

      admin = Roles.get_role_by_name("Admin")
      refute "api" in Permissions.get_permissions_for_role(admin.uuid)
    end

    test "so an Admin cannot open Settings -> API until the Owner grants it", %{conn: conn} do
      {admin, _token} = create_admin_user()
      path = Routes.path("/admin/settings/api")

      refused = conn |> log_in_user(admin) |> get(path)
      assert redirected_to(refused)

      admin_role = Roles.get_role_by_name("Admin")
      {:ok, _} = Permissions.grant_permission(admin_role.uuid, "api")

      opened = conn |> log_in_user(admin) |> get(path)
      assert html_response(opened, 200) =~ "api-settings-page"
    end

    test "the Owner opens it without any grant", %{conn: conn} do
      conn =
        conn
        |> log_in_user(KeyTestSupport.owner_user())
        |> get(Routes.path("/admin/settings/api"))

      assert html_response(conn, 200) =~ "api-settings-page"
    end
  end

  describe "with the API off, every path is a 404 and costs one settings read" do
    setup do
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      {:ok, _} = Settings.update_boolean_setting("api_admin_enabled", false)
      :ok
    end

    test "admin and public paths answer 404", %{conn: conn, token: token} do
      requests = [
        {:get, api_path(), nil},
        {:post, api_path(@identity_tool), token},
        {:post, api_path("anything.at_all"), nil},
        {:post, shop_path("shop.search_products"), nil},
        {:get, shop_path("openapi.json"), nil}
      ]

      for {method, path, key} <- requests do
        conn = conn |> from_ip() |> bearer(key) |> dispatch(@endpoint, method, path, nil)
        assert conn.status == 404, "#{method} #{path} answered #{conn.status}"
      end
    end

    test "after the first read of each switch the settings cache answers: no database query", %{
      conn: conn,
      token: token
    } do
      requests = [
        api_path(),
        api_path(@identity_tool),
        shop_path("shop.search_products"),
        shop_path("openapi.json")
      ]

      post_all = fn ->
        for path <- requests do
          assert (conn |> from_ip() |> bearer(token) |> post_json(path)).status == 404
        end
      end

      # The first round reads each switch once (one query each) and caches it.
      {_, first_round} = count_queries(post_all)
      assert first_round <= 2

      {_, second_round} = count_queries(post_all)
      assert second_round == 0
    end

    test "a flood of bad-key requests costs the first settings read and nothing more", %{
      conn: conn
    } do
      ip = KeyTestSupport.unique_ip()
      wrong = "pk_00000000_" <> String.duplicate("C", 43)

      {statuses, queries} =
        count_queries(fn ->
          for _ <- 1..60, do: call_tool(conn, wrong, @identity_tool, %{}, ip).status
        end)

      # Never a 429: with the API off the request is answered before the
      # failed-authentication throttle is looked at, so it is not fed either.
      assert Enum.uniq(statuses) == [404]
      assert queries <= 1
    end

    test "the two sides switch independently", %{conn: conn, token: token} do
      {:ok, _} = Settings.update_boolean_setting("api_admin_enabled", true)

      assert call_tool(conn, token, @identity_tool).status == 200
      assert (conn |> from_ip() |> post_json(shop_path("shop.search_products"))).status == 404
    end
  end
end
