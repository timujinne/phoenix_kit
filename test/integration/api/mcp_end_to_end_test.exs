defmodule PhoenixKit.API.MCPEndToEndTest do
  @moduledoc """
  The MCP transport and the OpenAPI document through the real endpoint,
  router, body guard and database. Nothing is called as a function: every
  check is an HTTP request against `PhoenixKitWeb.Endpoint`.

  Each request gets an `X-Forwarded-For` address of its own (believed because
  the test peer is loopback), so no test shares a rate-limit bucket with
  another.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness

  import PhoenixKit.Test.McpHarness,
    only: [message: 1, message: 2, message: 3, result: 1, tool_names: 1, version: 0]

  alias PhoenixKit.API.RateLimit
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.ApiCostTools
  alias PhoenixKit.Test.ApiTools
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Utils.Routes

  @read "testkit.items:read"
  @write "testkit.items:write"

  defmodule Hook do
    @moduledoc false
    def language_only(_conn), do: %{language: "de", currency: "EUR"}
    def raises(_conn), do: raise("hook failure")
  end

  setup %{conn: conn} do
    setup_api()
    put_setting("site_url", "https://shop.test")
    {owner, role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{conn: conn, owner: owner, role: role, key: key, token: token}
  end

  # --- requests ------------------------------------------------------------------

  defp maybe_bearer(conn, nil), do: conn
  defp maybe_bearer(conn, token), do: bearer(conn, token)

  # One JSON-RPC message (a map, or a raw binary) through the endpoint.
  defp rpc(conn, path, body, opts \\ []) do
    payload = if is_binary(body), do: body, else: JSON.encode!(body)

    conn
    |> with_client_ip(Keyword.get_lazy(opts, :ip, &unique_ip/0))
    |> maybe_bearer(opts[:token])
    |> put_req_header("content-type", "application/json")
    |> put_req_header("accept", "application/json")
    |> put_req_header("mcp-protocol-version", version())
    |> post(Routes.path(path), payload)
  end

  defp call_tool(conn, path, token, name, arguments \\ %{}, opts \\ []) do
    rpc(
      conn,
      path,
      message("tools/call", %{"name" => name, "arguments" => arguments}),
      [token: token] ++ opts
    )
  end

  defp rest_post(conn, path, token, body, ip) do
    conn
    |> with_client_ip(ip)
    |> maybe_bearer(token)
    |> put_req_header("content-type", "application/json")
    |> post(Routes.path(path), JSON.encode!(body))
  end

  defp text(result), do: result["content"] |> hd() |> Map.fetch!("text")

  # `config/test.exs` sets the primary Logger level to :warning: raise it for
  # real or a `refute log =~ x` passes without having looked at anything.
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
    handler = "mcp-e2e-queries-#{System.unique_integer([:positive])}"

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

  # --- the flow --------------------------------------------------------------------

  describe "a whole session, admin side" do
    test "initialize, initialized, tools/list, tools/call in both name forms", %{
      conn: conn,
      token: token
    } do
      init =
        message("initialize", %{
          "protocolVersion" => version(),
          "capabilities" => %{},
          "clientInfo" => %{"name" => "t", "version" => "1"}
        })

      assert result(rpc(conn, "/mcp/admin", init, token: token))["protocolVersion"] == version()

      initialized = %{"jsonrpc" => "2.0", "method" => "notifications/initialized"}
      assert rpc(conn, "/mcp/admin", initialized, token: token).status == 202

      names = conn |> rpc("/mcp/admin", message("tools/list"), token: token) |> tool_names()
      assert "system_get_identity" in names
      assert "testkit_write_item" in names

      identity = call_tool(conn, "/mcp/admin", token, "system_get_identity") |> result()
      assert identity["isError"] == false
      assert identity["structuredContent"]["scopes"] |> Enum.sort() == [@read, @write]

      underscore =
        call_tool(conn, "/mcp/admin", token, "testkit_write_item", %{"name" => "a"}) |> result()

      dotted =
        call_tool(conn, "/mcp/admin", token, "testkit.write_item", %{"name" => "a"}) |> result()

      assert underscore["structuredContent"]["written"] == "a"
      assert dotted["structuredContent"]["written"] == "a"
      assert_received {:write_item, %{"name" => "a"}}
    end

    test "the public side needs no key and lists only public tools", %{conn: conn} do
      assert conn |> rpc("/mcp/public", message("tools/list")) |> tool_names() == [
               "testkit_public_echo"
             ]

      echo =
        call_tool(conn, "/mcp/public", nil, "testkit_public_echo", %{"text" => "hi"}) |> result()

      assert echo["structuredContent"]["echo"] == "hi"
    end
  end

  describe "the Origin check, through the endpoint" do
    test "a foreign Origin is a 403 even with a valid key; the install's own origin passes", %{
      conn: conn,
      token: token
    } do
      foreign =
        conn
        |> put_req_header("origin", "https://evil.test")
        |> rpc("/mcp/admin", message("ping"), token: token)

      assert foreign.status == 403
      assert %{"code" => "origin_not_allowed"} = json(foreign)

      own =
        conn
        |> put_req_header("origin", "https://shop.test")
        |> rpc("/mcp/admin", message("ping"), token: token)

      assert own.status == 200
    end

    test "a rebinding page sends its own Host and the same Origin: still refused", %{
      conn: conn,
      token: token
    } do
      rebinding = %{conn | host: "evil.test"} |> put_req_header("origin", "http://evil.test")

      assert rpc(rebinding, "/mcp/admin", message("ping"), token: token).status == 403
      assert rpc(rebinding, "/mcp/public", message("ping")).status == 403
    end

    # The same attack with a host hook configured: a hook that
    # returns only language and currency, and a hook that raises, both leave
    # RequestContext's hosts at the Host header. The Origin check must not use it.
    for hook <- [:language_only, :raises] do
      test "a rebinding page is still refused with the #{hook} host hook configured", %{
        conn: conn,
        token: token
      } do
        Application.put_env(
          :phoenix_kit,
          :api_request_context,
          {PhoenixKit.API.MCPEndToEndTest.Hook, unquote(hook)}
        )

        on_exit(fn -> Application.delete_env(:phoenix_kit, :api_request_context) end)

        rebinding = %{conn | host: "evil.test"} |> put_req_header("origin", "http://evil.test")

        {{admin, public}, log} =
          with_log(fn ->
            {rpc(rebinding, "/mcp/admin", message("ping"), token: token),
             rpc(rebinding, "/mcp/public", message("ping"))}
          end)

        assert admin.status == 403
        assert public.status == 403
        assert %{"code" => "origin_not_allowed"} = json(admin)

        # the configured hook really ran (and failed) instead of being skipped
        if unquote(hook) == :raises, do: assert(log =~ "RuntimeError")
      end
    end

    test "25 refused origins do not lock a valid key out of the same address", %{
      conn: conn,
      token: token
    } do
      wait_for_window_room()
      ip = unique_ip()

      for _ <- 1..25 do
        refused =
          conn
          |> put_req_header("origin", "https://evil.test")
          |> rpc("/mcp/admin", message("ping"), token: "pk_00000000_wrong", ip: ip)

        assert refused.status == 403
      end

      assert rpc(conn, "/mcp/admin", message("ping"), token: token, ip: ip).status == 200

      # A valid key is never refused for its address's failures, so the 200
      # above cannot show that the refusals left the failure bucket alone.
      assert :ok = RateLimit.check_preauth(ip)
    end
  end

  describe "each endpoint follows its own switch, with a real call" do
    test "admin on, public off: tools/call works on /mcp/admin, /mcp/public is a 404", %{
      conn: conn,
      token: token
    } do
      switch(:public, false)

      assert call_tool(conn, "/mcp/admin", token, "testkit_read_items", %{"limit" => 2})
             |> result()
             |> Map.fetch!("isError") == false

      assert call_tool(conn, "/mcp/public", nil, "testkit_public_echo").status == 404
    end

    test "admin off, public on: the reverse", %{conn: conn, token: token} do
      switch(:admin, false)

      assert call_tool(conn, "/mcp/admin", token, "testkit_read_items").status == 404

      assert call_tool(conn, "/mcp/public", nil, "testkit_public_echo", %{"text" => "x"})
             |> result()
             |> Map.fetch!("isError") == false
    end
  end

  describe "malformed JSON-RPC" do
    test "a body that is not JSON is -32700 on both endpoints", %{conn: conn, token: token} do
      for {path, key} <- [{"/mcp/admin", token}, {"/mcp/public", nil}],
          body <- ["{broken", "not json", ~s({"a":})] do
        answer = rpc(conn, path, body, token: key)

        assert answer.status == 400, "#{path} #{body}"
        assert %{"id" => nil, "error" => %{"code" => -32_700}} = json(answer)
      end
    end

    test "a batch, an empty object and a bad id are -32600", %{conn: conn, token: token} do
      bodies = [
        JSON.encode!([message("ping"), message("ping", nil, 2)]),
        "{}",
        JSON.encode!(%{"jsonrpc" => "2.0", "id" => nil, "method" => "ping"}),
        JSON.encode!(%{"jsonrpc" => "2.0", "id" => 1.5, "method" => "ping"}),
        JSON.encode!(%{"jsonrpc" => "1.0", "id" => 1, "method" => "ping"}),
        "7"
      ]

      for body <- bodies do
        answer = rpc(conn, "/mcp/admin", body, token: token)

        assert answer.status == 400, body
        assert %{"error" => %{"code" => -32_600}} = json(answer)
      end
    end

    test "a tools/call without an id is a 202 and the write does not run", %{
      conn: conn,
      token: token
    } do
      notification = %{
        "jsonrpc" => "2.0",
        "method" => "tools/call",
        "params" => %{"name" => "testkit_write_item", "arguments" => %{"name" => "x"}}
      }

      answer = rpc(conn, "/mcp/admin", notification, token: token)

      assert answer.status == 202
      assert answer.resp_body == ""
      refute_received {:write_item, _}
    end
  end

  describe "errors are tool results, in both name forms" do
    test "validation and scope are tool results, an unknown tool is a protocol error", %{
      conn: conn,
      owner: owner,
      token: token
    } do
      for name <- ["testkit_write_item", "testkit.write_item"] do
        invalid = call_tool(conn, "/mcp/admin", token, name, %{"nope" => 1})
        assert invalid.status == 200
        assert result(invalid)["isError"] == true
        assert text(result(invalid)) =~ "[validation_failed] "
        refute Map.has_key?(result(invalid), "structuredContent")
      end

      {_key, read_only} = issue_key(owner, [@read])

      forbidden =
        call_tool(conn, "/mcp/admin", read_only, "testkit_write_item", %{"name" => "x"})
        |> result()

      assert text(forbidden) =~ "[forbidden] "

      unknown = call_tool(conn, "/mcp/admin", token, "testkit_nope")

      assert %{"code" => -32_602, "message" => "Unknown tool: testkit_nope"} =
               json(unknown)["error"]

      refute_received {:write_item, _}
    end

    test "a disabled module is module_disabled in both forms, and the list drops its tools", %{
      conn: conn,
      token: token
    } do
      ApiTools.set_enabled(false)

      for name <- ["testkit_read_items", "testkit.read_items"] do
        assert text(call_tool(conn, "/mcp/admin", token, name) |> result()) =~
                 "[module_disabled] "
      end

      names = conn |> rpc("/mcp/admin", message("tools/list"), token: token) |> tool_names()

      # contains, not equals: the set of core tools can grow (system.get_approval)
      assert "system_get_identity" in names
      refute Enum.any?(names, &String.starts_with?(&1, "testkit_"))
    end

    test "a crashing tool is a generic internal_error, only its class stays in the log, the key keeps working",
         %{
           conn: conn,
           token: token
         } do
      {answer, log} =
        with_log(fn -> call_tool(conn, "/mcp/admin", token, "testkit_crash_write") end)

      assert result(answer)["isError"] == true
      assert text(result(answer)) =~ "[internal_error] The tool failed unexpectedly."
      refute answer.resp_body =~ "secret-detail"
      refute answer.resp_body =~ "RuntimeError"

      problem = result(answer)["content"] |> Enum.at(1) |> Map.fetch!("text") |> JSON.decode!()
      assert problem["detail"] == "The tool failed unexpectedly."
      assert log =~ "RuntimeError"
      refute log =~ "secret-detail"

      assert call_tool(conn, "/mcp/admin", token, "testkit_read_items")
             |> result()
             |> Map.fetch!("isError") == false
    end

    test "a permission the owner lost fails the very next call and drops the tool from the list",
         %{
           conn: conn,
           token: token,
           key: key,
           role: role
         } do
      assert call_tool(conn, "/mcp/admin", token, "testkit_write_item")
             |> result()
             |> Map.fetch!("isError") == false

      assert_row_cached(key.prefix)

      assert :ok = Permissions.revoke_permission(role.uuid, "settings")
      assert_row_cached(key.prefix)

      lost = call_tool(conn, "/mcp/admin", token, "testkit_write_item") |> result()
      assert text(lost) =~ "[forbidden] "

      refute "testkit_write_item" in (conn
                                      |> rpc("/mcp/admin", message("tools/list"), token: token)
                                      |> tool_names())
    end

    test "the key and a client token appear in no answer and in no log line, at debug level", %{
      conn: conn,
      token: token
    } do
      [_pk, _prefix, secret] = String.split(token, "_", parts: 3)

      # The shipped filter, not a hand-written list: boot installs it.
      original = Application.fetch_env(:phoenix, :filter_parameters)

      on_exit(fn ->
        case original do
          {:ok, value} -> Application.put_env(:phoenix, :filter_parameters, value)
          :error -> Application.delete_env(:phoenix, :filter_parameters)
        end
      end)

      Application.delete_env(:phoenix, :filter_parameters)
      PhoenixKit.boot({:ok, self()})

      {answers, log} =
        capture_debug_log(fn ->
          [
            call_tool(conn, "/mcp/admin", token, "testkit_read_items"),
            call_tool(conn, "/mcp/admin", token, "testkit_nope"),
            call_tool(conn, "/mcp/public", nil, "testkit_public_echo", %{
              "text" => "hi",
              "session_token" => "my-session-token-value"
            })
          ]
        end)

      assert log =~ "Sent 200",
             "the endpoint's own log line was not captured: the refute below proves nothing"

      refute log =~ token
      refute log =~ secret
      refute log =~ "my-session-token-value"

      for answer <- answers do
        refute answer.resp_body =~ token
        refute answer.resp_body =~ secret
        refute answer.resp_body =~ "my-session-token-value"
      end
    end
  end

  describe "a flood of cheap messages" do
    setup do
      wait_for_window_room()
      :ok
    end

    test "against the public endpoint it ends in a 429 with Retry-After", %{conn: conn} do
      put_setting("api_public_ip_rate_per_min", 3)
      ip = unique_ip()

      for n <- 1..3,
          do: assert(rpc(conn, "/mcp/public", message("ping", nil, n), ip: ip).status == 200)

      answer = rpc(conn, "/mcp/public", message("ping", nil, 4), ip: ip)

      assert answer.status == 429
      assert %{"code" => "rate_limited"} = json(answer)
      assert [_] = get_resp_header(answer, "retry-after")
    end

    test "another address is not slowed", %{conn: conn} do
      put_setting("api_public_ip_rate_per_min", 1)
      assert rpc(conn, "/mcp/public", message("ping")).status == 200
      assert rpc(conn, "/mcp/public", message("ping")).status == 200
    end

    test "a flood of invented tool names against the admin endpoint ends in a 429 too", %{
      conn: conn,
      owner: owner
    } do
      {_key, token} = issue_key(owner, [@read])
      put_setting("api_admin_rate_per_min", 3)

      for n <- 1..3 do
        answer = call_tool(conn, "/mcp/admin", token, "testkit_nope_#{n}")
        assert answer.status == 200
        assert %{"code" => -32_602} = json(answer)["error"]
      end

      answer = call_tool(conn, "/mcp/admin", token, "testkit_nope_4")

      assert answer.status == 429
      assert %{"code" => "rate_limited"} = json(answer)
      assert [_] = get_resp_header(answer, "retry-after")
    end

    test "a flood of invented tool names against the public endpoint ends in a 429 too", %{
      conn: conn
    } do
      put_setting("api_public_ip_rate_per_min", 3)
      ip = unique_ip()

      for n <- 1..3 do
        answer = call_tool(conn, "/mcp/public", nil, "invented_tool_#{n}", %{}, ip: ip)
        assert answer.status == 200
        assert %{"code" => -32_602} = json(answer)["error"]
      end

      answer = call_tool(conn, "/mcp/public", nil, "invented_tool_4", %{}, ip: ip)

      assert answer.status == 429
      assert %{"code" => "rate_limited"} = json(answer)
      assert [_] = get_resp_header(answer, "retry-after")
    end
  end

  describe "the per-tool cost field, through both transports" do
    setup do
      wait_for_window_room()
      ModuleRegistry.register(ApiCostTools)
      on_exit(fn -> ModuleRegistry.unregister(ApiCostTools) end)
      :ok
    end

    test "a fixed price is charged by REST and by MCP: five units a call off a bucket of twelve",
         %{conn: conn, owner: owner} do
      {_key, token} = issue_key(owner, [@read])
      put_setting("api_admin_rate_per_min", 12)

      rest = fn ->
        rest_post(conn, "/api/admin/v1/testkit.costly_read", token, %{}, unique_ip())
      end

      mcp = fn -> call_tool(conn, "/mcp/admin", token, "testkit_costly_read") end

      assert rest.().status == 200
      assert result(mcp.())["isError"] == false

      # 5 + 5 of 12 are used: a third call would need 15. At one unit a call
      # (the default rule) none of these four would be refused.
      assert rest.().status == 429
      assert mcp.().status == 429
    end

    test "a public batch is charged per query on /mcp/public and on REST", %{conn: conn} do
      put_setting("api_public_ip_rate_per_min", 4)
      batch = fn n -> %{"queries" => List.duplicate(%{}, n)} end

      mcp_ip = unique_ip()

      assert call_tool(conn, "/mcp/public", nil, "testkit_public_batch", batch.(3), ip: mcp_ip).status ==
               200

      assert call_tool(conn, "/mcp/public", nil, "testkit_public_batch", batch.(3), ip: mcp_ip).status ==
               429

      rest_ip = unique_ip()

      assert rest_post(conn, "/api/public/v1/testkit.public_batch", nil, batch.(3), rest_ip).status ==
               200

      assert rest_post(conn, "/api/public/v1/testkit.public_batch", nil, batch.(3), rest_ip).status ==
               429
    end
  end

  describe "OpenAPI through the endpoint" do
    test "the public document is served and not swallowed by a locale route", %{conn: conn} do
      answer = conn |> with_client_ip() |> get(Routes.path("/api/public/v1/openapi.json"))

      assert answer.status == 200
      assert %{"openapi" => "3.1.0", "paths" => %{"/testkit.public_echo" => _}} = json(answer)
      assert ["*"] = get_resp_header(answer, "access-control-allow-origin")
    end

    test "the admin document needs a key and shows what the key can use", %{
      conn: conn,
      owner: owner,
      token: token
    } do
      path = Routes.path("/api/admin/v1/openapi.json")

      assert (conn |> with_client_ip() |> get(path)).status == 401

      {_key, read_only} = issue_key(owner, [@read])
      document = conn |> with_client_ip() |> bearer(read_only) |> get(path) |> json()
      assert Map.has_key?(document["paths"], "/testkit.read_items")
      refute Map.has_key?(document["paths"], "/testkit.write_item")

      full = conn |> with_client_ip() |> bearer(token) |> get(path) |> json()
      assert Map.has_key?(full["paths"], "/testkit.write_item")
    end
  end

  describe "with the API off, nothing costs a database query once the settings cache is warm" do
    setup do
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      {:ok, _} = Settings.update_boolean_setting("api_admin_enabled", false)
      {:ok, _} = Settings.update_boolean_setting("api_public_enabled", false)
      :ok
    end

    test "MCP and OpenAPI answer 404 and read nothing", %{conn: conn, token: token} do
      # A foreign Origin makes an Origin check that ran too early read the
      # settings (it asks for the install's own base URL).
      foreign = put_req_header(conn, "origin", "https://evil.test")

      requests = [
        fn -> foreign |> rpc("/mcp/admin", message("ping"), token: token) end,
        fn -> foreign |> rpc("/mcp/public", message("ping")) end,
        fn -> foreign |> rpc("/mcp/admin", "{broken", token: token) end,
        fn ->
          conn
          |> with_client_ip()
          |> bearer(token)
          |> get(Routes.path("/api/admin/v1/openapi.json"))
        end,
        fn -> conn |> with_client_ip() |> get(Routes.path("/api/public/v1/openapi.json")) end
      ]

      all = fn -> for request <- requests, do: request.().status end

      {first, first_round} = count_queries(all)
      assert Enum.uniq(first) == [404]
      assert first_round <= 2

      {second, second_round} = count_queries(all)
      assert Enum.uniq(second) == [404]
      assert second_round == 0
    end
  end
end
