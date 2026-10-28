defmodule PhoenixKitWeb.APIMCPRoutingTest do
  @moduledoc """
  Where the MCP endpoints sit in `phoenix_kit_routes/0` and how they answer
  through the real endpoint, router, body guard, database and settings: the
  switches (each endpoint follows its own), the pipeline, the website
  password gate, the Origin check, the handshake.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.Paths
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.WebsiteAccess.AllowedAddresses
  alias PhoenixKit.WebsiteAccess.Gate

  @router PhoenixKitWeb.Router

  defp route_info(verb, path),
    do: Phoenix.Router.route_info(@router, verb, Routes.path(path), "localhost")

  defp prefix_segments, do: String.split(Routes.prefix_base(), "/", trim: true)

  defp assert_no_browser_plugs(conn) do
    refute Map.has_key?(conn.private, :plug_session), "a session was fetched"
    refute Map.has_key?(conn.private, :phoenix_format), "the format was negotiated"
    assert get_resp_header(conn, "set-cookie") == []
  end

  defp maybe_bearer(conn, nil), do: conn
  defp maybe_bearer(conn, token), do: bearer(conn, token)

  # One JSON-RPC message through the endpoint, as a real client sends it.
  defp rpc(conn, path, body, opts \\ []) do
    payload = if is_binary(body), do: body, else: JSON.encode!(body)

    conn
    |> with_client_ip(Keyword.get_lazy(opts, :ip, &unique_ip/0))
    |> maybe_bearer(opts[:token])
    |> put_req_header("content-type", "application/json")
    |> put_req_header("accept", Keyword.get(opts, :accept, "application/json"))
    |> put_req_header("mcp-protocol-version", "2025-06-18")
    |> post(Routes.path(path), payload)
  end

  defp ping, do: %{"jsonrpc" => "2.0", "id" => 1, "method" => "ping"}

  describe "the routes" do
    test "both endpoints are forwarded to PhoenixKit.API.MCP under the URL prefix" do
      assert %{plug: MCP, plug_opts: [audience: :admin], forward: forward} =
               route_info("POST", "/mcp/admin")

      assert forward == prefix_segments() ++ ["mcp", "admin"]

      assert %{plug: MCP, plug_opts: [audience: :public], forward: forward} =
               route_info("POST", "/mcp/public")

      assert forward == prefix_segments() ++ ["mcp", "public"]
    end

    test "the old /mcp/shop path is gone: it is not an MCP route any more" do
      for verb <- ["GET", "POST"] do
        refute match?(%{plug: MCP}, route_info(verb, "/mcp/shop")), "#{verb} /mcp/shop"
      end
    end

    test "every method reaches the plug, which answers 405 itself" do
      for verb <- ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
          path <- ["/mcp/admin", "/mcp/public"] do
        assert %{plug: MCP} = route_info(verb, path), "#{verb} #{path}"
      end
    end

    test "they use the empty API pipeline: no session, CSRF or content negotiation" do
      assert %{pipe_through: [:phoenix_kit_api_v1]} = route_info("POST", "/mcp/admin")
      assert %{pipe_through: [:phoenix_kit_api_v1]} = route_info("POST", "/mcp/public")
    end

    test "they are declared before any route that starts with a :param" do
      routes = @router.__routes__() |> Enum.with_index()
      mcp = for {%{plug: MCP}, index} <- routes, do: index

      assert length(mcp) ==
               Enum.count(Paths.entries(), fn {[first | _], _, _} -> first == "mcp" end)

      prefix = Routes.prefix_base()

      first_param_rooted =
        routes
        |> Enum.filter(fn {route, _index} ->
          match?("/:" <> _, String.replace_prefix(route.path, prefix, ""))
        end)
        |> Enum.map(&elem(&1, 1))
        |> Enum.min()

      assert Enum.max(mcp) < first_param_rooted
    end

    test "the REST forwards beside them are unchanged" do
      assert %{plug: PhoenixKit.API.REST, plug_opts: [audience: :admin]} =
               route_info("POST", "/api/admin/v1/system.get_identity")

      assert %{plug: PhoenixKit.API.REST, plug_opts: [audience: :public]} =
               route_info("GET", "/api/public/v1/openapi.json")
    end
  end

  describe "with the API switched off, which is the default" do
    test "both endpoints are a 404 problem, whatever the method", %{conn: conn} do
      for path <- ["/mcp/admin", "/mcp/public"], method <- [:post, :get, :delete, :options] do
        conn = conn |> with_client_ip() |> dispatch(@endpoint, method, Routes.path(path), nil)

        assert conn.status == 404, "#{method} #{path}"
        assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
        assert %{"code" => "not_found"} = json(conn)
        assert_no_browser_plugs(conn)
      end
    end

    test "whatever the client asks to Accept, it is never a 406 page", %{conn: conn} do
      for accept <- [
            "text/event-stream",
            "application/json, text/event-stream",
            "text/html",
            "*/*"
          ] do
        conn = rpc(conn, "/mcp/admin", ping(), accept: accept)

        assert conn.status == 404, accept
        assert_no_browser_plugs(conn)
      end
    end

    test "a broken or oversized body is still a 404: nothing is read", %{conn: conn} do
      for body <- ["{broken", String.duplicate("x", 3_000_000)] do
        assert rpc(conn, "/mcp/admin", body).status == 404
        assert rpc(conn, "/mcp/public", body).status == 404
      end
    end
  end

  describe "with the API switched on" do
    setup %{conn: conn} do
      setup_api()
      put_setting("site_url", "https://shop.test")
      {owner, _role} = user_with(["dashboard", "settings"])
      {_key, token} = issue_key(owner, ["testkit.items:read", "testkit.items:write"])
      %{conn: conn, token: token}
    end

    test "the admin handshake over HTTP: initialize, initialized, ping, tools/list", %{
      conn: conn,
      token: token
    } do
      init = %{
        "jsonrpc" => "2.0",
        "id" => 1,
        "method" => "initialize",
        "params" => %{
          "protocolVersion" => "2025-06-18",
          "capabilities" => %{},
          "clientInfo" => %{"name" => "t", "version" => "1"}
        }
      }

      conn1 = rpc(conn, "/mcp/admin", init, token: token)
      assert conn1.status == 200

      assert %{
               "result" => %{
                 "protocolVersion" => "2025-06-18",
                 "serverInfo" => %{"name" => "phoenix_kit"}
               }
             } = json(conn1)

      assert_no_browser_plugs(conn1)

      initialized = %{"jsonrpc" => "2.0", "method" => "notifications/initialized"}
      conn2 = rpc(conn, "/mcp/admin", initialized, token: token)
      assert conn2.status == 202
      assert conn2.resp_body == ""

      assert %{"result" => %{}} = rpc(conn, "/mcp/admin", ping(), token: token) |> json()

      list = %{"jsonrpc" => "2.0", "id" => 2, "method" => "tools/list"}

      names =
        rpc(conn, "/mcp/admin", list, token: token)
        |> json()
        |> get_in(["result", "tools"])
        |> Enum.map(& &1["name"])

      assert "system_get_identity" in names
    end

    test "no key is a 401 problem; the public endpoint needs none", %{conn: conn} do
      assert rpc(conn, "/mcp/admin", ping()).status == 401
      assert rpc(conn, "/mcp/public", ping()).status == 200
    end

    test "bad JSON reaches the client as a JSON-RPC parse error", %{
      conn: conn,
      token: token
    } do
      for {path, key} <- [{"/mcp/admin", token}, {"/mcp/public", nil}] do
        conn = rpc(conn, path, "{broken", token: key)

        assert conn.status == 400, path
        assert %{"jsonrpc" => "2.0", "id" => nil, "error" => %{"code" => -32_700}} = json(conn)
      end
    end

    test "a batch is an invalid request", %{conn: conn, token: token} do
      conn1 = rpc(conn, "/mcp/admin", JSON.encode!([ping(), ping()]), token: token)
      assert conn1.status == 400
      assert %{"error" => %{"code" => -32_600}} = json(conn1)
    end

    test "GET is a 405 with Allow: POST and no CORS header, on both", %{conn: conn, token: token} do
      admin = conn |> with_client_ip() |> bearer(token) |> get(Routes.path("/mcp/admin"))
      shop = conn |> with_client_ip() |> get(Routes.path("/mcp/public"))

      for answer <- [admin, shop] do
        assert answer.status == 405
        assert ["POST"] = get_resp_header(answer, "allow")
        assert [] = get_resp_header(answer, "access-control-allow-origin")
      end
    end

    test "a client that accepts only an event stream gets a 406 JSON-RPC error, not a page", %{
      conn: conn,
      token: token
    } do
      conn = rpc(conn, "/mcp/admin", ping(), token: token, accept: "text/event-stream")

      assert conn.status == 406
      assert %{"error" => %{"code" => -32_600}} = json(conn)
    end

    test "a foreign Origin is a 403 even with a valid key; the install's own passes",
         %{
           conn: conn,
           token: token
         } do
      foreign =
        conn
        |> put_req_header("origin", "https://evil.test")
        |> rpc("/mcp/admin", ping(), token: token)

      assert foreign.status == 403
      assert %{"code" => "origin_not_allowed"} = json(foreign)

      own =
        conn
        |> put_req_header("origin", "https://shop.test")
        |> rpc("/mcp/admin", ping(), token: token)

      assert own.status == 200
    end
  end

  describe "each endpoint follows its own switch, through the real body guard" do
    setup %{conn: conn} do
      setup_api()
      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["testkit.items:read"])
      %{conn: conn, token: token}
    end

    test "admin on, public off", %{conn: conn, token: token} do
      switch(:public, false)

      conn1 = rpc(conn, "/mcp/admin", ping(), token: token)
      assert conn1.status == 200
      assert json(conn1)["result"] == %{}

      assert rpc(conn, "/mcp/public", ping()).status == 404
    end

    test "admin off, public on: the admin endpoint is a 404 even for a broken body", %{
      conn: conn,
      token: token
    } do
      switch(:admin, false)

      assert rpc(conn, "/mcp/admin", ping(), token: token).status == 404
      assert rpc(conn, "/mcp/admin", "{broken", token: token).status == 404
      assert rpc(conn, "/mcp/public", ping()).status == 200
    end
  end

  describe "the website password gate" do
    setup %{conn: conn} do
      setup_api()
      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["testkit.items:read"])

      # The gate's writes invalidate the settings cache; with it running they
      # log nothing. The settings rows are rolled back with the sandbox.
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      {:ok, _} = Gate.set_password("Secret42")
      {:ok, _} = Gate.set_enabled(true)
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), "")

      %{conn: conn, token: token}
    end

    test "the public endpoint is a 404 while the gate is on; the admin one is unaffected", %{
      conn: conn,
      token: token
    } do
      shop = rpc(conn, "/mcp/public", ping())
      assert shop.status == 404
      assert %{"code" => "not_found"} = json(shop)
      assert_no_browser_plugs(shop)

      assert rpc(conn, "/mcp/admin", ping(), token: token).status == 200
    end
  end
end
