defmodule PhoenixKitWeb.APIRoutingTest do
  @moduledoc """
  Where the machine API sits in `phoenix_kit_routes/0`, and how it answers
  through the real endpoint and router: the pipeline, the two forwards, the
  order against the `/:locale` catch-alls, the API switch and the website
  password gate.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.Paths
  alias PhoenixKit.API.REST
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.WebsiteAccess.AllowedAddresses
  alias PhoenixKit.WebsiteAccess.Gate

  @router PhoenixKitWeb.Router
  @max 2_097_152
  @three_mb ~s({"a":"#{String.duplicate("x", 3_000_000)}"})

  defp route_info(verb, path),
    do: Phoenix.Router.route_info(@router, verb, Routes.path(path), "localhost")

  # The URL prefix as `forward` records it: [] at a root-mounted kit,
  # ["phoenix_kit"] in the test configuration. The router is compiled once with
  # the configured prefix, so the root-mounted case cannot be rebuilt here; it
  # is covered where the prefix is read at run time (`BodyGuard.guarded?/1`,
  # `body_guard_test.exs`).
  defp prefix_segments, do: String.split(Routes.prefix_base(), "/", trim: true)

  # The machine API pipeline fetches no session and negotiates no format; neither
  # leaves anything in `conn.private`, and no cookie is set.
  defp assert_no_browser_plugs(conn) do
    refute Map.has_key?(conn.private, :plug_session), "a session was fetched"
    refute conn.private[:plug_session_fetch] == :done, "a session was fetched"
    refute Map.has_key?(conn.private, :phoenix_format), "the format was negotiated"
    assert get_resp_header(conn, "set-cookie") == []
  end

  defp post_json(conn, path, body) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(Routes.path(path), body)
  end

  describe "the routes" do
    test "both audiences are forwarded to PhoenixKit.API.REST under the URL prefix" do
      admin_forward = prefix_segments() ++ ["api", "admin", "v1"]
      public_forward = prefix_segments() ++ ["api", "public", "v1"]

      assert %{plug: REST, plug_opts: [audience: :admin], forward: ^admin_forward} =
               route_info("POST", "/api/admin/v1/ecommerce.set_prices")

      assert %{plug: REST, plug_opts: [audience: :public], forward: ^public_forward} =
               route_info("POST", "/api/public/v1/shop.search_products")
    end

    test "the old shop paths are gone: neither is an API route any more" do
      for verb <- ["GET", "POST"],
          path <- ["/api/shop/v1", "/api/shop/v1/openapi.json", "/mcp/shop"] do
        refute match?(%{plug: plug} when plug in [REST, MCP], route_info(verb, path)),
               "#{verb} #{path}"
      end
    end

    test "the forwards carry the audience and nothing else" do
      assert %{plug_opts: [audience: :public]} = route_info("GET", "/api/public/v1")
      assert %{plug_opts: [audience: :admin]} = route_info("GET", "/api/admin/v1")
    end

    test "every method and the discovery paths reach the plug" do
      for verb <- ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
          path <- [
            "/api/admin/v1",
            "/api/admin/v1/",
            "/api/public/v1",
            "/api/public/v1/system.get_identity"
          ] do
        assert %{plug: REST} = route_info(verb, path), "#{verb} #{path}"
      end
    end

    test "/api/public/v1/openapi.json is not swallowed by a /:locale catch-all" do
      assert %{plug: REST, plug_opts: [audience: :public]} =
               route_info("GET", "/api/public/v1/openapi.json")

      assert %{plug: REST, plug_opts: [audience: :admin]} =
               route_info("GET", "/api/admin/v1/openapi.json")
    end

    test "the pipeline has no content negotiation, session or CSRF" do
      assert %{pipe_through: [:phoenix_kit_api_v1]} = route_info("POST", "/api/admin/v1/x")

      # The pipeline declares no plug at all: read it from the source, because
      # the router does not expose a pipeline's plugs.
      {:ok, ast} = "lib/phoenix_kit_web/integration.ex" |> File.read!() |> Code.string_to_quoted()

      {_ast, bodies} =
        Macro.prewalk(ast, [], fn
          {:pipeline, _, [:phoenix_kit_api_v1, [do: body]]} = node, acc -> {node, [body | acc]}
          node, acc -> {node, acc}
        end)

      assert [body] = bodies

      {_body, plugs} =
        Macro.prewalk(body, [], fn
          {:plug, _, _} = node, acc -> {node, [node | acc]}
          node, acc -> {node, acc}
        end)

      assert plugs == [],
             "the machine API pipeline must stay empty (no :accepts, session or CSRF)"
    end

    test "the forwards are declared before any route that starts with a :param" do
      routes = @router.__routes__() |> Enum.with_index()

      api = for {%{plug: REST}, index} <- routes, do: index

      assert length(api) ==
               Enum.count(Paths.entries(), fn {[first | _], _, _} -> first == "api" end)

      prefix = Routes.prefix_base()

      first_param_rooted =
        routes
        |> Enum.filter(fn {route, _index} ->
          case String.replace_prefix(route.path, prefix, "") do
            "/:" <> _ -> true
            _ -> false
          end
        end)
        |> Enum.map(&elem(&1, 1))
        |> Enum.min()

      assert Enum.max(api) < first_param_rooted
    end

    test "the storage routes beside it are unchanged" do
      assert %{plug: PhoenixKitWeb.UploadController} = route_info("POST", "/api/upload")
      assert %{plug: PhoenixKitWeb.FileController} = route_info("GET", "/api/files/abc/info")

      assert %{plug: PhoenixKitWeb.Controllers.ConsentConfig} =
               route_info("GET", "/api/consent-config")
    end

    test "a look-alike path is not an API route" do
      refute match?(%{plug: REST}, route_info("POST", "/apiary/admin/v1/x"))
      refute match?(%{plug: REST}, route_info("POST", "/api/admin/v1x/x"))
    end
  end

  describe "with the API switched off, which is the default" do
    test "every API path is a 404 problem, for either audience", %{conn: conn} do
      for path <- [
            "/api/admin/v1/system.get_identity",
            "/api/public/v1/shop.search_products",
            "/api/public/v1/openapi.json"
          ],
          method <- [:post, :get] do
        conn = conn |> with_client_ip() |> dispatch(@endpoint, method, Routes.path(path))

        assert conn.status == 404, path
        assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
        assert %{"code" => "not_found"} = json(conn)
        assert_no_browser_plugs(conn)
      end
    end

    test "whatever the client asks to Accept, it is never a 406", %{conn: conn} do
      for accept <- [
            "application/problem+json",
            "text/html",
            "application/json",
            "*/*",
            "text/event-stream"
          ] do
        conn =
          conn
          |> with_client_ip()
          |> put_req_header("accept", accept)
          |> post(Routes.path("/api/admin/v1/system.get_identity"), %{})

        assert conn.status == 404, accept
        assert_no_browser_plugs(conn)
      end
    end
  end

  describe "with the API switched on" do
    setup %{conn: conn} do
      setup_api()
      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["testkit.items:read"])
      %{conn: with_client_ip(conn), token: token}
    end

    test "POST /api/admin/v1/system.get_identity works end to end", %{conn: conn, token: token} do
      conn =
        conn
        |> bearer(token)
        |> put_req_header("content-type", "application/json")
        |> post(Routes.path("/api/admin/v1/system.get_identity"), "{}")

      assert conn.status == 200
      assert %{"scopes" => ["testkit.items:read"], "owner" => %{"email" => _}} = json(conn)

      # A POST with no CSRF token succeeded (no CSRF plug), with a key and no
      # session.
      assert_no_browser_plugs(conn)
    end

    test "a client that accepts only problem+json is served, never a 406", %{
      conn: conn,
      token: token
    } do
      conn =
        conn
        |> bearer(token)
        |> put_req_header("accept", "application/problem+json")
        |> get(Routes.path("/api/admin/v1/"))

      assert conn.status == 200
      assert_no_browser_plugs(conn)
    end

    test "a percent-encoded prefix is the same API: a POST reaches the tool, a GET the listing",
         %{conn: conn, token: token} do
      base = Routes.prefix_base()
      conn = bearer(conn, token)

      for prefix <- [base <> "/api/%61dmin/v1", base <> "/%61pi/%61dmin/%76%31"] do
        posted =
          conn
          |> put_req_header("content-type", "application/json")
          |> post(prefix <> "/system.get_identity", "{}")

        assert posted.status == 200, prefix
        assert %{"scopes" => ["testkit.items:read"]} = json(posted)

        listed = get(conn, prefix <> "/")
        assert listed.status == 200, prefix
        assert "system.get_identity" in Enum.map(json(listed)["tools"], & &1["name"])
      end
    end

    test "GET /api/admin/v1/ lists the tools", %{conn: conn, token: token} do
      conn = conn |> bearer(token) |> get(Routes.path("/api/admin/v1/"))

      assert conn.status == 200
      assert "system.get_identity" in Enum.map(json(conn)["tools"], & &1["name"])
    end

    test "no key is a 401 problem", %{conn: conn} do
      conn = post(conn, Routes.path("/api/admin/v1/system.get_identity"), %{})
      assert conn.status == 401
      assert %{"code" => "unauthorized"} = json(conn)
    end

    test "a tool path with a dot reaches the executor: an unknown tool is a 404 problem", %{
      conn: conn,
      token: token
    } do
      conn = conn |> bearer(token) |> post(Routes.path("/api/admin/v1/no.such_tool"), %{})
      assert conn.status == 404
      assert %{"code" => "not_found"} = json(conn)
    end

    test "the public audience answers without a key", %{conn: conn} do
      conn = get(conn, Routes.path("/api/public/v1"))

      assert conn.status == 200
      assert ["testkit.public_echo"] = Enum.map(json(conn)["tools"], & &1["name"])
      assert ["*"] = get_resp_header(conn, "access-control-allow-origin")
      assert_no_browser_plugs(conn)
    end
  end

  describe "the website password gate" do
    setup %{conn: conn} do
      setup_api()

      # The gate's writes invalidate the settings cache; with it running they
      # log nothing. The settings rows are rolled back with the sandbox, so no
      # clean-up is needed (one in `on_exit` would run after the cache and the
      # registry are gone and only log warnings).
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["testkit.items:read"])

      {:ok, _} = Gate.set_password("Secret42")
      {:ok, _} = Gate.set_enabled(true)
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), "")

      %{conn: with_client_ip(conn), token: token}
    end

    test "the public API answers 404 while the gate is on", %{conn: conn} do
      for {method, path} <- [get: "/api/public/v1", post: "/api/public/v1/testkit.public_echo"] do
        conn = dispatch(conn, @endpoint, method, Routes.path(path), %{})

        assert conn.status == 404, path
        assert %{"code" => "not_found"} = json(conn)
      end
    end

    test "the admin API is unaffected", %{conn: conn, token: token} do
      conn = conn |> bearer(token) |> post(Routes.path("/api/admin/v1/system.get_identity"), %{})
      assert conn.status == 200
    end

    test "an address on the gate's allow-list gets through", %{conn: conn} do
      ip = unique_ip()
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), ip)

      assert 200 == (conn |> with_client_ip(ip) |> get(Routes.path("/api/public/v1"))).status
      assert 404 == (conn |> with_client_ip() |> get(Routes.path("/api/public/v1"))).status
    end

    test "a body the gate turns away is neither read nor judged: malformed JSON and 3 MB are a 404",
         %{conn: conn} do
      for path <- ["/api/public/v1/testkit.public_echo", "/api/public/v1/x"],
          body <- ["{not json", @three_mb] do
        conn = post_json(conn, path, body)

        assert conn.status == 404, path
        assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
        assert %{"code" => "not_found", "detail" => ""} = json(conn)
      end

      # The same through a percent-encoded prefix.
      encoded = post_json(conn, "/api/%70ublic/v1/x", "{not json")
      assert encoded.status == 404
    end

    test "the guard's 400 and 413 stay for an address on the allow-list", %{conn: conn} do
      ip = unique_ip()
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), ip)
      conn = with_client_ip(conn, ip)

      path = "/api/public/v1/testkit.public_echo"

      broken = post_json(conn, path, "{not json")
      assert broken.status == 400
      assert %{"code" => "invalid_json"} = json(broken)

      big = post_json(conn, path, ~s({"a":"#{String.duplicate("x", @max)}"}))
      assert big.status == 413
      assert %{"code" => "payload_too_large"} = json(big)
    end

    test "the admin API keeps its guard while the gate is on", %{conn: conn, token: token} do
      broken =
        conn |> bearer(token) |> post_json("/api/admin/v1/system.get_identity", "{not json")

      assert broken.status == 400
      assert %{"code" => "invalid_json"} = json(broken)
    end

    test "a gate with no password is not enforced, as on the site", %{conn: conn} do
      {:ok, _} = Gate.set_password("")

      assert 200 == (conn |> get(Routes.path("/api/public/v1"))).status
    end

    test "switching the gate off opens the public API again", %{conn: conn} do
      {:ok, _} = Gate.set_enabled(false)
      assert 200 == (conn |> get(Routes.path("/api/public/v1"))).status
    end

    test "never touches the session: no session is fetched on an API request", %{conn: conn} do
      conn = get(conn, Routes.path("/api/public/v1"))
      assert conn.status == 404

      # `Auth` asked `Gate.enabled?/0` and the allow-list only. The gate's own
      # helpers call `get_session`, which would leave `:plug_session` in
      # `conn.private` (and, if the session changed, a cookie).
      assert_no_browser_plugs(conn)
    end
  end
end
