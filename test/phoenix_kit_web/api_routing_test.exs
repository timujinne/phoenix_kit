defmodule PhoenixKitWeb.APIRoutingTest do
  @moduledoc """
  Where the machine API sits in `phoenix_kit_routes/0`, and how it answers
  through the real endpoint and router: the pipeline, the two forwards, the
  order against the `/:locale` catch-alls, the API switch and the website
  password gate.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.MCP.Origin
  alias PhoenixKit.API.Paths
  alias PhoenixKit.API.PublicDiscovery
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

    test "the deprecated alias is the same plug, with the public audience, and says so" do
      alias_forward = prefix_segments() ++ ["api", "shop", "v1"]

      assert %{plug: REST, plug_opts: opts, forward: ^alias_forward} =
               route_info("POST", "/api/shop/v1/shop.search_products")

      assert opts[:audience] == :public
      assert opts[:deprecated][:path] == "/api/shop/v1"
      assert opts[:deprecated][:successor] == Paths.rest_path(:public)
    end

    test "the alias is routed before the /:locale scopes, as the canonical path is" do
      for path <- [
            "/api/shop/v1",
            "/api/shop/v1/openapi.json",
            "/api/shop/v1/shop.search_products"
          ],
          verb <- ["GET", "POST", "OPTIONS"] do
        assert %{plug: REST, plug_opts: [{:audience, :public} | _]} = route_info(verb, path),
               "#{verb} #{path}"
      end
    end

    test "the canonical forwards carry no deprecation option" do
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
               Enum.count(Paths.entries(), fn {[first | _], _, _, _} -> first == "api" end)

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

  describe "the deprecated alias /api/shop/v1" do
    setup %{conn: conn} do
      setup_api()
      %{conn: with_client_ip(conn)}
    end

    defp successor_link,
      do: "<#{PublicDiscovery.api_url(Origin.canonical_origin())}>; rel=\"successor-version\""

    test "answers like the canonical path: the same tools, the same CORS", %{conn: conn} do
      canonical = get(conn, Routes.path("/api/public/v1"))
      aliased = get(conn, Routes.path("/api/shop/v1"))

      assert aliased.status == 200
      assert json(aliased) == json(canonical)
      assert ["*"] = get_resp_header(aliased, "access-control-allow-origin")
    end

    test "runs a tool as the public audience", %{conn: conn} do
      conn = post_json(conn, "/api/shop/v1/testkit.public_echo", ~s({"text":"hi"}))

      assert conn.status == 200
      assert %{"echo" => "hi"} = json(conn)
    end

    test "carries Deprecation and a successor-version Link; the canonical path carries neither",
         %{conn: conn} do
      aliased = get(conn, Routes.path("/api/shop/v1"))

      assert ["@1792454400"] = get_resp_header(aliased, "deprecation")
      assert [link] = get_resp_header(aliased, "link")
      assert link =~ successor_link()

      canonical = get(conn, Routes.path("/api/public/v1"))
      assert [] = get_resp_header(canonical, "deprecation")
      refute canonical |> get_resp_header("link") |> Enum.join(", ") =~ "successor-version"
    end

    test "adds its Link to the links of the tool list instead of replacing them", %{conn: conn} do
      aliased = get(conn, Routes.path("/api/shop/v1"))

      assert [link] = get_resp_header(aliased, "link")
      assert link =~ successor_link()
      assert link =~ ~s(rel="service-desc")
      assert link =~ ~s(rel="service-doc")
    end

    test "marks every answer of the plug, a 404 problem and a 405 too", %{conn: conn} do
      for answer <- [
            get(conn, Routes.path("/api/shop/v1/no/such/path")),
            put(conn, Routes.path("/api/shop/v1/testkit.public_echo"), %{}),
            post_json(conn, "/api/shop/v1/no.such_tool", "{}")
          ] do
        assert ["@1792454400"] = get_resp_header(answer, "deprecation")
        assert answer |> get_resp_header("link") |> Enum.join(", ") =~ successor_link()
      end
    end

    test "the OpenAPI document served there names the canonical server only", %{conn: conn} do
      document = conn |> get(Routes.path("/api/shop/v1/openapi.json")) |> json()

      assert [%{"url" => url}] = document["servers"]
      assert url =~ Paths.rest_path(:public)
      refute JSON.encode!(document) =~ "/api/shop"
    end

    test "logs once per node, at info level", %{conn: conn} do
      :persistent_term.erase({Paths, :deprecation_logged, "/api/shop/v1"})
      previous = Logger.level()
      Logger.configure(level: :info)
      on_exit(fn -> Logger.configure(level: previous) end)

      log =
        ExUnit.CaptureLog.capture_log([level: :info], fn ->
          get(conn, Routes.path("/api/shop/v1"))
          get(conn, Routes.path("/api/shop/v1"))
        end)

      assert [_once] = Regex.scan(~r/deprecated path/, log)
      assert log =~ "/api/shop/v1"
      assert log =~ Paths.rest_path(:public)
    end

    test "with the API switched off it is a bare 404 that names nothing", %{conn: conn} do
      switch(:public, false)
      aliased = get(conn, Routes.path("/api/shop/v1"))

      assert aliased.status == 404
      assert [] = get_resp_header(aliased, "deprecation")
      assert [] = get_resp_header(aliased, "link")
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

      # The deprecated alias is gated like the canonical path.
      aliased = post_json(conn, "/api/shop/v1/x", "{not json")
      assert aliased.status == 404
      assert [] = get_resp_header(aliased, "deprecation")
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
