defmodule PhoenixKitWeb.APIBodyGuardEndpointTest do
  @moduledoc """
  `PhoenixKit.API.BodyGuard` in the test endpoint, ahead of `Plug.Parsers`:
  without it a malformed JSON body on an API path raises
  `Plug.Parsers.ParseError` (a Phoenix error page, not problem+json) and a
  large body is read up to the parser's 8 MB. While the API is switched off
  (the default) the guard stays out of the way and the API answers the bare
  `404`, whatever the body.
  """
  use PhoenixKitWeb.ConnCase, async: false

  import PhoenixKit.Test.ApiHarness, only: [switch: 2, with_client_ip: 1]

  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.Utils.Routes

  @max 2_097_152
  @three_mb ~s({"a":"#{String.duplicate("x", 3_000_000)}"})

  setup do
    # `switch/2` writes a setting; without the registry the write logs
    # "unknown registry" instead of the one expected warning.
    KeyTestSupport.start_cache_registry!()
    switch(:admin, true)
    switch(:public, true)
  end

  defp post_json(conn, path, body) do
    conn
    |> put_req_header("content-type", "application/json")
    |> post(path, body)
  end

  defp tool_path, do: Routes.path("/api/admin/v1/system.get_identity")

  test "malformed JSON on an API path is a 400 problem+json, not an exception", %{conn: conn} do
    conn = post_json(conn, tool_path(), "{not json")

    assert conn.status == 400
    assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
    assert %{"code" => "invalid_json", "status" => 400} = JSON.decode!(conn.resp_body)
  end

  test "a body over 2 MB is a 413 problem+json", %{conn: conn} do
    body = ~s({"a":"#{String.duplicate("x", @max)}"})

    conn = post_json(conn, Routes.path("/api/public/v1/shop.search_products"), body)

    assert conn.status == 413
    assert %{"code" => "payload_too_large"} = JSON.decode!(conn.resp_body)
  end

  describe "a percent-encoded path (the router decodes it, so the guard must)" do
    test "malformed JSON is a 400 (problem+json, JSON-RPC on /mcp), not a raised ParseError",
         %{conn: conn} do
      base = Routes.prefix_base()

      for path <- [
            base <> "/api/%61dmin/v1/system.get_identity",
            base <> "/%61pi/admin/v1/system.get_identity",
            base <> "/api/admin/%76%31/system.get_identity",
            base <> "/api/%70ublic/v1/shop.search_products",
            base <> "/mcp/%61dmin",
            base <> "/mcp/%70ublic"
          ] do
        conn = post_json(conn, path, "{not json")

        assert conn.status == 400, path

        if String.contains?(URI.decode(path), "/mcp/") do
          assert ["application/json" <> _] = get_resp_header(conn, "content-type"), path

          assert %{"jsonrpc" => "2.0", "id" => nil, "error" => %{"code" => -32_700}} =
                   JSON.decode!(conn.resp_body)
        else
          assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type"), path
          assert %{"code" => "invalid_json"} = JSON.decode!(conn.resp_body)
        end
      end
    end

    test "a body over 2 MB is a 413 problem+json", %{conn: conn} do
      body = ~s({"a":"#{String.duplicate("x", @max)}"})

      conn = post_json(conn, Routes.prefix_base() <> "/api/%61dmin/v1/x", body)

      assert conn.status == 413
      assert %{"code" => "payload_too_large"} = JSON.decode!(conn.resp_body)
    end

    test "the router really does decode it: an encoded API path is the plain API path",
         %{conn: conn} do
      encoded = post_json(conn, Routes.prefix_base() <> "/api/%61dmin/v1/x", ~s({"a":1}))
      plain = post_json(conn, Routes.path("/api/admin/v1/x"), ~s({"a":1}))

      assert encoded.status == plain.status
      refute encoded.status in [400, 413]
    end

    test "a request without a body takes the same road as the plain path (no router MatchError)",
         %{conn: conn} do
      base = Routes.prefix_base()

      for {encoded, plain} <- [
            {base <> "/api/%61dmin/v1/", base <> "/api/admin/v1/"},
            {base <> "/%61pi/%70ublic/v1", base <> "/api/public/v1"}
          ] do
        conn = with_client_ip(conn)

        assert get(conn, encoded).status == get(conn, plain).status, encoded
      end
    end

    test "the lookalike /apiary stays outside, encoded or not", %{conn: conn} do
      assert_raise Plug.Parsers.ParseError, fn ->
        post_json(conn, Routes.prefix_base() <> "/%61piary/admin/v1/x", "{not json")
      end
    end

    test "with the switches off an encoded path is a 404, not a ParseError or a 413",
         %{conn: conn} do
      switch(:admin, false)
      switch(:public, false)

      paths = [
        Routes.prefix_base() <> "/api/%61dmin/v1/x",
        Routes.prefix_base() <> "/api/%70ublic/v1/x"
      ]

      for path <- paths, body <- ["{not json", @three_mb] do
        conn = conn |> with_client_ip() |> post_json(path, body)

        # The status is the guard's business (no ParseError, no 413); the
        # problem document of the bare 404 is `Auth`'s, behind the forward
        # routes, and is asserted with the plain paths above.
        assert conn.status == 404, path
      end
    end
  end

  describe "CORS" do
    test "the public audience's 400 and 413 are readable by a browser agent", %{conn: conn} do
      path = Routes.path("/api/public/v1/shop.search_products")

      broken = post_json(conn, path, "{not json")
      assert broken.status == 400
      assert get_resp_header(broken, "access-control-allow-origin") == ["*"]

      big = post_json(conn, path, ~s({"a":"#{String.duplicate("x", @max)}"}))
      assert big.status == 413
      assert get_resp_header(big, "access-control-allow-origin") == ["*"]
    end

    test "the admin audience's are not", %{conn: conn} do
      broken = post_json(conn, tool_path(), "{not json")
      assert broken.status == 400
      assert get_resp_header(broken, "access-control-allow-origin") == []
    end
  end

  test "the request id the endpoint assigned is in the problem document", %{conn: conn} do
    conn = post_json(conn, tool_path(), "{not json")

    assert [request_id] = get_resp_header(conn, "x-request-id")
    assert JSON.decode!(conn.resp_body)["request_id"] == request_id
  end

  test "a well-formed body passes on to the router", %{conn: conn} do
    # Whatever the router answers, it is not the guard's 400/413.
    conn = post_json(conn, tool_path(), ~s({"a":1}))
    refute conn.status in [400, 413]
  end

  test "a path that is merely similar is parsed by Plug.Parsers as before", %{
    conn: conn
  } do
    # `/apiary` is not `/api`: no BodyGuard, so the stock parser raises on bad
    # JSON exactly as it did before this change.
    assert_raise Plug.Parsers.ParseError, fn ->
      post_json(conn, Routes.path("/apiary/admin/v1/x"), "{not json")
    end
  end

  test "a non-API path with a large body is not touched by the guard", %{conn: conn} do
    # Under the parser's own 8 MB limit, so it reaches the router and 404s or
    # redirects; the point is that it is not a 413 from the guard.
    body = ~s({"a":"#{String.duplicate("x", @max + 1_000)}"})
    conn = post_json(conn, Routes.path("/not-an-api-path"), body)
    refute conn.status == 413
  end

  describe "the API switch is off" do
    setup do
      switch(:admin, false)
      switch(:public, false)
    end

    test "invalid JSON and a 3 MB body to either audience are a bare 404, not 400 or 413",
         %{conn: conn} do
      paths = [tool_path(), Routes.path("/api/public/v1/shop.search_products")]

      for path <- paths, body <- ["{not json", @three_mb] do
        conn = conn |> with_client_ip() |> post_json(path, body)

        assert conn.status == 404, path
        assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
        assert %{"code" => "not_found", "detail" => ""} = JSON.decode!(conn.resp_body)
      end
    end

    test "costs no database query once the settings cache is warm", %{conn: conn} do
      # The setup started the cache registry; only the settings cache is new.
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      switch(:admin, false)
      switch(:public, false)
      PhoenixKit.Cache.invalidate_now(:settings, ["api_admin_enabled", "api_public_enabled"])

      paths = [tool_path(), Routes.path("/api/public/v1/shop.search_products")]

      # One request to each path warms the cache with both switches.
      for path <- paths, do: conn |> with_client_ip() |> post_json(path, "{not json")

      counter = :counters.new(1, [])
      test_pid = self()
      handler = "api-body-guard-query-count-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler,
        [:phoenix_kit, :test, :repo, :query],
        fn _event, _measurements, _metadata, _config ->
          if self() == test_pid, do: :counters.add(counter, 1, 1)
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler) end)

      for path <- paths, body <- ["{not json", @three_mb] do
        assert 404 == (conn |> with_client_ip() |> post_json(path, body)).status
      end

      assert :counters.get(counter, 1) == 0
    end
  end
end
