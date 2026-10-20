defmodule PhoenixKit.API.BodyGuardTest do
  @moduledoc """
  `PhoenixKit.API.BodyGuard` as a plug: what it reads, what it sets, what it
  refuses and, as important, which requests it never touches: the paths
  outside the machine API and every path while the API switch of its audience is
  off. The guard reads those switches (`api_admin_enabled`,
  `api_public_enabled`), so this is a database test; `setup` switches both on.
  The same plug in the real endpoint, ahead of `Plug.Parsers`, is in
  `PhoenixKitWeb.APIBodyGuardEndpointTest`.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness, only: [switch: 2]
  import Plug.Conn
  import Plug.Test

  alias PhoenixKit.API.BodyGuard
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.Paths
  alias PhoenixKit.Test.ApiReadProbeAdapter
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.WebsiteAccess.AllowedAddresses
  alias PhoenixKit.WebsiteAccess.Gate

  @max 2_097_152

  # Over the limit and not JSON either: whichever the guard checks, it answers.
  @oversized_and_broken ~s({"a":") <> String.duplicate("x", 3_000_000)

  setup do
    # `switch/2` writes a setting; without the registry the write logs
    # "unknown registry" instead of the one expected warning.
    KeyTestSupport.start_cache_registry!()
    switch(:admin, true)
    switch(:public, true)
  end

  # Paths are built with `Routes.path/1` (the API paths) and `prefix_base/0`
  # (lookalikes and `/mcp`), never with a literal `/phoenix_kit`, so the tests
  # hold for whatever prefix the test configuration sets.
  defp tool_path, do: Routes.path("/api/admin/v1/system.get_identity")
  defp public_path, do: Routes.path("/api/public/v1/shop.search_products")
  defp mcp_admin_path, do: Routes.prefix_base() <> "/mcp/admin"
  defp mcp_public_path, do: Routes.prefix_base() <> "/mcp/public"
  defp guarded_paths, do: [tool_path(), public_path(), mcp_admin_path(), mcp_public_path()]

  defp with_url_prefix(value, fun) do
    previous = Application.fetch_env(:phoenix_kit, :url_prefix)
    Application.put_env(:phoenix_kit, :url_prefix, value)
    PhoenixKit.Config.clear_url_prefix_cache()

    try do
      fun.()
    after
      case previous do
        {:ok, prior} -> Application.put_env(:phoenix_kit, :url_prefix, prior)
        :error -> Application.delete_env(:phoenix_kit, :url_prefix)
      end

      PhoenixKit.Config.clear_url_prefix_cache()
    end
  end

  defp run(method, path, body, headers \\ []) do
    conn = conn(method, path, body)

    conn =
      Enum.reduce(headers, conn, fn {name, value}, acc -> put_req_header(acc, name, value) end)

    BodyGuard.call(conn, BodyGuard.init([]))
  end

  defp problem(conn) do
    assert conn.halted
    assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
    JSON.decode!(conn.resp_body)
  end

  # The guard's 400 for a body that is not JSON: problem+json on the REST paths,
  # a JSON-RPC parse error (code -32700, id null) on /mcp/admin and /mcp/public.
  # Returns the human-readable detail either way.
  defp invalid_json_detail(conn, path) do
    if String.contains?(URI.decode(path), "/mcp/") do
      assert conn.halted, path
      assert conn.status == 400, path
      assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")

      assert %{
               "jsonrpc" => "2.0",
               "id" => nil,
               "error" => %{"code" => -32_700, "message" => message}
             } =
               JSON.decode!(conn.resp_body)

      message
    else
      assert conn.status == 400, path
      assert %{"code" => "invalid_json", "status" => 400, "detail" => detail} = problem(conn)
      detail
    end
  end

  # A JSON object of exactly `size` bytes.
  defp json_of_size(size) do
    filler = String.duplicate("x", size - byte_size(~s({"a":""})))
    ~s({"a":"#{filler}"})
  end

  describe "a body on a guarded path" do
    test "a JSON object becomes body_params and params, and Plug.Parsers will skip it" do
      conn = run(:post, tool_path(), ~s({"a":1,"b":[true,null]}))

      refute conn.halted
      assert conn.body_params == %{"a" => 1, "b" => [true, nil]}
      assert conn.params == conn.body_params
    end

    test "a JSON array is wrapped the way Plug.Parsers.JSON wraps it" do
      assert run(:post, tool_path(), "[1,2,3]").body_params == %{"_json" => [1, 2, 3]}
    end

    test "any other JSON value is wrapped too" do
      assert run(:post, tool_path(), "7").body_params == %{"_json" => 7}
      assert run(:post, tool_path(), ~s("text")).body_params == %{"_json" => "text"}
    end

    test "an empty or blank body is an empty map" do
      for body <- ["", "  ", "\n\t "] do
        conn = run(:post, tool_path(), body)
        refute conn.halted
        assert conn.body_params == %{}
      end
    end

    test "is parsed as JSON whatever the content-type says" do
      conn =
        run(:post, tool_path(), ~s({"a":1}), [
          {"content-type", "application/x-www-form-urlencoded"}
        ])

      assert conn.body_params == %{"a" => 1}
    end

    test "POST, PUT, PATCH and DELETE are read" do
      for method <- [:post, :put, :patch, :delete] do
        assert run(method, tool_path(), ~s({"a":1})).body_params == %{"a" => 1}, "#{method}"
      end
    end

    test "a body that went through a parser already is left alone" do
      conn = :post |> conn(tool_path(), %{"a" => 1}) |> BodyGuard.call([])
      assert conn.body_params == %{"a" => 1}
      refute conn.halted
    end

    test "GET is not read" do
      conn = run(:get, tool_path(), "")
      assert %Plug.Conn.Unfetched{} = conn.body_params
    end
  end

  describe "malformed JSON" do
    test "is 400 invalid_json as problem+json" do
      for body <- ["{nope", ~s({"a":}), "{", "not json", ~s({"a":1} trailing)] do
        conn = run(:post, tool_path(), body)

        assert conn.status == 400, body
        assert %{"code" => "invalid_json", "status" => 400} = problem(conn)
      end
    end

    test "an integer the decoder cannot hold is 400 invalid_json, not an exception" do
      # Inside the 2 MB limit; `JSON.decode/1` raises `SystemLimitError` on it.
      body = "[" <> String.duplicate("9", 1_500_000) <> "]"

      for path <- guarded_paths() do
        conn = run(:post, path, body)

        detail = invalid_json_detail(conn, path)
        assert detail =~ "The request body is not valid JSON or holds a number that is too large."
      end
    end
  end

  describe "a body over 2 MB" do
    test "is 413 payload_too_large as problem+json" do
      conn = run(:post, tool_path(), json_of_size(@max + 1))

      assert conn.status == 413

      assert %{"code" => "payload_too_large", "context" => %{"limit_bytes" => @max}} =
               problem(conn)
    end

    test "a body of exactly 2 MB passes" do
      body = json_of_size(@max)
      assert byte_size(body) == @max

      conn = run(:post, tool_path(), body)

      refute conn.halted
      assert %{"a" => _} = conn.body_params
    end

    test "a Content-Length over the limit is refused without reading the body" do
      conn =
        :post
        |> conn(tool_path(), "{}")
        |> put_req_header("content-length", Integer.to_string(@max + 1))
        |> ApiReadProbeAdapter.wrap(:pass)
        |> BodyGuard.call([])

      assert conn.status == 413
      assert %{"code" => "payload_too_large"} = problem(conn)
      refute_received {:read_req_body, _}
    end

    test "the probe sees a read when the declared length is within the limit" do
      conn =
        :post
        |> conn(tool_path(), ~s({"a":1}))
        |> ApiReadProbeAdapter.wrap(:pass)
        |> BodyGuard.call([])

      assert conn.body_params == %{"a" => 1}
      assert_received {:read_req_body, _}
    end

    test "a body that cannot be read is 400 invalid_json as problem+json" do
      conn =
        :post
        |> conn(tool_path(), ~s({"a":1}))
        |> ApiReadProbeAdapter.wrap(:fail)
        |> BodyGuard.call([])

      assert_received {:read_req_body, _}
      assert conn.status == 400
      assert %{"code" => "invalid_json", "detail" => detail} = problem(conn)
      assert detail =~ "could not be read"
    end

    test "a Content-Length that is not a number is ignored" do
      conn = run(:post, tool_path(), ~s({"a":1}), [{"content-length", "lots"}])
      assert conn.body_params == %{"a" => 1}
    end
  end

  describe "every other path is untouched" do
    test "the body is neither read nor judged" do
      base = Routes.prefix_base()

      # Under the kit's prefix, but not the machine API.
      paths =
        Enum.map(
          [
            "/apiary",
            "/apiary/admin/v1/x",
            "/api/upload",
            "/api/files/abc/burn",
            "/api/admin/v1x",
            "/api/admin",
            "/mcpx",
            "/mcp",
            "/mcp/other",
            "/mcp/administrator",
            "/mcp/publicping",
            "/other/api/admin/v1/x",
            "/admin/settings",
            "/en/shop"
          ],
          &(base <> &1)
        )

      # Outside the kit's URL prefix (the test configuration has one; the
      # root-mounted case is "at a root-mounted kit" below).
      assert base != ""
      paths = paths ++ ["/", "/api/admin/v1/x", "/mcp/admin", "/mcp/public"]

      for path <- paths do
        conn = run(:post, path, @oversized_and_broken)

        refute conn.halted, path
        assert %Plug.Conn.Unfetched{} = conn.body_params, path
      end
    end
  end

  describe "percent-encoded path segments (the router decodes them before matching)" do
    # One character of a guarded segment written as %XX, in upper and lower
    # case, and a whole segment encoded.
    # Each encoded path with the segments that follow the URL prefix once the
    # guarded part is decoded (a segment after it, `x`, stays as sent).
    defp encoded_guarded_cases do
      base = Routes.prefix_base()

      [
        {base <> "/%61pi/admin/v1/x", ["api", "admin", "v1", "x"]},
        {base <> "/api/%61dmin/v1/x", ["api", "admin", "v1", "x"]},
        {base <> "/api/admin/%76%31/x", ["api", "admin", "v1", "x"]},
        {base <> "/api/a%64min/v1", ["api", "admin", "v1"]},
        {base <> "/api/%70ublic/v1/x", ["api", "public", "v1", "x"]},
        {base <> "/%61%70%69/%70%75%62%6C%69%63/%76%31", ["api", "public", "v1"]},
        {base <> "/mcp/%61dmin", ["mcp", "admin"]},
        {base <> "/%6Dcp/%70ublic", ["mcp", "public"]},
        # The kit's own prefix, encoded.
        {encode_first_char(base) <> "/api/admin/v1/x", ["api", "admin", "v1", "x"]}
      ]
    end

    defp encoded_guarded_paths, do: Enum.map(encoded_guarded_cases(), &elem(&1, 0))

    defp encode_first_char("/" <> <<first, rest::binary>>),
      do: "/%" <> Base.encode16(<<first>>) <> rest

    test "guarded?/1 is true for the encoded variants of all four guarded paths" do
      for path <- encoded_guarded_paths() do
        assert BodyGuard.guarded?(conn(:post, path)), path
      end
    end

    test "the path_info of those requests is still encoded (the guard has to decode it)" do
      assert %Plug.Conn{path_info: [_, "%61pi" | _]} =
               conn(:post, Routes.prefix_base() <> "/%61pi/admin/v1/x")
    end

    test "guarded?/1 is false for an encoded lookalike" do
      base = Routes.prefix_base()

      for path <- [
            base <> "/%61piary/admin/v1/x",
            base <> "/%61piary",
            base <> "/api/%61dmin/v1x",
            base <> "/api/%61dminx/v1",
            # Route matching is case-sensitive: this is `Admin`.
            base <> "/api/%41dmin/v1",
            base <> "/mcp/%61dministrator",
            base <> "/mcp/%70ublicity",
            base <> "/%6Dcp",
            base <> "/api/admin/%2Fv1/x"
          ] do
        refute BodyGuard.guarded?(conn(:post, path)), path
      end
    end

    test "a body over 2 MB and invalid JSON are 413 and 400 problem+json on an encoded path" do
      for path <- encoded_guarded_paths() do
        too_large = run(:post, path, @oversized_and_broken)
        assert too_large.status == 413, path
        assert %{"code" => "payload_too_large"} = problem(too_large)

        broken = run(:post, path, "{nope")
        assert broken.status == 400, path
        invalid_json_detail(broken, path)

        assert run(:post, path, ~s({"a":1})).body_params == %{"a" => 1}, path
      end
    end

    test "with the switches off an encoded path is left alone like the plain one" do
      switch(:admin, false)
      switch(:public, false)

      for path <- encoded_guarded_paths(), body <- [@oversized_and_broken, "{nope"] do
        :post |> run(path, body) |> assert_left_alone(path)
      end
    end

    test "the matched prefix of path_info is decoded, for every method and with the switches off too" do
      base_segments = Routes.prefix_base() |> String.split("/", trim: true)

      for switches_on? <- [true, false],
          method <- [:get, :post, :options],
          {path, words} <- encoded_guarded_cases() do
        switch(:admin, switches_on?)
        switch(:public, switches_on?)

        conn = run(method, path <> "/%61b%2Fc", "")

        # Only the segments of the URL prefix and of the guarded path are
        # decoded (`Phoenix.Router.Route.call/2` strips them from the raw
        # `path_info` and raises when one is still encoded); the tool name
        # after them stays as sent.
        {prefix, rest} = Enum.split(conn.path_info, length(base_segments))
        assert prefix == base_segments, path
        assert rest == words ++ ["%61b%2Fc"], path
      end
    end

    test "an encoded lookalike keeps its path_info" do
      path = Routes.prefix_base() <> "/%61piary/admin/v1/x"
      conn = run(:get, path, "")

      assert conn.path_info == conn(:get, path).path_info
    end

    test "a malformed escape inside the prefix keeps its path_info" do
      path = Routes.prefix_base() <> "/api/%zz/v1/x"

      assert run(:get, path, "").path_info == conn(:get, path).path_info
    end

    test "an encoded lookalike is untouched" do
      conn = run(:post, Routes.prefix_base() <> "/%61piary/admin/v1/x", "{nope")

      refute conn.halted
      assert %Plug.Conn.Unfetched{} = conn.body_params
    end

    test "a malformed escape does not raise" do
      base = Routes.prefix_base()

      for path <- [base <> "/api/%zz/v1/x", base <> "/%/api/admin/v1", base <> "/mcp/%a"] do
        refute BodyGuard.guarded?(conn(:post, path)), path

        conn = run(:post, path, "{nope")
        refute conn.halted, path
        assert %Plug.Conn.Unfetched{} = conn.body_params, path
      end

      # Past the guarded prefix a malformed escape is just a character.
      path = base <> "/api/admin/v1/%zz"
      assert BodyGuard.guarded?(conn(:post, path))
      assert run(:post, path, "{nope").status == 400
    end
  end

  describe "guarded?/1" do
    test "matches whole path segments under the URL prefix" do
      base = Routes.prefix_base()

      guarded = [
        Routes.path("/api/admin/v1"),
        base <> "/api/admin/v1/",
        Routes.path("/api/admin/v1/ecommerce.set_prices"),
        Routes.path("/api/public/v1/openapi.json"),
        base <> "/mcp/admin",
        base <> "/mcp/admin/",
        base <> "/mcp/public",
        base <> "//mcp//public",
        # The router drops empty segments, so these reach the API too.
        base <> "//api//admin//v1/x",
        base <> "/api/admin/v1//x"
      ]

      for path <- guarded do
        assert BodyGuard.guarded?(conn(:post, path)), path
      end
    end

    test "uses the configured URL prefix" do
      assert Routes.prefix_base() != ""
      refute BodyGuard.guarded?(conn(:post, "/api/admin/v1/x"))
    end
  end

  describe ~s[at a root-mounted kit (url_prefix "/" or "")] do
    # The router scope itself is compiled with the test configuration's
    # prefix and cannot be rebuilt in a test; the guard's own matching, which
    # is what decides whether a request is read, is run with an empty base.
    test "guarded?/1 matches the API paths without a prefix, and nothing else" do
      for prefix <- ["/", ""] do
        with_url_prefix(prefix, fn ->
          assert Routes.prefix_base() == ""

          for path <- [
                "/api/admin/v1/x",
                "/api/public/v1",
                "/mcp/admin",
                "/mcp/public",
                "/api//admin/v1"
              ] do
            assert BodyGuard.guarded?(conn(:post, path)), "#{inspect(prefix)} #{path}"
          end

          for path <- [
                "/apiary",
                "/api/upload",
                "/api/files/abc/burn",
                "/api/admin/v1x",
                "/mcpx",
                "/mcp",
                "/mcp/other",
                "/phoenix_kit/api/admin/v1/x",
                "/en/shop",
                "/"
              ] do
            refute BodyGuard.guarded?(conn(:post, path)), "#{inspect(prefix)} #{path}"
          end
        end)
      end
    end

    test "the guard bounds and parses the body there too" do
      with_url_prefix("/", fn ->
        assert 413 == run(:post, "/api/public/v1/x", json_of_size(@max + 1)).status
        assert %{"a" => 1} == run(:post, "/api/admin/v1/x", ~s({"a":1})).body_params
        assert %Plug.Conn.Unfetched{} = run(:post, "/apiary/x", "{nope").body_params
      end)
    end
  end

  describe "while the audience's switch is off the guard reads nothing" do
    # `%{}`, not `Unfetched`: `Plug.Parsers` runs after the guard and would
    # raise on the invalid JSON; a map in `body_params` makes it skip the
    # request, and `Auth` then answers the bare 404.
    defp assert_left_alone(conn, path) do
      refute conn.halted, path
      assert conn.body_params == %{}, path
    end

    test "an oversized body and invalid JSON are neither read nor answered, on every guarded path" do
      switch(:admin, false)
      switch(:public, false)

      for path <- guarded_paths(), body <- [@oversized_and_broken, "{nope"] do
        :post |> run(path, body) |> assert_left_alone(path)
      end
    end

    test "each switch governs its own paths: admin, then shop (public)" do
      switch(:admin, false)
      switch(:public, true)

      :post |> run(tool_path(), @oversized_and_broken) |> assert_left_alone(tool_path())
      assert 413 == run(:post, public_path(), @oversized_and_broken).status

      switch(:admin, true)
      switch(:public, false)

      assert 413 == run(:post, tool_path(), @oversized_and_broken).status
      :post |> run(public_path(), @oversized_and_broken) |> assert_left_alone(public_path())
    end

    test "/mcp/admin follows the admin switch and /mcp/public the public switch" do
      for {admin?, public?} <- [{true, false}, {false, true}] do
        switch(:admin, admin?)
        switch(:public, public?)

        admin = run(:post, mcp_admin_path(), @oversized_and_broken)
        shop = run(:post, mcp_public_path(), @oversized_and_broken)

        if admin? do
          assert admin.status == 413
          assert shop.body_params == %{}
          refute shop.halted
        else
          assert admin.body_params == %{}
          refute admin.halted
          assert shop.status == 413
        end
      end

      # The mirrored case with a body that is parsed, not refused.
      switch(:admin, true)
      switch(:public, false)
      assert run(:post, mcp_admin_path(), ~s({"a":1})).body_params == %{"a" => 1}
      assert run(:post, mcp_public_path(), ~s({"a":1})).body_params == %{}

      switch(:admin, false)
      switch(:public, true)
      assert run(:post, mcp_admin_path(), ~s({"a":1})).body_params == %{}
      assert run(:post, mcp_public_path(), ~s({"a":1})).body_params == %{"a" => 1}
    end

    test "bare /mcp and /mcp/other are untouched in every switch combination" do
      base = Routes.prefix_base()

      for admin? <- [true, false], public? <- [true, false] do
        switch(:admin, admin?)
        switch(:public, public?)

        for path <- [base <> "/mcp", base <> "/mcp/other"],
            body <- [@oversized_and_broken, "{nope"] do
          conn = run(:post, path, body)

          refute conn.halted, path
          assert %Plug.Conn.Unfetched{} = conn.body_params, path
        end
      end
    end

    test "with the switches on, the same bodies are 413 and 400, on every guarded path" do
      for path <- guarded_paths() do
        too_large = run(:post, path, @oversized_and_broken)
        assert too_large.status == 413, path
        assert %{"code" => "payload_too_large"} = problem(too_large)

        broken = run(:post, path, "{nope")
        assert broken.status == 400, path
        invalid_json_detail(broken, path)
      end
    end
  end

  describe "the website password gate hides the public audience, as it does in Auth" do
    setup do
      # The gate's writes invalidate the settings cache; with it running they
      # log nothing.
      start_supervised!(
        Supervisor.child_spec({PhoenixKit.Cache, name: :settings}, id: :settings_cache)
      )

      {:ok, _} = Gate.set_password("Secret42")
      {:ok, _} = Gate.set_enabled(true)
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), "")
      :ok
    end

    defp via(ip), do: [{"x-forwarded-for", ip}]

    test "a body on a public path is neither read nor judged for a client the gate turns away" do
      ip = KeyTestSupport.unique_ip()

      for path <- [public_path(), mcp_public_path()], body <- [@oversized_and_broken, "{nope"] do
        conn =
          :post
          |> conn(path, body)
          |> put_req_header("x-forwarded-for", ip)
          |> ApiReadProbeAdapter.wrap(:pass)
          |> BodyGuard.call([])

        assert_left_alone(conn, path)
        refute_received {:read_req_body, _}
      end
    end

    test "the admin audience is not gated: its bodies are still judged" do
      ip = KeyTestSupport.unique_ip()

      for path <- [tool_path(), mcp_admin_path()] do
        assert run(:post, path, "{nope", via(ip)).status == 400, path
        assert run(:post, path, @oversized_and_broken, via(ip)).status == 413, path
      end
    end

    test "an address on the gate's allow-list is judged as without a gate" do
      ip = KeyTestSupport.unique_ip()
      {:ok, _} = PhoenixKit.Settings.update_setting(AllowedAddresses.key(), ip)

      for path <- [public_path(), mcp_public_path()] do
        assert run(:post, path, "{nope", via(ip)).status == 400, path
        assert run(:post, path, @oversized_and_broken, via(ip)).status == 413, path
        assert run(:post, path, ~s({"a":1}), via(ip)).body_params == %{"a" => 1}, path
      end
    end

    test "a gate without a password, or switched off, is not enforced" do
      ip = KeyTestSupport.unique_ip()

      {:ok, _} = Gate.set_password("")
      assert run(:post, public_path(), "{nope", via(ip)).status == 400

      {:ok, _} = Gate.set_password("Secret42")
      {:ok, _} = Gate.set_enabled(false)
      assert run(:post, public_path(), "{nope", via(ip)).status == 400
    end

    test "an encoded public path is hidden too" do
      ip = KeyTestSupport.unique_ip()

      for {path, words} <- encoded_guarded_cases(), "public" in words do
        :post |> run(path, "{nope", via(ip)) |> assert_left_alone(path)
      end
    end
  end

  describe "an unreadable switch counts as off" do
    test "the guard reads nothing and judges nothing" do
      # Update mode makes every Settings read answer nil, as when the database
      # is not reachable.
      previous = Application.get_env(:phoenix_kit, :update_mode, false)
      Application.put_env(:phoenix_kit, :update_mode, true)
      on_exit(fn -> Application.put_env(:phoenix_kit, :update_mode, previous) end)

      for path <- guarded_paths(), body <- [@oversized_and_broken, "{nope"] do
        :post |> run(path, body) |> assert_left_alone(path)
      end
    end
  end

  describe "CORS on the guard's own answers" do
    defp cors(conn), do: get_resp_header(conn, "access-control-allow-origin")

    test "the public REST audience gets the header on 413 and 400, as REST answers do" do
      path = public_path()

      assert cors(run(:post, path, @oversized_and_broken)) == ["*"]
      assert cors(run(:post, path, "{nope")) == ["*"]

      declared = run(:post, path, "{}", [{"content-length", Integer.to_string(@max + 1)}])
      assert declared.status == 413
      assert cors(declared) == ["*"]

      unreadable =
        :post |> conn(path, "{}") |> ApiReadProbeAdapter.wrap(:fail) |> BodyGuard.call([])

      assert unreadable.status == 400
      assert cors(unreadable) == ["*"]

      assert cors(run(:post, Routes.prefix_base() <> "/api/%70ublic/v1/x", "{nope")) == ["*"]
    end

    test "the public REST answers of the guard expose the rate-limit and request-id headers" do
      for conn <- [
            run(:post, public_path(), @oversized_and_broken),
            run(:post, public_path(), "{nope")
          ] do
        assert [exposed] = get_resp_header(conn, "access-control-expose-headers")

        assert String.split(exposed, ", ") ==
                 ~w(retry-after ratelimit-limit ratelimit-remaining ratelimit-reset x-request-id idempotent-replayed)
      end
    end

    test "the admin audience and MCP get no CORS header" do
      for path <- [tool_path(), mcp_admin_path(), mcp_public_path()],
          body <- [@oversized_and_broken, "{nope"] do
        conn = run(:post, path, body)
        assert conn.halted, path
        assert cors(conn) == [], path
        assert get_resp_header(conn, "access-control-expose-headers") == [], path
      end
    end

    test "a request the guard accepts gets none from it" do
      assert cors(run(:post, public_path(), ~s({"a":1}))) == []
    end
  end

  describe "the request id of the guard's own answers" do
    defp refused_with_id(id) do
      :post
      |> conn(public_path(), "{nope")
      |> put_resp_header("x-request-id", id)
      |> BodyGuard.call(BodyGuard.init([]))
    end

    test "a safe id set by Plug.RequestId is echoed" do
      conn = refused_with_id("req-from-the-endpoint")
      assert problem(conn)["request_id"] == "req-from-the-endpoint"
    end

    test "an id with characters outside the URL-safe set is replaced, as Auth does" do
      bad = ~s(client "id" <script> with spaces)
      conn = refused_with_id(bad)

      [id] = get_resp_header(conn, "x-request-id")
      assert id =~ ~r/\A[A-Za-z0-9_-]{20}\z/
      assert problem(conn)["request_id"] == id
      refute conn.resp_body =~ "script"
    end
  end

  describe "the deprecated aliases (PhoenixKit.API.Legacy)" do
    defp alias_rest_path, do: Routes.path("/api/shop/v1/shop.search_products")
    defp alias_mcp_path, do: Routes.prefix_base() <> "/mcp/shop"

    test "the guard guards every path of PhoenixKit.API.Paths.entries/0, aliases included" do
      prefix = Routes.prefix_base()

      for {segments, _audience, _cors?, _kind} <- Paths.entries() do
        path = prefix <> "/" <> Enum.join(segments, "/")
        assert BodyGuard.guarded?(conn(:post, path)), path
        assert BodyGuard.guarded?(conn(:post, path <> "/x")), path
      end
    end

    test "a body over 2 MB is a 413 and invalid JSON a 400 problem+json, with the public CORS header" do
      big = run(:post, alias_rest_path(), @oversized_and_broken)
      assert big.status == 413
      assert %{"code" => "payload_too_large"} = problem(big)
      assert cors(big) == ["*"]

      broken = run(:post, alias_rest_path(), "{nope")
      assert %{"code" => "invalid_json"} = problem(broken)
      assert cors(broken) == ["*"]
    end

    test "the guard's own 413 and 400 on an alias carry Deprecation and the successor Link" do
      rest_successor = Routes.path("/api/public/v1")
      mcp_successor = Routes.path("/mcp/public")

      for {path, body, successor} <- [
            {alias_rest_path(), @oversized_and_broken, rest_successor},
            {alias_rest_path(), "{nope", rest_successor},
            {alias_mcp_path(), @oversized_and_broken, mcp_successor},
            {alias_mcp_path(), "{nope", mcp_successor}
          ] do
        conn = run(:post, path, body)
        assert conn.status in [400, 413], path
        assert get_resp_header(conn, "deprecation") == ["@1792454400"], path
        assert [link] = get_resp_header(conn, "link"), path
        assert link =~ ~s(#{successor}>; rel="successor-version"), path
      end

      for path <- [
            Routes.path("/api/public/v1/shop.search_products"),
            Routes.prefix_base() <> "/mcp/public"
          ] do
        conn = run(:post, path, "{nope")
        assert conn.status == 400, path
        assert get_resp_header(conn, "deprecation") == [], path
      end
    end

    test "a JSON body becomes body_params, as on the canonical path" do
      assert run(:post, alias_rest_path(), ~s({"a":1})).body_params == %{"a" => 1}
    end

    test "a bad body on the MCP alias is a JSON-RPC parse error, without CORS" do
      conn = run(:post, alias_mcp_path(), "{nope")

      assert conn.status == 400
      assert %{"error" => %{"code" => -32_700}} = JSON.decode!(conn.resp_body)
      assert cors(conn) == []
    end

    test "the aliases follow the public switch and the admin switch has no say" do
      switch(:admin, true)
      switch(:public, false)

      for path <- [alias_rest_path(), alias_mcp_path()] do
        :post |> run(path, @oversized_and_broken) |> assert_left_alone(path)
      end

      switch(:admin, false)
      switch(:public, true)

      for path <- [alias_rest_path(), alias_mcp_path()] do
        assert run(:post, path, @oversized_and_broken).status == 413, path
      end
    end

    test "their percent-encoded prefix is decoded for the router, as the canonical one is" do
      base = Routes.prefix_base()

      for {encoded, decoded} <- [
            {base <> "/api/%73hop/v1/x", ["api", "shop", "v1", "x"]},
            {base <> "/%6Dcp/%73hop", ["mcp", "shop"]}
          ] do
        conn = run(:post, encoded, ~s({"a":1}))
        prefix = String.split(base, "/", trim: true)

        assert conn.path_info == prefix ++ decoded, encoded
        assert conn.body_params == %{"a" => 1}
      end
    end
  end
end
