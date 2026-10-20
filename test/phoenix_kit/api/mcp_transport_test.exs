defmodule PhoenixKit.API.MCPTransportTest do
  @moduledoc """
  The MCP plug at plug level: the order of the checks, the handshake, the
  methods that need no tool, malformed JSON-RPC, and the rate limit of the
  cheap methods. Real keys, real settings, real rate limiter.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness
  import PhoenixKit.Test.McpHarness
  import Plug.Conn

  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.RateLimit

  @read "testkit.items:read"
  @write "testkit.items:write"

  setup do
    setup_api()
    put_setting("site_url", "https://shop.test")
    {owner, _role} = user_with(["dashboard", "settings"])
    {_key, token} = issue_key(owner, [@read, @write])
    %{token: token}
  end

  defp client_info, do: %{"name" => "test", "version" => "1"}

  defp initialize_params(version \\ "2025-06-18"),
    do: %{"protocolVersion" => version, "capabilities" => %{}, "clientInfo" => client_info()}

  describe "init/1" do
    test "keeps a known audience and refuses anything else" do
      assert [audience: :admin] = MCP.init(audience: :admin)
      assert [audience: :public] = MCP.init(audience: :public)
      assert_raise ArgumentError, fn -> MCP.init(audience: :nope) end
      assert_raise KeyError, fn -> MCP.init([]) end
    end

    test "the supported revisions, newest first" do
      assert MCP.supported_versions() == ["2025-11-25", "2025-06-18", "2025-03-26"]
    end
  end

  describe "initialize" do
    test "answers with the negotiated revision, the tools capability, server info and instructions",
         %{token: token} do
      conn = post_rpc(:admin, message("initialize", initialize_params(), 7), token: token)

      assert conn.status == 200
      assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")
      assert ["no-store"] = get_resp_header(conn, "cache-control")
      assert %{"jsonrpc" => "2.0", "id" => 7} = json(conn)

      result = result(conn)
      assert result["protocolVersion"] == "2025-06-18"
      assert result["capabilities"] == %{"tools" => %{"listChanged" => false}}

      assert %{"name" => "phoenix_kit", "version" => version, "title" => title} =
               result["serverInfo"]

      assert version == PhoenixKit.version()
      assert title =~ "admin API"
      assert result["instructions"] =~ "system_get_identity"
      assert result["instructions"] =~ "executed false, status pending_approval"
      assert result["instructions"] =~ "still waiting"
      assert result["instructions"] =~ "same approval_id"
      assert result["instructions"] =~ "changed meanwhile"
      assert result["instructions"] =~ "dry_run"
      assert result["instructions"] =~ "confirm_token"
      assert result["instructions"] =~ "idempotency_key"
      refute result["instructions"] =~ "idempotent-replayed"
    end

    test "echoes every supported revision", %{token: token} do
      for version <- MCP.supported_versions() do
        conn = post_rpc(:admin, message("initialize", initialize_params(version)), token: token)
        assert result(conn)["protocolVersion"] == version
      end
    end

    test "an unsupported revision gets the newest we speak", %{token: token} do
      conn =
        post_rpc(:admin, message("initialize", initialize_params("1999-01-01")), token: token)

      assert result(conn)["protocolVersion"] == hd(MCP.supported_versions())
    end

    test "the oldest revision gets no title", %{token: token} do
      conn =
        post_rpc(:admin, message("initialize", initialize_params("2025-03-26")), token: token)

      refute Map.has_key?(result(conn)["serverInfo"], "title")
    end

    test "an id that is a string is echoed as it is", %{token: token} do
      conn = post_rpc(:admin, message("initialize", initialize_params(), "init-1"), token: token)
      assert json(conn)["id"] == "init-1"
    end

    test "without protocolVersion it is invalid params, answered 200 with the id", %{token: token} do
      conn = post_rpc(:admin, message("initialize", %{"capabilities" => %{}}, 4), token: token)

      assert conn.status == 200
      assert %{"id" => 4, "error" => %{"code" => -32_602}} = json(conn)
      assert error(conn)["message"] =~ "protocolVersion"
    end

    test "the public side needs no key and says so" do
      conn = post_rpc(:public, message("initialize", initialize_params()))

      assert conn.status == 200
      assert result(conn)["serverInfo"]["title"] =~ "public API"
      refute result(conn)["instructions"] =~ "system_get_identity"
    end

    test "a stale MCP-Protocol-Version header does not stop the handshake", %{token: token} do
      conn =
        post_rpc(:admin, message("initialize", initialize_params()),
          token: token,
          headers: [{"accept", "application/json"}, {"mcp-protocol-version", "1999-01-01"}]
        )

      assert conn.status == 200
    end
  end

  describe "ping and unknown methods" do
    test "ping is an empty result", %{token: token} do
      conn = post_rpc(:admin, message("ping", nil, 12), token: token)

      assert conn.status == 200
      assert json(conn) == %{"jsonrpc" => "2.0", "id" => 12, "result" => %{}}
    end

    test "a method we do not have is -32601, answered 200 with the id", %{token: token} do
      for method <- ["resources/list", "prompts/list", "completion/complete", "nope"] do
        conn = post_rpc(:admin, message(method, nil, "m"), token: token)

        assert conn.status == 200, method
        assert %{"id" => "m", "error" => %{"code" => -32_601, "message" => text}} = json(conn)
        assert text =~ method
      end
    end

    test "a very long method name is clipped in the answer", %{token: token} do
      conn = post_rpc(:admin, message(String.duplicate("m", 5_000)), token: token)
      assert String.length(error(conn)["message"]) < 200
    end
  end

  describe "messages that get no answer" do
    test "a notification is 202 with an empty body", %{token: token} do
      conn = post_rpc(:admin, notification("notifications/initialized"), token: token)

      assert conn.status == 202
      assert conn.resp_body == ""
    end

    test "a tools/call sent as a notification runs nothing", %{token: token} do
      message =
        notification("tools/call", %{
          "name" => "testkit_write_item",
          "arguments" => %{"name" => "x"}
        })

      conn = post_rpc(:admin, message, token: token)

      assert conn.status == 202
      refute_received {:write_item, _}
    end

    test "a response from the client is 202", %{token: token} do
      conn = post_rpc(:admin, %{"jsonrpc" => "2.0", "id" => 3, "result" => %{}}, token: token)
      assert conn.status == 202
    end
  end

  describe "malformed JSON-RPC is a 400 invalid request, never a 500" do
    test "each shape, with the id echoed when the message had a usable one", %{token: token} do
      cases = [
        {"a batch", %{"_json" => [message("ping"), message("ping", nil, 2)]}, nil},
        {"a bare number", %{"_json" => 7}, nil},
        {"a bare string", %{"_json" => "ping"}, nil},
        {"an empty object", %{}, nil},
        {"a wrong version", %{"jsonrpc" => "1.0", "id" => 1, "method" => "ping"}, 1},
        {"no jsonrpc member", %{"id" => 2, "method" => "ping"}, 2},
        {"no method", %{"jsonrpc" => "2.0", "id" => 3}, 3},
        {"a numeric method", %{"jsonrpc" => "2.0", "id" => 4, "method" => 5}, 4},
        {"a null id", %{"jsonrpc" => "2.0", "id" => nil, "method" => "ping"}, nil},
        {"a float id", %{"jsonrpc" => "2.0", "id" => 1.5, "method" => "ping"}, nil},
        {"a boolean id", %{"jsonrpc" => "2.0", "id" => true, "method" => "ping"}, nil}
      ]

      for {label, body, id} <- cases do
        conn = post_rpc(:admin, body, token: token)

        assert conn.status == 400, label
        assert ["application/json; charset=utf-8"] = get_resp_header(conn, "content-type")

        assert %{
                 "jsonrpc" => "2.0",
                 "id" => ^id,
                 "error" => %{"code" => -32_600, "message" => text}
               } =
                 json(conn),
               label

        assert is_binary(text) and text != ""
      end
    end

    test "no body at all", %{token: token} do
      conn =
        :post
        |> api_conn("/", token: token, headers: default_headers())
        |> MCP.call(MCP.init(audience: :admin))

      assert conn.status == 400
      assert error(conn)["code"] == -32_600
    end
  end

  describe "Accept" do
    test "must allow application/json, a missing header is fine", %{token: token} do
      ok = [
        [{"accept", "application/json"}],
        [{"accept", "application/json, text/event-stream"}],
        [{"accept", "text/event-stream, application/json;q=0.9"}],
        [{"accept", "*/*"}],
        [{"accept", "application/*"}],
        [{"accept", "APPLICATION/JSON"}],
        []
      ]

      for headers <- ok do
        conn = post_rpc(:admin, message("ping"), token: token, headers: headers)
        assert conn.status == 200, inspect(headers)
      end
    end

    test "text/event-stream alone is 406", %{token: token} do
      for accept <- ["text/event-stream", "text/html", "image/png, text/plain"] do
        conn = post_rpc(:admin, message("ping"), token: token, headers: [{"accept", accept}])

        assert conn.status == 406, accept
        assert error(conn)["code"] == -32_600
        assert error(conn)["message"] =~ "application/json"
      end
    end
  end

  describe "MCP-Protocol-Version" do
    test "a supported value or none is fine", %{token: token} do
      for version <- MCP.supported_versions() do
        headers = [{"accept", "application/json"}, {"mcp-protocol-version", version}]
        assert post_rpc(:admin, message("ping"), token: token, headers: headers).status == 200
      end

      assert post_rpc(:admin, message("ping"), token: token, headers: []).status == 200
    end

    test "an unsupported value is 400, with the id and the supported list", %{token: token} do
      headers = [{"accept", "application/json"}, {"mcp-protocol-version", "1999-01-01"}]
      conn = post_rpc(:admin, message("ping", nil, 5), token: token, headers: headers)

      assert conn.status == 400
      assert %{"id" => 5, "error" => %{"code" => -32_600, "message" => text}} = json(conn)
      assert text =~ "1999-01-01"
      assert text =~ "2025-06-18"
    end

    test "two values are 400", %{token: token} do
      conn =
        :post
        |> api_conn("/",
          token: token,
          body: message("ping"),
          headers: [{"accept", "application/json"}]
        )
        |> Map.update!(
          :req_headers,
          &(&1 ++ [{"mcp-protocol-version", "2025-06-18"}, {"mcp-protocol-version", "2025-03-26"}])
        )
        |> MCP.call(MCP.init(audience: :admin))

      assert conn.status == 400
    end
  end

  describe "methods and paths" do
    test "only POST: the others are 405 problems with Allow: POST and no CORS", %{token: token} do
      for method <- [:get, :put, :patch, :delete, :options, :head] do
        conn =
          method
          |> api_conn("/", token: token, headers: default_headers())
          |> MCP.call(MCP.init(audience: :admin))

        assert conn.status == 405, "#{method}"
        assert ["POST"] = get_resp_header(conn, "allow"), "#{method}"
        assert [] = get_resp_header(conn, "access-control-allow-origin"), "#{method}"
      end
    end

    test "the 405 is problem+json", %{token: token} do
      conn =
        :get
        |> api_conn("/", token: token, headers: default_headers())
        |> MCP.call(MCP.init(audience: :admin))

      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
      assert %{"code" => "method_not_allowed"} = json(conn)
    end

    test "the public side answers GET 405 too" do
      conn =
        :get |> api_conn("/", headers: default_headers()) |> MCP.call(MCP.init(audience: :public))

      assert conn.status == 405
    end

    test "a path below the endpoint is a 404 problem", %{token: token} do
      conn = post_rpc(:admin, message("ping"), token: token, path: "/tools")

      assert conn.status == 404
      assert %{"code" => "not_found"} = json(conn)
    end

    test "the success answers carry no CORS headers", %{token: token} do
      conn = post_rpc(:admin, message("ping"), token: token)
      assert [] = get_resp_header(conn, "access-control-allow-origin")
      conn = post_rpc(:public, message("ping"))
      assert [] = get_resp_header(conn, "access-control-allow-origin")
    end
  end

  describe "the checks of the REST side apply" do
    test "no key is a 401 problem with a bearer challenge" do
      conn = post_rpc(:admin, message("ping"))

      assert conn.status == 401
      assert [~s(Bearer error="invalid_token")] = get_resp_header(conn, "www-authenticate")
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
    end

    test "a wrong key is a 401 problem" do
      conn = post_rpc(:admin, message("ping"), token: "pk_00000000_" <> String.duplicate("A", 43))
      assert conn.status == 401
    end

    test "a credential in the URL is refused before anything else", %{token: token} do
      conn = post_rpc(:admin, message("ping"), token: token, path: "/?token=abc")

      assert conn.status == 400
      assert %{"code" => "token_in_url"} = json(conn)
    end

    test "with the switch off every request is a bare 404 problem", %{token: token} do
      switch(:admin, false)
      conn = post_rpc(:admin, message("ping"), token: token)
      assert conn.status == 404
      assert %{"code" => "not_found"} = json(conn)

      switch(:public, false)
      assert post_rpc(:public, message("ping")).status == 404
    end

    test "the two switches are independent", %{token: token} do
      switch(:public, false)
      assert post_rpc(:admin, message("ping"), token: token).status == 200
      assert post_rpc(:public, message("ping")).status == 404

      switch(:public, true)
      switch(:admin, false)
      assert post_rpc(:admin, message("ping"), token: token).status == 404
      assert post_rpc(:public, message("ping")).status == 200
    end
  end

  describe "the Origin check" do
    test "a foreign Origin is 403 before the key is looked at, and costs the failure bucket nothing" do
      ip = unique_ip()

      for _ <- 1..25 do
        conn =
          post_rpc(:admin, message("ping"),
            token: "pk_00000000_wrong",
            ip: ip,
            extra_headers: [{"origin", "https://evil.test"}]
          )

        assert conn.status == 403
        assert %{"code" => "origin_not_allowed"} = json(conn)
      end

      assert :ok = RateLimit.check_preauth(ip)
    end

    test "the install's own origin passes, a request without Origin passes", %{token: token} do
      ok =
        post_rpc(:admin, message("ping"),
          token: token,
          extra_headers: [{"origin", "https://shop.test"}]
        )

      assert ok.status == 200
      assert post_rpc(:admin, message("ping"), token: token).status == 200
    end

    test "the public side checks it too" do
      conn = post_rpc(:public, message("ping"), extra_headers: [{"origin", "https://evil.test"}])
      assert conn.status == 403
    end

    test "an origin from api_mcp_allowed_origins passes", %{token: token} do
      put_setting("api_mcp_allowed_origins", "https://client.example")

      conn =
        post_rpc(:admin, message("ping"),
          token: token,
          extra_headers: [{"origin", "https://client.example"}]
        )

      assert conn.status == 200
    end
  end

  describe "the cheap methods are throttled" do
    setup do
      wait_for_window_room()
    end

    test "public: initialize, ping, notifications and unknown methods share the IP bucket" do
      put_setting("api_public_ip_rate_per_min", 4)
      ip = unique_ip()

      assert 200 == post_rpc(:public, message("ping", nil, 1), ip: ip).status

      assert 200 ==
               post_rpc(:public, message("initialize", initialize_params(), 2), ip: ip).status

      assert 202 == post_rpc(:public, notification("notifications/initialized"), ip: ip).status
      assert 200 == post_rpc(:public, message("nope", nil, 4), ip: ip).status

      conn = post_rpc(:public, message("ping", nil, 5), ip: ip)

      assert conn.status == 429
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")

      assert %{"code" => "rate_limited", "context" => %{"retry_after" => retry_after}} =
               json(conn)

      assert retry_after > 0
      assert [_] = get_resp_header(conn, "retry-after")
    end

    test "admin: they cost the key's bucket", %{token: token} do
      put_setting("api_admin_rate_per_min", 2)

      assert 200 == post_rpc(:admin, message("ping"), token: token).status

      assert 202 ==
               post_rpc(:admin, notification("notifications/initialized"), token: token).status

      conn = post_rpc(:admin, message("initialize", initialize_params()), token: token)
      assert conn.status == 429
      assert [_] = get_resp_header(conn, "retry-after")
    end

    test "the answers carry the rate-limit headers", %{token: token} do
      conn = post_rpc(:admin, message("ping"), token: token)

      assert [_] = get_resp_header(conn, "ratelimit-limit")
      assert [_] = get_resp_header(conn, "ratelimit-remaining")
    end

    test "a refused request is not charged twice: invalid messages cost nothing", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      assert 400 == post_rpc(:admin, %{"_json" => [1]}, token: token).status
      assert 400 == post_rpc(:admin, %{}, token: token).status
      assert 200 == post_rpc(:admin, message("ping"), token: token).status
    end
  end
end
