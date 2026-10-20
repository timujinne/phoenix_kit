defmodule PhoenixKit.API.MCPToolsCallTest do
  @moduledoc """
  `tools/call` of the MCP plug: both name forms, results and errors as tool
  results, the arguments rules, the audit entry, the rate limit. Plug level,
  real keys, the fake module `PhoenixKit.Test.ApiTools`.
  """
  use PhoenixKit.DataCase, async: false

  import ExUnit.CaptureLog
  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness
  import PhoenixKit.Test.McpHarness
  import Plug.Conn

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Test.ApiTools

  @read "testkit.items:read"
  @write "testkit.items:write"

  defmodule ClashTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_clash_tools"
    def module_name, do: "Clash tools"
    def enabled?, do: true

    def api_tools do
      for {name, function, scope} <- [
            {"clash.one_two", :one, "clash.a:read"},
            {"clash_one.two", :two, "clash.b:read"}
          ] do
        Tool.new!(
          name: name,
          audience: :admin,
          scope: scope,
          permission: "dashboard",
          description: "Clash.",
          handler: {__MODULE__, function},
          annotations: %{read_only: true}
        )
      end
    end

    def one(_input, _ctx) do
      send(self(), :one)
      {:ok, %{"which" => "one"}}
    end

    def two(_input, _ctx) do
      send(self(), :two)
      {:ok, %{"which" => "two"}}
    end
  end

  defmodule NotFoundTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_not_found_tools"
    def module_name, do: "Not found tools"
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "notfound.get_thing",
          audience: :admin,
          scope: "testkit.items:read",
          permission: "dashboard",
          description: "A read whose subject does not exist.",
          handler: {__MODULE__, :get_thing},
          annotations: %{read_only: true}
        )
      ]
    end

    def get_thing(_input, _ctx),
      do: {:error, :not_found, "No such thing.", %{tool: "notfound.get_thing"}}
  end

  defmodule CountingTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_counting_tools"
    def module_name, do: "Counting tools"
    def enabled?, do: true

    # Every walk of the registry calls this once; the test reads the count.
    def api_tools do
      send(:persistent_term.get({__MODULE__, :observer}), :walked)

      [
        Tool.new!(
          name: "counting.public_ping",
          audience: :public,
          description: "Counting.",
          handler: {__MODULE__, :ping},
          annotations: %{read_only: true}
        )
      ]
    end

    def ping(_input, _ctx), do: {:ok, %{}}
  end

  setup do
    setup_api()
    {owner, role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{owner: owner, role: role, key: key, token: token}
  end

  defp call(token, tool, arguments \\ %{}, opts \\ []),
    do: post_rpc(:admin, call_message(tool, arguments), Keyword.put(opts, :token, token))

  defp flush_walks do
    receive do
      :walked -> flush_walks()
    after
      0 -> :ok
    end
  end

  defp text(result), do: result |> Map.fetch!("content") |> hd() |> Map.fetch!("text")

  defp problem(result),
    do: result |> Map.fetch!("content") |> Enum.at(1) |> Map.fetch!("text") |> JSON.decode!()

  defp audit_entries(key) do
    Repo.all(
      from(e in Entry,
        where: e.action == "api.request" and e.resource_uuid == ^key.uuid,
        order_by: e.inserted_at
      )
    )
  end

  describe "a successful call" do
    test "runs the tool; the text is the JSON, the structured content the same map", %{
      token: token
    } do
      conn = call(token, "testkit_read_items", %{"limit" => 4})

      assert conn.status == 200
      assert %{"jsonrpc" => "2.0", "id" => 1} = json(conn)

      result = result(conn)
      assert result["isError"] == false
      assert result["structuredContent"]["limit"] == 4
      assert JSON.decode!(text(result)) == result["structuredContent"]

      assert_received {:read_items, %{"limit" => 4}, ctx}
      assert ctx.audience == :admin
      assert ctx.actor.kind == :key
      assert ctx.scopes |> Enum.sort() == [@read, @write]
      assert is_binary(ctx.request_id)
    end

    test "the dotted name works the same", %{token: token} do
      result = token |> call("testkit.read_items", %{"limit" => 2}) |> result()

      assert result["isError"] == false
      assert result["structuredContent"]["limit"] == 2
    end

    test "the id of the request is echoed", %{token: token} do
      conn = post_rpc(:admin, call_message("testkit_read_items", %{}, "abc"), token: token)
      assert json(conn)["id"] == "abc"
    end

    test "effects of a handler are in the result", %{token: token} do
      result = token |> call("testkit_write_item", %{"name" => "x"}) |> result()

      assert result["structuredContent"]["written"] == "x"
      assert result["structuredContent"]["effects"] == [%{"code" => "item_indexed"}]
    end

    test "arguments absent or null mean an empty object", %{token: token} do
      for params <- [
            %{"name" => "testkit_read_items"},
            %{"name" => "testkit_read_items", "arguments" => nil}
          ] do
        conn = post_rpc(:admin, message("tools/call", params), token: token)
        assert result(conn)["isError"] == false, inspect(params)
        assert_received {:read_items, %{}, _ctx}
      end
    end

    test "a client of the oldest revision gets the text only", %{token: token} do
      headers = [{"accept", "application/json"}, {"mcp-protocol-version", "2025-03-26"}]
      result = token |> call("testkit_read_items", %{}, headers: headers) |> result()

      assert result["isError"] == false
      refute Map.has_key?(result, "structuredContent")
      assert %{"limit" => 10} = JSON.decode!(text(result))
    end

    test "system_get_identity is open to every valid key and answers for this key", %{
      token: token,
      key: key
    } do
      result = token |> call("system_get_identity") |> result()

      assert result["structuredContent"]["key"]["prefix"] == key.prefix
      assert result["structuredContent"]["scopes"] |> Enum.sort() == [@read, @write]
    end

    test "carries the rate-limit headers", %{token: token} do
      assert [_] = token |> call("testkit_read_items") |> get_resp_header("ratelimit-remaining")
    end
  end

  describe "the audit entry" do
    test "a write through MCP is logged once, with the dotted tool name", %{
      token: token,
      key: key
    } do
      call(token, "testkit_write_item", %{"name" => "x"})

      assert [entry] = audit_entries(key)
      assert entry.metadata["tool"] == "testkit.write_item"
      assert entry.metadata["outcome"] == "ok"
      assert entry.metadata["via"] == "api"
    end

    test "a read through MCP is not", %{token: token, key: key} do
      call(token, "testkit_read_items")
      assert audit_entries(key) == []
    end
  end

  describe "errors are tool results" do
    test "validation: HTTP 200, isError, [validation_failed], the problem document, no structured content",
         %{token: token} do
      conn = call(token, "testkit_write_item", %{"unknown_field" => 5})

      assert conn.status == 200
      result = result(conn)

      assert result["isError"] == true
      refute Map.has_key?(result, "structuredContent")
      assert text(result) =~ "[validation_failed] "
      assert text(result) =~ "context.errors"

      assert %{
               "code" => "validation_failed",
               "status" => 422,
               "context" => %{"errors" => [_ | _]}
             } =
               problem(result)

      assert problem(result)["request_id"] == hd(get_resp_header(conn, "x-request-id"))
      assert [_] = get_resp_header(conn, "ratelimit-remaining")
      refute_received {:write_item, _}
    end

    test "the id of the request is echoed in an isError result too", %{token: token} do
      conn = post_rpc(:admin, call_message("testkit_fail_write", %{}, "abc"), token: token)

      assert %{"id" => "abc", "result" => %{"isError" => true}} = json(conn)
    end

    test "a handler error carries the rate-limit headers", %{token: token} do
      conn = call(token, "testkit_fail_write")

      assert text(result(conn)) =~ "[insufficient_stock] "
      assert [_] = get_resp_header(conn, "ratelimit-remaining")
    end

    test "a missing scope names the scope", %{owner: owner} do
      {_key, read_only} = issue_key(owner, [@read])

      result = read_only |> call("testkit_write_item", %{"name" => "x"}) |> result()

      assert result["isError"] == true
      assert text(result) =~ "[forbidden] "
      assert problem(result)["context"]["required_scope"] == @write
      refute_received {:write_item, _}
    end

    test "an unknown tool, in either form, is a JSON-RPC -32602 error and not a tool result", %{
      token: token
    } do
      for name <- ["testkit_nope", "testkit.nope", "nope"] do
        conn = call(token, name, %{}, [])

        assert conn.status == 200, name
        assert %{"jsonrpc" => "2.0", "id" => 1} = body = json(conn)
        refute Map.has_key?(body, "result"), name
        assert %{"code" => -32_602, "message" => "Unknown tool: " <> ^name} = body["error"]
      end
    end

    test "an unknown tool name is clipped by code points, not graphemes", %{token: token} do
      # One letter and 200000 combining marks is a single grapheme.
      name = "a" <> String.duplicate("\u0301", 200_000)
      conn = call(token, name, %{}, [])

      assert %{"code" => -32_602, "message" => "Unknown tool: " <> echoed} = json(conn)["error"]
      assert String.length(echoed) == 1
      assert length(String.to_charlist(echoed)) == 80
    end

    test "the id of the request is echoed in an unknown tool error", %{token: token} do
      conn = post_rpc(:admin, call_message("testkit_nope", %{}, "abc"), token: token)

      assert %{"id" => "abc", "error" => %{"code" => -32_602}} = json(conn)
    end

    test "a very long name is clipped in the answer", %{token: token} do
      conn = call(token, String.duplicate("a", 5_000))

      assert %{"code" => -32_602, "message" => message} = error(conn)
      assert String.length(message) < 120
    end

    test "a handler that answers not_found stays an isError result", %{token: token} do
      :ok = ModuleRegistry.register(NotFoundTools)
      on_exit(fn -> ModuleRegistry.unregister(NotFoundTools) end)

      conn = call(token, "notfound_get_thing")

      assert conn.status == 200
      refute Map.has_key?(json(conn), "error")
      assert result(conn)["isError"] == true
      assert text(result(conn)) =~ "[not_found] No such thing."
    end

    test "a disabled module's tool is module_disabled in either form, not not_found", %{
      token: token
    } do
      ApiTools.set_enabled(false)

      for name <- ["testkit_read_items", "testkit.read_items"] do
        result = token |> call(name) |> result()

        assert result["isError"] == true, name
        assert text(result) =~ "[module_disabled] ", name
      end

      refute_received {:read_items, _, _}
    end

    test "a tool in api_disabled_tools is unknown", %{token: token} do
      put_setting("api_disabled_tools", "testkit.read_items")

      assert %{"code" => -32_602, "message" => "Unknown tool: testkit_read_items"} =
               token |> call("testkit_read_items") |> error()
    end

    test "a tool of a module whose API is switched off is unknown in either form", %{
      token: token
    } do
      put_setting("api_disabled_modules", "api_test_tools")

      for name <- ["testkit_read_items", "testkit.read_items"] do
        assert %{"code" => -32_602, "message" => "Unknown tool: " <> ^name} =
                 token |> call(name) |> error()
      end

      refute_received {:read_items, _, _}

      put_setting("api_disabled_modules", "")
      refute token |> call("testkit_read_items") |> result() |> Map.get("isError")
    end

    test "a handler that returns an error: its code and context", %{token: token} do
      result = token |> call("testkit_fail_write") |> result()

      assert text(result) =~ "[insufficient_stock] Three lines are short."
      assert problem(result)["context"] == %{"lines" => [%{"product" => "a"}]}
    end

    test "a handler that raises is a generic internal_error; only its class stays in the log and the key keeps working",
         %{token: token} do
      log =
        capture_log(fn ->
          send(self(), {:conn, call(token, "testkit_crash_write")})
        end)

      assert_received {:conn, conn}
      result = result(conn)

      assert result["isError"] == true
      assert text(result) =~ "[internal_error] The tool failed unexpectedly."
      refute conn.resp_body =~ "secret-detail"
      assert log =~ "RuntimeError"
      refute log =~ "secret-detail"

      assert token |> call("testkit_read_items") |> result() |> Map.fetch!("isError") == false
    end

    test "nothing the caller sent reaches the log: the tool name and an argument value", %{
      token: token
    } do
      log =
        capture_log(fn ->
          send(self(), {:unknown, call(token, "zz-sentinel-name", %{"zz_sentinel_field" => "x"})})

          send(
            self(),
            {:invalid,
             call(token, "testkit_write_item", %{"zz_sentinel_field" => "zz-sentinel-value"})}
          )
        end)

      assert_received {:unknown, unknown}
      assert_received {:invalid, invalid}
      assert %{"code" => -32_602} = json(unknown)["error"]
      assert text(result(invalid)) =~ "[validation_failed] "

      refute log =~ "zz-sentinel"
      refute log =~ "zz_sentinel"
    end

    test "an admin tool on the public endpoint, and a public tool on the admin one, are unknown",
         %{token: token} do
      public = post_rpc(:public, call_message("testkit_read_items"))
      assert %{"code" => -32_602} = error(public)

      admin = call(token, "testkit_public_echo", %{"text" => "x"})
      assert %{"code" => -32_602} = error(admin)
    end

    test "the public endpoint does not reveal admin tools: a real admin tool and an invented name get the same answer" do
      for {real, ghost} <- [
            {"testkit_write_item", "testkit_no_such_thing"},
            {"system_get_identity", "system_no_such_thing"},
            {"testkit.write_item", "testkit.no_such_thing"}
          ] do
        real_conn = post_rpc(:public, call_message(real))
        ghost_conn = post_rpc(:public, call_message(ghost))

        real_message = error(real_conn)["message"]
        ghost_message = error(ghost_conn)["message"]

        assert real_message =~ "Unknown tool: ", real
        assert real_message == String.replace(ghost_message, ghost, real), real

        # The dotted name of an admin tool is never printed for an underscore name.
        unless String.contains?(real, ".") do
          refute real_conn.resp_body =~ String.replace(real, "_", ".", global: false), real
        end
      end
    end

    test "nor does it reveal that an admin tool's module is switched off" do
      ApiTools.set_enabled(false)

      for name <- ["testkit_write_item", "testkit.write_item"] do
        message = post_rpc(:public, call_message(name)) |> error() |> Map.fetch!("message")

        assert message =~ "Unknown tool: ", name
        refute message =~ "module_disabled", name
      end
    end

    test "no answer ever repeats the key", %{token: token} do
      for conn <- [
            call(token, "testkit_nope"),
            call(token, "testkit_write_item", %{"x" => 1}),
            call(token, "testkit_read_items")
          ] do
        refute conn.resp_body =~ token
      end
    end
  end

  describe "params" do
    test "a missing, empty or non-string name is invalid params and runs nothing", %{token: token} do
      for params <- [
            %{},
            %{"arguments" => %{}},
            %{"name" => ""},
            %{"name" => 5},
            %{"name" => nil},
            "x"
          ] do
        conn = post_rpc(:admin, message("tools/call", params, 9), token: token)

        assert conn.status == 200, inspect(params)
        assert %{"id" => 9, "error" => %{"code" => -32_602, "message" => text}} = json(conn)
        assert text =~ "params.name"
      end
    end

    test "arguments that are not an object are invalid params and run nothing", %{token: token} do
      for arguments <- ["x", 5, [1], true] do
        conn =
          post_rpc(
            :admin,
            message("tools/call", %{"name" => "testkit_write_item", "arguments" => arguments}),
            token: token
          )

        assert %{"error" => %{"code" => -32_602, "message" => text}} = json(conn),
               inspect(arguments)

        assert text =~ "arguments"
      end

      refute_received {:write_item, _}
    end
  end

  describe "the rate limit" do
    setup do
      wait_for_window_room()
    end

    test "invalid params of tools/call cost a unit, on the admin endpoint", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      first = post_rpc(:admin, message("tools/call", %{}, 9), token: token)
      assert %{"error" => %{"code" => -32_602}} = json(first)
      assert [_] = get_resp_header(first, "ratelimit-remaining")

      second = post_rpc(:admin, message("tools/call", %{"name" => 5}, 9), token: token)
      assert second.status == 429
      assert [_] = get_resp_header(second, "retry-after")
    end

    test "invalid params of tools/call cost a unit, on the public endpoint, per address" do
      put_setting("api_public_ip_rate_per_min", 1)
      ip = unique_ip()

      first =
        post_rpc(:public, message("tools/call", %{"name" => "x", "arguments" => 5}, 9), ip: ip)

      assert %{"error" => %{"code" => -32_602}} = json(first)

      second = post_rpc(:public, message("tools/call", %{}, 9), ip: ip)
      assert second.status == 429
      assert [_] = get_resp_header(second, "retry-after")
    end

    test "a refusal is a 429 problem with Retry-After, not an isError result", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      assert call(token, "testkit_read_items").status == 200
      conn = call(token, "testkit_read_items")

      assert conn.status == 429
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")

      assert %{"code" => "rate_limited", "context" => %{"retry_after" => retry_after}} =
               json(conn)

      assert retry_after > 0
      assert [_] = get_resp_header(conn, "retry-after")
    end

    test "a call refused before the limiter still costs one unit: unknown, forbidden and disabled-module names are throttled",
         %{owner: owner} do
      {_key, read_only} = issue_key(owner, [@read])
      put_setting("api_admin_rate_per_min", 3)

      unknown = call(read_only, "testkit_nope")
      assert unknown.status == 200
      assert %{"code" => -32_602} = error(unknown)
      assert [_] = get_resp_header(unknown, "ratelimit-remaining")

      forbidden = call(read_only, "testkit_write_item", %{"name" => "x"})
      assert text(result(forbidden)) =~ "[forbidden] "

      ApiTools.set_enabled(false)
      assert text(read_only |> call("testkit_read_items") |> result()) =~ "[module_disabled] "

      refused = call(read_only, "testkit_nope")
      assert refused.status == 429
      assert %{"code" => "rate_limited"} = json(refused)
      assert [_] = get_resp_header(refused, "retry-after")
      refute_received {:write_item, _}
    end

    test "the same flood of invented names against the public endpoint is throttled per address" do
      put_setting("api_public_ip_rate_per_min", 2)
      ip = unique_ip()

      assert post_rpc(:public, call_message("testkit_nope"), ip: ip).status == 200
      assert post_rpc(:public, call_message("testkit_write_item"), ip: ip).status == 200

      refused = post_rpc(:public, call_message("testkit_nope"), ip: ip)
      assert refused.status == 429
      assert [_] = get_resp_header(refused, "retry-after")
    end

    test "an over-limit anonymous call walks the registry zero times, for any form of the name" do
      :ok = ModuleRegistry.register(CountingTools)
      :persistent_term.put({CountingTools, :observer}, self())

      on_exit(fn ->
        ModuleRegistry.unregister(CountingTools)
        :persistent_term.erase({CountingTools, :observer})
      end)

      put_setting("api_public_ip_rate_per_min", 1)
      ip = unique_ip()

      assert post_rpc(:public, call_message("counting_public_ping"), ip: ip).status == 200
      assert_received :walked
      flush_walks()

      for name <- ["counting_public_ping", "counting.public_ping", "no_such_tool", "system_ping"] do
        assert post_rpc(:public, call_message(name), ip: ip).status == 429
      end

      refute_received :walked
    end

    test "a call that reached the limiter is charged once, not twice", %{token: token} do
      put_setting("api_admin_rate_per_min", 2)

      assert call(token, "testkit_write_item", %{"unknown_field" => 1}).status == 200
      assert call(token, "testkit_write_item", %{"unknown_field" => 1}).status == 200
      assert call(token, "testkit_write_item", %{"unknown_field" => 1}).status == 429
    end

    test "a 120-row write costs three units", %{token: token} do
      put_setting("api_admin_rate_per_min", 3)
      # 120 rows is a batch to confirm under the default threshold of 50; the fixture does not
      # answer a dry run, so the threshold is raised to its maximum (120 rows are below it).
      put_setting("api_confirm_batch_over", 500)

      conn = call(token, "testkit_write_batch", %{"items" => List.duplicate(%{}, 120)})

      assert conn.status == 200
      assert result(conn)["isError"] == false
      assert result(conn)["structuredContent"] == %{"count" => 120}
      assert get_resp_header(conn, "ratelimit-remaining") == ["0"]

      assert post_rpc(:admin, message("ping"), token: token).status == 429
    end

    test "the public side is limited per IP" do
      put_setting("api_public_ip_rate_per_min", 1)
      ip = unique_ip()

      assert post_rpc(:public, call_message("testkit_public_echo", %{"text" => "a"}), ip: ip).status ==
               200

      assert post_rpc(:public, call_message("testkit_public_echo", %{"text" => "b"}), ip: ip).status ==
               429
    end
  end

  describe "the public endpoint" do
    test "runs a public tool with no key; the client token is never echoed" do
      conn =
        post_rpc(
          :public,
          call_message("testkit_public_echo", %{
            "text" => "hi",
            "session_token" => "my-session-token"
          })
        )

      result = result(conn)
      assert result["isError"] == false
      assert result["structuredContent"]["echo"] == "hi"
      assert is_binary(result["structuredContent"]["client_token_hash"])
      refute conn.resp_body =~ "my-session-token"
    end
  end

  describe "names that clash" do
    test "an underscore name reaches the first tool in registry order, the dotted name the one it names" do
      :ok = ModuleRegistry.register(ClashTools)
      on_exit(fn -> ModuleRegistry.unregister(ClashTools) end)

      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["clash.a:read", "clash.b:read"])

      assert call(token, "clash_one_two") |> result() |> Map.fetch!("structuredContent") == %{
               "which" => "one"
             }

      assert_received :one

      assert call(token, "clash_one.two") |> result() |> Map.fetch!("structuredContent") == %{
               "which" => "two"
             }

      assert_received :two
    end

    test "with different scopes the list shows the tool the key can run, the underscore name still reaches the first" do
      :ok = ModuleRegistry.register(ClashTools)
      on_exit(fn -> ModuleRegistry.unregister(ClashTools) end)

      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["clash.b:read"])

      listed = post_rpc(:admin, message("tools/list"), token: token) |> tool_names()
      assert "clash_one_two" in listed

      refused = call(token, "clash_one_two") |> result()
      assert refused["isError"] == true
      assert text(refused) =~ "[forbidden] "
      assert problem(refused)["context"]["required_scope"] == "clash.a:read"
      refute_received :one
      refute_received :two

      dotted = call(token, "clash_one.two") |> result()
      assert dotted["isError"] == false
      assert_received :two
    end
  end
end
