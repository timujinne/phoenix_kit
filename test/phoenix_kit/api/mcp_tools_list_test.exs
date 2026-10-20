defmodule PhoenixKit.API.MCPToolsListTest do
  @moduledoc """
  `tools/list` of the MCP plug: who sees which tool, in which shape, under
  which name. Plug level, real keys, the fake module `PhoenixKit.Test.ApiTools`.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport, only: [wait_for_window_room: 0]
  import PhoenixKit.Test.ApiHarness
  import PhoenixKit.Test.McpHarness
  import Plug.Conn

  alias PhoenixKit.API.MCP.Shape
  alias PhoenixKit.API.ToolLint
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Test.ApiTools
  alias PhoenixKit.Users.Permissions

  @read "testkit.items:read"
  @write "testkit.items:write"

  defmodule CollidingTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "api_colliding_tools"
    def module_name, do: "Colliding tools"
    def enabled?, do: true

    def api_tools do
      for name <- ["clash.one_two", "clash_one.two"] do
        Tool.new!(
          name: name,
          audience: :admin,
          scope: "clash.items:read",
          permission: "dashboard",
          description: "Clash.",
          handler: {__MODULE__, :run},
          annotations: %{read_only: true}
        )
      end
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  defmodule BrokenTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    # An annotation may hold any term as far as the validator walks it; the verdict is seeded below.
    @schema %{"type" => "object", "properties" => %{}, "default" => {:not, :encodable}}

    def module_key, do: "api_broken_tools"
    def module_name, do: "Broken tools"
    def enabled?, do: true

    # A struct literal, not Tool.new!: Tool.validate/1 refuses this schema (a tuple is not
    # JSON), so the verdict on it is seeded in the cache that stands between a tool and the
    # validator. JSON encoding of the descriptor then raises.
    def api_tools do
      [
        struct!(Tool,
          name: "broken.list_things",
          audience: :admin,
          scope: "broken.items:read",
          permission: "dashboard",
          title: "Broken",
          description: "A tool whose schema cannot be encoded.",
          handler: {__MODULE__, :run},
          input_schema: @schema,
          output_schema: nil,
          annotations: %{
            read_only: true,
            destructive: false,
            idempotent: false,
            open_world: false
          }
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}

    # Seed BEFORE ModuleRegistry.register/1, forget in on_exit. The key layout is private to
    # Tool: if it changes, the tool is dropped (a warning, HTTP 200) and the test fails on
    # `conn.status == 500`, loudly, never vacuously.
    def seed_verdict, do: :persistent_term.put(verdict_key(), [])
    def forget_verdict, do: :persistent_term.erase(verdict_key())

    defp verdict_key do
      {Tool, :schema_problems, :input,
       @schema |> :erlang.term_to_binary([:deterministic]) |> :erlang.md5()}
    end
  end

  setup do
    setup_api()
    {owner, role} = user_with(["dashboard", "settings"])
    {key, token} = issue_key(owner, [@read, @write])
    %{owner: owner, role: role, key: key, token: token}
  end

  defp list(token, params \\ nil, opts \\ []),
    do: post_rpc(:admin, message("tools/list", params), Keyword.put(opts, :token, token))

  describe "which tools" do
    test "a read-only key sees the read tools and system.get_identity, with underscore names", %{
      owner: owner
    } do
      {_key, token} = issue_key(owner, [@read])

      names = token |> list() |> tool_names()

      assert "testkit_read_items" in names
      assert "system_get_identity" in names
      refute "testkit_write_item" in names
      refute "testkit_public_echo" in names
      refute Enum.any?(names, &String.contains?(&1, "."))
    end

    test "a key with both scopes sees every testkit tool", %{token: token} do
      names = token |> list() |> tool_names() |> Enum.sort()

      # system_get_identity is contained, not listed exactly: core also lists the scope-less
      # tool system.get_approval
      assert "system_get_identity" in names

      assert Enum.filter(names, &String.starts_with?(&1, "testkit_")) == [
               "testkit_crash_write",
               "testkit_fail_write",
               "testkit_open_schema_write",
               "testkit_read_items",
               "testkit_write_batch",
               "testkit_write_item"
             ]
    end

    test "the public side lists the public tools and needs no key" do
      conn = post_rpc(:public, message("tools/list"))

      assert conn.status == 200
      assert tool_names(conn) == ["testkit_public_echo"]
    end

    test "a module switched off drops out, core's tool stays", %{token: token} do
      ApiTools.set_enabled(false)

      names = token |> list() |> tool_names()

      # contains, not equals: core also lists the scope-less tool system.get_approval
      assert "system_get_identity" in names
      refute Enum.any?(names, &String.starts_with?(&1, "testkit_"))
    end

    test "a module whose API is switched off drops out, core's tool stays, and it comes back", %{
      token: token
    } do
      put_setting("api_disabled_modules", "api_test_tools")

      names = token |> list() |> tool_names()
      assert "system_get_identity" in names
      refute Enum.any?(names, &String.starts_with?(&1, "testkit_"))

      put_setting("api_disabled_modules", "")
      assert "testkit_read_items" in (token |> list() |> tool_names())
    end

    test "a tool in api_disabled_tools drops out", %{token: token} do
      put_setting("api_disabled_tools", "testkit.write_item")

      names = token |> list() |> tool_names()
      refute "testkit_write_item" in names
      assert "testkit_write_batch" in names
    end

    test "a permission the owner lost drops the tools it unlocked, on the very next request", %{
      token: token,
      role: role,
      key: key
    } do
      assert "testkit_write_item" in (token |> list() |> tool_names())
      assert_row_cached(key.prefix)

      assert :ok = Permissions.revoke_permission(role.uuid, "settings")

      assert_row_cached(key.prefix)
      names = token |> list() |> tool_names()
      refute "testkit_write_item" in names
      assert "testkit_read_items" in names
    end

    test "two tools with one MCP name are listed once, the first in registry order" do
      :ok = ModuleRegistry.register(CollidingTools)
      on_exit(fn -> ModuleRegistry.unregister(CollidingTools) end)

      {owner, _role} = user_with(["dashboard"])
      {_key, token} = issue_key(owner, ["clash.items:read"])

      tools = token |> list() |> result() |> Map.fetch!("tools")
      clashing = Enum.filter(tools, &(&1["name"] == "clash_one_two"))

      assert [%{"title" => "clash.one_two"}] = clashing
    end
  end

  describe "the shape of a tool" do
    test "name, description, closed input schema and hints", %{token: token} do
      tool =
        token
        |> list()
        |> result()
        |> Map.fetch!("tools")
        |> Enum.find(&(&1["name"] == "testkit_read_items"))

      assert tool["description"] == "Test tool testkit.read_items."
      assert tool["title"] == "testkit.read_items"
      assert tool["inputSchema"]["type"] == "object"
      assert tool["inputSchema"]["additionalProperties"] == false
      assert Map.keys(tool["inputSchema"]["properties"]) |> Enum.sort() == ["fields", "limit"]

      assert tool["annotations"] == %{
               "readOnlyHint" => true,
               "destructiveHint" => false,
               "idempotentHint" => true,
               "openWorldHint" => false
             }
    end

    test "a tool whose author forgot additionalProperties is closed on the wire", %{token: token} do
      tool =
        token
        |> list()
        |> result()
        |> Map.fetch!("tools")
        |> Enum.find(&(&1["name"] == "testkit_open_schema_write"))

      assert tool["inputSchema"]["additionalProperties"] == false
    end

    test "a write tool's output schema is the success shape or a preview, with an object root", %{
      token: token
    } do
      tool =
        token
        |> list()
        |> result()
        |> Map.fetch!("tools")
        |> Enum.find(&(&1["name"] == "testkit_write_item"))

      assert %{"type" => "object", "anyOf" => [%{"type" => "object"}, preview]} =
               tool["outputSchema"]

      assert preview["required"] == ["executed"]
      assert tool["annotations"]["readOnlyHint"] == false
    end

    test "a client of the oldest revision gets neither title nor outputSchema", %{token: token} do
      headers = [{"accept", "application/json"}, {"mcp-protocol-version", "2025-03-26"}]
      tools = token |> list(nil, headers: headers) |> result() |> Map.fetch!("tools")

      assert tools != []

      for tool <- tools do
        refute Map.has_key?(tool, "title"), tool["name"]
        refute Map.has_key?(tool, "outputSchema"), tool["name"]
      end
    end

    test "with no revision header it is the oldest revision too", %{token: token} do
      tools = token |> list(nil, headers: []) |> result() |> Map.fetch!("tools")

      assert tools != []
      refute Enum.any?(tools, &Map.has_key?(&1, "title"))
      refute Enum.any?(tools, &Map.has_key?(&1, "outputSchema"))
    end

    test "every schema on the wire passes the lint", %{token: token} do
      tools = token |> list() |> result() |> Map.fetch!("tools")
      assert tools != []

      for tool <- tools do
        assert :ok = ToolLint.check_schema(tool["inputSchema"], :input), tool["name"]
        assert :ok = ToolLint.check_schema(tool["outputSchema"], :output), tool["name"]
      end
    end

    test "is what Shape.tool_descriptor/2 builds", %{token: token} do
      {:ok, tool} = PhoenixKit.API.Registry.find("testkit.read_items", :admin)

      listed =
        token
        |> list()
        |> result()
        |> Map.fetch!("tools")
        |> Enum.find(&(&1["name"] == "testkit_read_items"))

      assert listed == JSON.decode!(JSON.encode!(Shape.tool_descriptor(tool, version())))
    end
  end

  describe "a tool that cannot be described" do
    test "is a 500 problem, logged by class only, and the key keeps working", %{owner: owner} do
      BrokenTools.seed_verdict()
      on_exit(&BrokenTools.forget_verdict/0)
      :ok = ModuleRegistry.register(BrokenTools)
      on_exit(fn -> ModuleRegistry.unregister(BrokenTools) end)

      {_key, token} = issue_key(owner, ["broken.items:read"])

      {conn, log} = ExUnit.CaptureLog.with_log(fn -> list(token) end)

      assert conn.status == 500
      assert ["application/problem+json" <> _] = get_resp_header(conn, "content-type")
      assert %{"code" => "internal_error"} = json(conn)
      refute conn.resp_body =~ "UndefinedError"

      # The class of the exception, nothing else: no stacktrace (it holds the conn and its
      # Authorization header), no key, no value from the schema.
      assert log =~ "MCP request failed"
      assert log =~ "Protocol.UndefinedError"
      refute log =~ ":encodable"
      refute log =~ "lib/phoenix_kit/"
      refute log =~ token
      refute String.downcase(log) =~ "authorization"
      refute String.downcase(log) =~ "bearer"

      assert post_rpc(:admin, message("ping"), token: token).status == 200
    end
  end

  describe "params" do
    test "none, an empty object and a null cursor are fine", %{token: token} do
      for params <- [nil, %{}, %{"cursor" => nil}, %{"_meta" => %{"progressToken" => 1}}] do
        conn = list(token, params)

        assert conn.status == 200, inspect(params)
        refute Map.has_key?(json(conn), "error"), inspect(params)
        assert "testkit_read_items" in tool_names(conn), inspect(params)
      end
    end

    test "a cursor is invalid params: the server never issues one", %{token: token} do
      conn = list(token, %{"cursor" => "abc"})

      assert conn.status == 200
      assert %{"id" => 1, "error" => %{"code" => -32_602, "message" => text}} = json(conn)
      assert text =~ "cursor"
    end

    test "params that are not an object are invalid params", %{token: token} do
      conn = list(token, ["x"])
      assert %{"error" => %{"code" => -32_602}} = json(conn)
    end
  end

  describe "the rate limit" do
    setup do
      wait_for_window_room()
      :ok
    end

    test "tools/list costs a unit, and a refusal is a 429 problem", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      assert list(token).status == 200
      conn = list(token)

      assert conn.status == 429
      assert %{"code" => "rate_limited", "context" => %{"retry_after" => _}} = json(conn)
      assert [_] = get_resp_header(conn, "retry-after")

      # The refusal still tells the client where its budget stands.
      assert get_resp_header(conn, "ratelimit-remaining") == ["0"]
      assert [_] = get_resp_header(conn, "ratelimit-limit")
      assert [_] = get_resp_header(conn, "ratelimit-reset")
    end

    test "the public side is throttled per address" do
      put_setting("api_public_ip_rate_per_min", 2)
      ip = unique_ip()

      assert post_rpc(:public, message("tools/list"), ip: ip).status == 200
      assert post_rpc(:public, message("tools/list"), ip: ip).status == 200

      conn = post_rpc(:public, message("tools/list"), ip: ip)
      assert conn.status == 429
      assert %{"code" => "rate_limited"} = json(conn)
    end

    test "a list refused as invalid params still costs a unit", %{token: token} do
      put_setting("api_admin_rate_per_min", 1)

      assert %{"error" => %{"code" => -32_602}} = token |> list(%{"cursor" => "abc"}) |> json()

      conn = list(token, %{"cursor" => "abc"})
      assert conn.status == 429
      assert %{"code" => "rate_limited"} = json(conn)
    end

    test "the same holds for params that are not an object, and on the public side", %{
      token: token
    } do
      put_setting("api_admin_rate_per_min", 1)
      assert %{"error" => _} = token |> list(["x"]) |> json()
      assert list(token, ["x"]).status == 429

      put_setting("api_public_ip_rate_per_min", 1)
      ip = unique_ip()
      bad = message("tools/list", %{"cursor" => "abc"})

      assert %{"error" => _} = :public |> post_rpc(bad, ip: ip) |> json()
      assert post_rpc(:public, bad, ip: ip).status == 429
    end

    test "the answer carries the rate-limit headers", %{token: token} do
      assert [_] = token |> list() |> get_resp_header("ratelimit-remaining")
    end
  end
end
