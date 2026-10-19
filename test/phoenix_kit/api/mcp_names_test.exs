defmodule PhoenixKit.API.MCP.NamesTest do
  @moduledoc """
  Tool names on MCP: `.` becomes `_`, both forms are accepted, and what the
  registry knows decides how an underscore name maps back.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.API.MCP.Names
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.ToolLint
  alias PhoenixKit.Test.ApiTools

  setup do
    setup_api()
    :ok
  end

  defp tool(name, audience \\ :admin) do
    Tool.new!(
      name: name,
      audience: audience,
      scope: if(audience == :admin, do: "demo.things:read"),
      permission: if(audience == :admin, do: "dashboard"),
      description: "A tool.",
      handler: {Kernel, :inspect}
    )
  end

  describe "to_mcp/1" do
    test "replaces the dot" do
      assert Names.to_mcp("ecommerce.set_prices") == "ecommerce_set_prices"
      assert Names.to_mcp("system.get_identity") == "system_get_identity"
    end

    test "agrees with the collision rule of ToolLint" do
      assert {:error, [message]} = ToolLint.check_tools([tool("a.b_c"), tool("a_b.c")])
      assert message =~ "share the MCP name #{Names.to_mcp("a.b_c")}"
      assert Names.to_mcp("a.b_c") == Names.to_mcp("a_b.c")
    end
  end

  describe "resolve/2" do
    test "a dotted name is returned as it is, known or not" do
      assert Names.resolve("testkit.read_items", :admin) == "testkit.read_items"
      assert Names.resolve("no.such_tool", :admin) == "no.such_tool"
    end

    test "an underscore name maps to the dotted name of a live tool" do
      assert Names.resolve("testkit_read_items", :admin) == "testkit.read_items"
      assert Names.resolve("system_get_identity", :admin) == "system.get_identity"
      assert Names.resolve("testkit_public_echo", :public) == "testkit.public_echo"
    end

    test "an unknown underscore name is returned as it is" do
      assert Names.resolve("no_such_tool", :admin) == "no_such_tool"
      assert Names.resolve("", :admin) == ""
    end

    test "a tool of the other audience is unknown: the name comes back as typed, never dotted" do
      assert Names.resolve("testkit_read_items", :public) == "testkit_read_items"
      assert Names.resolve("system_get_identity", :public) == "system_get_identity"
      assert Names.resolve("testkit_public_echo", :admin) == "testkit_public_echo"
    end

    test "a disabled module's underscore name still maps on its own audience, so the answer is module_disabled" do
      ApiTools.set_enabled(false)
      assert Names.resolve("testkit_write_item", :admin) == "testkit.write_item"
    end

    test "a disabled module's tool is as unknown as any other name on the other audience" do
      ApiTools.set_enabled(false)
      assert Names.resolve("testkit_write_item", :public) == "testkit_write_item"
    end

    test "a tool hidden by api_disabled_tools is unknown: the name comes back as typed, and the executor says not_found" do
      put_setting("api_disabled_tools", "testkit.read_items")
      assert Names.resolve("testkit_read_items", :admin) == "testkit_read_items"
    end
  end

  describe "resolve/2 and api_disabled_modules" do
    test "a tool of a module whose API is switched off is unknown: the name comes back as typed" do
      put_setting("api_disabled_modules", "api_test_tools")

      assert Names.resolve("testkit_read_items", :admin) == "testkit_read_items"
      assert Names.resolve("testkit_public_echo", :public) == "testkit_public_echo"
      # Core's tools belong to no module.
      assert Names.resolve("system_get_identity", :admin) == "system.get_identity"

      put_setting("api_disabled_modules", "")
      assert Names.resolve("testkit_read_items", :admin) == "testkit.read_items"
    end
  end

  describe "dedupe/1" do
    test "keeps the first of the tools that share an MCP name, in order" do
      first = tool("a.b_c")
      second = tool("a_b.c")
      other = tool("x.y")

      assert Names.dedupe([first, other, second]) == [first, other]
    end

    test "leaves a clean list alone" do
      tools = [tool("a.b"), tool("a.c"), tool("b.c")]
      assert Names.dedupe(tools) == tools
    end
  end
end
