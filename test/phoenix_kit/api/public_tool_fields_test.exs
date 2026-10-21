defmodule PhoenixKit.API.PublicToolFieldsTest do
  @moduledoc """
  A public tool declares `language`, `currency` and `session_token` itself: core
  reserves only the control fields of a write tool. The tool passes the checks,
  is listed on every surface with those properties, validates them like any
  other property and hands them to the handler unchanged.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness
  import PhoenixKit.Test.McpHarness

  alias PhoenixKit.API.REST
  alias PhoenixKit.API.Tool
  alias PhoenixKit.API.ToolLint
  alias PhoenixKit.ModuleRegistry

  defmodule FieldTools do
    @moduledoc false

    def module_key, do: "api_public_fields_tools"
    def module_name, do: "Public field tools"
    def enabled?, do: true

    def tool_options do
      [
        name: "pubfields.search_things",
        audience: :public,
        title: "Search things",
        description:
          "Test tool: a public tool that declares language, currency and a client token.",
        input_schema: %{
          "type" => "object",
          "properties" => %{
            "language" => %{"type" => "string", "enum" => ["en", "de"]},
            "currency" => %{"type" => "string", "pattern" => "^[A-Z]{3}$"},
            "session_token" => %{"type" => "string"}
          },
          "additionalProperties" => false
        },
        output_schema: %{"type" => "object"},
        handler: {__MODULE__, :search},
        annotations: %{read_only: true, idempotent: true},
        client_token: "session_token"
      ]
    end

    def api_tools, do: [Tool.new!(tool_options())]

    def search(input, ctx) do
      send(self(), {:handler, input, ctx})
      {:ok, %{"seen" => input}}
    end
  end

  setup do
    setup_api()
    :ok = ModuleRegistry.register(FieldTools)
    on_exit(fn -> ModuleRegistry.unregister(FieldTools) end)
  end

  defp public_rest(path, opts),
    do: :post |> api_conn(path, opts) |> REST.call(REST.init(audience: :public))

  defp declared(schema), do: schema |> Map.fetch!("properties") |> Map.keys() |> Enum.sort()

  test "the tool passes Tool.new and the tool checks" do
    assert {:ok, %Tool{} = tool} = Tool.new(FieldTools.tool_options())
    assert :ok = ToolLint.check_tools([tool])
    assert :ok = ToolLint.check_tools(FieldTools.api_tools())
  end

  test "tools/list shows the three properties" do
    conn = post_rpc(:public, message("tools/list"))

    tool =
      conn
      |> result()
      |> Map.fetch!("tools")
      |> Enum.find(&(&1["name"] == "pubfields_search_things"))

    assert declared(tool["inputSchema"]) == ["currency", "language", "session_token"]
    assert tool["inputSchema"]["additionalProperties"] == false
  end

  test "openapi.json shows the three properties in the request body" do
    conn = :get |> api_conn("/openapi.json") |> REST.call(REST.init(audience: :public))
    operation = json(conn)["paths"]["/pubfields.search_things"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]

    assert declared(schema) == ["currency", "language", "session_token"]
  end

  test "a value reaches the handler unchanged, over REST" do
    body = %{"language" => "de", "currency" => "EUR", "session_token" => "abc"}
    conn = public_rest("/pubfields.search_things", body: body)

    assert conn.status == 200
    assert json(conn)["seen"] == body
    assert_received {:handler, ^body, _ctx}
  end

  test "a value reaches the handler unchanged, over MCP" do
    body = %{"language" => "en", "currency" => "USD"}
    conn = post_rpc(:public, call_message("pubfields_search_things", body))

    assert conn.status == 200
    assert result(conn)["isError"] != true
    assert_received {:handler, ^body, _ctx}
  end

  test "a value is validated like any other property" do
    for bad <- [%{"language" => "xx"}, %{"language" => 5}, %{"currency" => "eur"}] do
      conn = public_rest("/pubfields.search_things", body: bad)

      assert conn.status == 422
      assert json(conn)["code"] == "validation_failed"
      refute_received {:handler, _input, _ctx}
    end
  end

  test "an undeclared property is still refused" do
    conn = public_rest("/pubfields.search_things", body: %{"dry_run" => true})

    assert conn.status == 422
    refute_received {:handler, _input, _ctx}
  end

  test "the executor still refuses the control field names in a tool's schema" do
    for name <- ~w(dry_run confirm_token idempotency_key) do
      schema = %{
        "type" => "object",
        "properties" => %{name => %{"type" => "string"}, "session_token" => %{"type" => "string"}}
      }

      assert {:error, [message]} =
               FieldTools.tool_options() |> Keyword.put(:input_schema, schema) |> Tool.new()

      assert message =~ "input_schema.properties.#{name} is a field the executor adds itself"
    end
  end
end
