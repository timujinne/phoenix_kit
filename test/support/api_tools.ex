defmodule PhoenixKit.Test.ApiTools do
  @moduledoc """
  A stand-in for a PhoenixKit module that declares API tools, for the tests
  of the executor, the REST plug and the routes.

  Register it with `PhoenixKit.Test.ApiHarness.setup_api/1`. It is a plain
  module with the callbacks `ModuleRegistry` calls, like the fake modules in
  `module_registry_test.exs`; `set_enabled/1` turns it off to test
  `module_disabled`.

  The tools run the handlers below, which tell the test what they were called
  with by sending messages to the test process (the handlers run in it).

  | Tool | Audience | Scope / permission | What it does |
  |---|---|---|---|
  | `testkit.read_items` | admin | `testkit.items:read` / `dashboard` | read; echoes the context; has a `fields` list (a read with a long list costs 1) |
  | `testkit.write_item` | admin | `testkit.items:write` / `settings` | write; returns `effects` |
  | `testkit.write_batch` | admin | `testkit.items:write` / `settings` | write; `items` list, `max_items` 500 |
  | `testkit.fail_write` | admin | `testkit.items:write` / `settings` | write; `{:error, :insufficient_stock, ...}` |
  | `testkit.crash_write` | admin | `testkit.items:write` / `settings` | write; raises |
  | `testkit.open_schema_write` | admin | `testkit.items:write` / `settings` | write; its schema does NOT say `additionalProperties: false` (the executor must close it) |
  | `testkit.public_echo` | public | none | read; echoes input and client token hash; has a `lines` list (a public call costs 1 whatever the list) |
  """

  alias PhoenixKit.API.Tool

  @enabled_key {__MODULE__, :enabled}

  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}
  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}

  def module_key, do: "api_test_tools"
  def module_name, do: "API test tools"

  def enabled?, do: :persistent_term.get(@enabled_key, true)

  @doc "Turns the module on or off, as an admin would on the Modules page."
  def set_enabled(on?) when is_boolean(on?), do: :persistent_term.put(@enabled_key, on?)

  def api_tools do
    [
      tool("testkit.read_items", "testkit.items:read", "dashboard", @read, :read_items, %{
        "limit" => %{"type" => "integer", "minimum" => 1, "maximum" => 100},
        "fields" => %{"type" => "array", "items" => %{"type" => "string"}}
      }),
      tool("testkit.write_item", "testkit.items:write", "settings", @write, :write_item, %{
        "name" => %{"type" => "string"}
      }),
      tool(
        "testkit.write_batch",
        "testkit.items:write",
        "settings",
        @write,
        :write_batch,
        %{"items" => %{"type" => "array", "items" => %{"type" => "object"}}},
        500
      ),
      tool("testkit.fail_write", "testkit.items:write", "settings", @write, :fail_write, %{}),
      tool("testkit.crash_write", "testkit.items:write", "settings", @write, :crash_write, %{}),
      open_schema_write_tool(),
      public_echo_tool()
    ]
  end

  # A module author who forgot `additionalProperties: false`. The executor
  # closes every schema (`Validator.close_schema/2`), so this tool must still
  # refuse `dry_run`, `confirm_token` and `idempotency_key`.
  defp open_schema_write_tool do
    Tool.new!(
      name: "testkit.open_schema_write",
      audience: :admin,
      scope: "testkit.items:write",
      permission: "settings",
      title: "Open schema write",
      description: "Test tool: a write whose schema is left open.",
      input_schema: %{
        "type" => "object",
        "properties" => %{"name" => %{"type" => "string"}}
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, :open_schema_write},
      annotations: @write
    )
  end

  defp tool(name, scope, permission, annotations, function, properties, max_items \\ nil) do
    Tool.new!(
      name: name,
      audience: :admin,
      scope: scope,
      permission: permission,
      title: name,
      description: "Test tool #{name}.",
      input_schema: %{
        "type" => "object",
        "properties" => properties,
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, function},
      annotations: annotations,
      max_items: max_items
    )
  end

  defp public_echo_tool do
    Tool.new!(
      name: "testkit.public_echo",
      audience: :public,
      title: "Public echo",
      description: "Test tool: echoes its input.",
      input_schema: %{
        "type" => "object",
        "properties" => %{
          "text" => %{"type" => "string"},
          "session_token" => %{"type" => "string"},
          "lines" => %{"type" => "array", "items" => %{"type" => "object"}}
        },
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, :public_echo},
      annotations: @read,
      client_token: "session_token"
    )
  end

  # --- handlers -------------------------------------------------------------

  def read_items(input, ctx) do
    send(self(), {:read_items, input, ctx})

    {:ok,
     %{
       "limit" => Map.get(input, "limit", 10),
       "language" => ctx.language,
       "request_id" => ctx.request_id,
       "base_url" => ctx.base_url,
       "dry_run" => ctx.dry_run?
     }}
  end

  def write_item(input, _ctx) do
    send(self(), {:write_item, input})
    {:ok, %{"written" => Map.get(input, "name")}, [%{"code" => "item_indexed"}]}
  end

  def write_batch(input, _ctx) do
    send(self(), {:write_batch, input})
    {:ok, %{"count" => length(Map.get(input, "items", []))}}
  end

  def fail_write(_input, _ctx) do
    send(self(), :fail_write)
    {:error, :insufficient_stock, "Three lines are short.", %{lines: [%{product: "a"}]}}
  end

  def crash_write(_input, _ctx) do
    send(self(), :crash_write)
    raise "boom with a secret-detail inside"
  end

  def open_schema_write(input, _ctx) do
    send(self(), {:open_schema_write, input})
    {:ok, %{"written" => Map.get(input, "name")}}
  end

  def public_echo(input, ctx) do
    {:ok, %{"echo" => Map.get(input, "text"), "client_token_hash" => ctx.actor.client_token_hash}}
  end
end
