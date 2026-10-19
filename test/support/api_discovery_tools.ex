defmodule PhoenixKit.Test.DiscoveryTools do
  @moduledoc """
  A stand-in feature module for the tests of the public discovery documents
  (`PhoenixKit.API.PublicDiscovery`).

  Its public tools differ in what the guide shows (a read tool that needs no
  input, one that needs a field, a write tool that can ask for confirmation,
  one whose description is markup), and it also declares an **admin** tool with
  a distinctive name, scope and permission (`zzleak`), so the leak test can
  prove that no public document names it. `put_extra/1` adds public tools while
  a test runs; `set_enabled/1` switches the module off.

  Register it with `register!/0`.
  """

  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleRegistry

  @enabled_key {__MODULE__, :enabled}
  @extra_key {__MODULE__, :extra}

  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}
  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}

  @doc "The markup in the description of `zzdisc.markup_tool`."
  def markup, do: ~s|<script>alert(1)</script><img src=x onerror=alert(2)> & "quoted"|

  def admin_scope, do: "zzleak.things:write"
  def admin_permission, do: "zzleak_perm"

  def module_key, do: "zzdisc"
  def module_name, do: "Discovery test tools"
  def enabled?, do: :persistent_term.get(@enabled_key, true)

  @doc "Turns the module on or off, as an admin would on the Modules page."
  def set_enabled(on?) when is_boolean(on?), do: :persistent_term.put(@enabled_key, on?)

  @doc "Adds public tools (`Tool` structs) to the module's list until the test ends."
  def put_extra(tools) when is_list(tools) do
    :persistent_term.put(@extra_key, tools)
    ExUnit.Callbacks.on_exit(fn -> :persistent_term.erase(@extra_key) end)
  end

  @doc "Registers the module for the current test and unregisters it afterwards."
  def register! do
    :ok = ModuleRegistry.register(__MODULE__)
    set_enabled(true)

    ExUnit.Callbacks.on_exit(fn ->
      ModuleRegistry.unregister(__MODULE__)
      set_enabled(true)
    end)
  end

  @doc "A public tool with the given attributes, for `put_extra/1`."
  def public_tool(name, attrs \\ []) do
    Tool.new!(
      Keyword.merge(
        [
          name: name,
          audience: :public,
          title: "Extra tool",
          description: "An extra public tool.",
          input_schema: %{
            "type" => "object",
            "properties" => %{},
            "additionalProperties" => false
          },
          output_schema: %{"type" => "object"},
          handler: {__MODULE__, :handle},
          annotations: @read
        ],
        attrs
      )
    )
  end

  def api_tools do
    [
      public_tool("zzdisc.search_things",
        title: "Search things",
        description: "Finds things.\nSecond line of the description.",
        input_schema: %{
          "type" => "object",
          "properties" => %{"query" => %{"type" => "string"}},
          "additionalProperties" => false
        }
      ),
      public_tool("zzdisc.browse_required",
        title: "Browse (needs a field)",
        description: "Needs a field, so it is never the example call.",
        input_schema: %{
          "type" => "object",
          "properties" => %{"id" => %{"type" => "string"}},
          "required" => ["id"],
          "additionalProperties" => false
        }
      ),
      public_tool("zzdisc.add_thing",
        title: "Add a thing",
        description: "Adds a thing.",
        annotations: @write,
        danger: :always
      ),
      public_tool("zzdisc.markup_tool", title: "Markup", description: markup()),
      admin_tool()
    ] ++ :persistent_term.get(@extra_key, [])
  end

  defp admin_tool do
    Tool.new!(
      name: "zzleak.reset_things",
      audience: :admin,
      scope: admin_scope(),
      permission: admin_permission(),
      title: "Reset things",
      description: "Admin only.",
      input_schema: %{"type" => "object", "properties" => %{}, "additionalProperties" => false},
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, :handle},
      annotations: @write
    )
  end

  def handle(_input, _ctx), do: {:ok, %{}}
end
