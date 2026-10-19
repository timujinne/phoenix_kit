defmodule PhoenixKit.Test.ApiLowercaseTools do
  @moduledoc """
  A stand-in feature module whose display name starts with a lowercase letter, for the
  test that the API guide sorts modules by name regardless of case. It declares one
  admin read tool, `lowercasekit.list_items`; a test registers it with
  `ModuleRegistry.register/1` and unregisters it in `on_exit`.
  """

  alias PhoenixKit.API.Tool

  def module_key, do: "lowercasekit"
  def module_name, do: "acme lowercase tools"
  def enabled?, do: true

  def api_tools do
    [
      Tool.new!(%{
        name: "lowercasekit.list_items",
        audience: :admin,
        scope: "lowercasekit.items:read",
        permission: "dashboard",
        title: "List items",
        description: "Lists the items.",
        input_schema: schema(),
        output_schema: schema(),
        handler: {__MODULE__, :handle},
        annotations: %{read_only: true, destructive: false, idempotent: true, open_world: false}
      })
    ]
  end

  def handle(_input, _ctx), do: {:ok, %{}}

  defp schema, do: %{"type" => "object", "properties" => %{}, "additionalProperties" => false}
end
