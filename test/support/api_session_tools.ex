defmodule PhoenixKit.Test.ApiSessionTools do
  @moduledoc """
  A stand-in feature module with two **read** tools that declare the same scope but need
  different permissions, for the tests of `PhoenixKit.API.Executor.execute_as/5` and
  `visible_for/3`: a session holds that scope only when its scope holds both permissions.

  | Tool | Scope | Permission |
  |---|---|---|
  | `sessiontest.read_a` | `sessiontest.shared:read` | `dashboard` |
  | `sessiontest.read_b` | `sessiontest.shared:read` | `users` |

  The handlers send `{:session_tool, name, ctx}` to the calling process.
  """

  alias PhoenixKit.API.Tool

  @read %{read_only: true, destructive: false, idempotent: true, open_world: false}

  def module_key, do: "api_session_tools"
  def module_name, do: "API session test tools"
  def enabled?, do: true

  def scope, do: "sessiontest.shared:read"

  def api_tools, do: [tool(:read_a, "dashboard"), tool(:read_b, "users")]

  def read_a(_input, ctx), do: answer("sessiontest.read_a", ctx)
  def read_b(_input, ctx), do: answer("sessiontest.read_b", ctx)

  defp answer(name, ctx) do
    send(self(), {:session_tool, name, ctx})
    {:ok, %{"tool" => name}}
  end

  defp tool(verb, permission) do
    Tool.new!(
      name: "sessiontest.#{verb}",
      audience: :admin,
      scope: scope(),
      permission: permission,
      title: Atom.to_string(verb),
      description: "Test tool #{verb}.",
      input_schema: %{"type" => "object", "properties" => %{}, "additionalProperties" => false},
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, verb},
      annotations: @read
    )
  end
end
