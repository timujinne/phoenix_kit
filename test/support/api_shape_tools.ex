defmodule PhoenixKit.Test.ApiShapeTools do
  @moduledoc """
  A second stand-in module for the executor tests only: tools whose handlers
  break the handler contract, and a public tool that is not read-only. They
  live apart from `PhoenixKit.Test.ApiTools` so that the shared fixture keeps
  the tool list the other tests assert on (REST, discovery, MCP). Only
  `executor_test.exs` registers this module.

  It is on while `PhoenixKit.Test.ApiTools` is on, so `ApiTools.set_enabled/1`
  switches both.

  | Tool | Audience | Scope / permission | What it does |
  |---|---|---|---|
  | `testkit.bad_shape` | admin | `testkit.items:write` / `settings` | write; returns a bare `:ok` (not a valid handler result) |
  | `testkit.bad_text` | admin | `testkit.items:write` / `settings` | write; returns a bare string carrying a secret |
  | `testkit.bad_utf8` | admin | `testkit.items:write` / `settings` | write; an error whose message is not valid UTF-8 |
  | `testkit.throw_write` | admin | `testkit.items:write` / `settings` | write; throws a very long term |
  | `testkit.exit_write` | admin | `testkit.items:write` / `settings` | write; exits with a very long reason |
  | `testkit.long_crash_write` | admin | `testkit.items:write` / `settings` | write; raises a `RuntimeError` with a 2000-code-point message (the log must not carry it) |
  | `testkit.echo_raise_write` | admin | `testkit.items:write` / `settings` | write; raises a `RuntimeError` that prints its `v` input |
  | `testkit.echo_argument_write` | admin | `testkit.items:write` / `settings` | write; raises an `ArgumentError` that prints its `v` input |
  | `testkit.echo_date_write` | admin | `testkit.items:write` / `settings` | write; `Date.from_iso8601!/1` on its `v` input (the stdlib message prints the input) |
  | `testkit.echo_module_write` | admin | `testkit.items:write` / `settings` | write; calls a function of the module named by its `v` input (the `UndefinedFunctionError` message prints it) |
  | `testkit.echo_atom_throw_write` | admin | `testkit.items:write` / `settings` | write; throws an atom made from its `v` input (`String.to_atom/1`) |
  | `testkit.echo_code_write` | admin | `testkit.items:write` / `settings` | write; returns an error whose code is an atom made from its `v` input |
  | `testkit.arith_write` | admin | `testkit.items:write` / `settings` | write; raises an `ArithmeticError` (its fixed message may be logged) |
  | `testkit.clause_write` | admin | `testkit.items:write` / `settings` | write; calls a function with an argument no clause matches (the stacktrace of a `FunctionClauseError` holds the arguments) |
  | `testkit.key_error_write` | admin | `testkit.items:write` / `settings` | write; `Map.fetch!/2` on a map that holds a secret (the `KeyError` message prints the map) |
  | `testkit.match_error_write` | admin | `testkit.items:write` / `settings` | write; a `MatchError` whose message prints a secret |
  | `testkit.changeset_write` | admin | `testkit.items:write` / `settings` | write; an `Ecto.InvalidChangesetError` whose message prints the changes, a secret among them |
  | `testkit.secret_throw_write` | admin | `testkit.items:write` / `settings` | write; throws a tuple that holds a secret |
  | `testkit.secret_exit_write` | admin | `testkit.items:write` / `settings` | write; exits with a tuple that holds a secret |
  | `testkit.public_write` | public | none | write (not read-only); anonymous callers, so the executor must write no `api.request` entry |
  """

  alias PhoenixKit.API.Tool
  alias PhoenixKit.Test.ApiTools

  @write %{read_only: false, destructive: false, idempotent: false, open_world: false}

  def module_key, do: "api_shape_tools"
  def module_name, do: "API shape test tools"

  def enabled?, do: ApiTools.enabled?()

  def api_problems do
    %{
      insufficient_stock: %{
        status: 422,
        title: "Insufficient stock",
        advice: "Reduce the quantities listed in context.lines; nothing was posted."
      }
    }
  end

  def api_tools do
    [
      admin_tool("testkit.bad_shape", :bad_shape),
      admin_tool("testkit.bad_text", :bad_text),
      admin_tool("testkit.bad_utf8", :bad_utf8),
      admin_tool("testkit.throw_write", :throw_write),
      admin_tool("testkit.exit_write", :exit_write),
      admin_tool("testkit.long_crash_write", :long_crash_write),
      admin_tool("testkit.clause_write", :clause_write),
      echo_tool("testkit.echo_raise_write", :echo_raise_write),
      echo_tool("testkit.echo_argument_write", :echo_argument_write),
      echo_tool("testkit.echo_date_write", :echo_date_write),
      echo_tool("testkit.echo_module_write", :echo_module_write),
      echo_tool("testkit.echo_atom_throw_write", :echo_atom_throw_write),
      echo_tool("testkit.echo_code_write", :echo_code_write),
      admin_tool("testkit.arith_write", :arith_write),
      admin_tool("testkit.key_error_write", :key_error_write),
      admin_tool("testkit.match_error_write", :match_error_write),
      admin_tool("testkit.changeset_write", :changeset_write),
      admin_tool("testkit.secret_throw_write", :secret_throw_write),
      admin_tool("testkit.secret_exit_write", :secret_exit_write),
      public_write_tool()
    ]
  end

  defp admin_tool(name, function), do: admin_tool(name, function, %{})

  # A tool that takes one string, `v`: the request-derived value its handler
  # crashes on.
  defp echo_tool(name, function),
    do: admin_tool(name, function, %{"v" => %{"type" => "string"}})

  defp admin_tool(name, function, properties) do
    Tool.new!(
      name: name,
      audience: :admin,
      scope: "testkit.items:write",
      permission: "settings",
      title: name,
      description: "Test tool #{name}.",
      input_schema: %{
        "type" => "object",
        "properties" => properties,
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, function},
      annotations: @write
    )
  end

  defp public_write_tool do
    Tool.new!(
      name: "testkit.public_write",
      audience: :public,
      title: "Public write",
      description: "Test tool: a public call that is not read-only.",
      input_schema: %{
        "type" => "object",
        "properties" => %{"text" => %{"type" => "string"}},
        "additionalProperties" => false
      },
      output_schema: %{"type" => "object"},
      handler: {__MODULE__, :public_write},
      annotations: @write
    )
  end

  # --- handlers -------------------------------------------------------------

  def bad_shape(_input, _ctx), do: :ok

  def bad_text(_input, _ctx), do: "secret-detail in a bare string"

  def bad_utf8(_input, _ctx),
    do: {:error, :validation_failed, <<0xFF, 0xFE, "secret-detail">>, %{}}

  def throw_write(_input, _ctx), do: throw({:boom, String.duplicate("t", 1_000)})

  def exit_write(_input, _ctx), do: exit({:boom, String.duplicate("x", 1_000)})

  def long_crash_write(_input, _ctx), do: raise(String.duplicate("e\u0301", 1_000))

  def echo_raise_write(%{"v" => v}, _ctx), do: raise("bad value #{inspect(v)}")

  def echo_argument_write(%{"v" => v}, _ctx), do: raise(ArgumentError, "invalid sku #{v}")

  def echo_date_write(%{"v" => v}, _ctx), do: {:ok, %{"date" => Date.from_iso8601!(v)}}

  def echo_module_write(%{"v" => v}, _ctx), do: Module.concat([v]).nope()

  def arith_write(_input, _ctx), do: {:ok, %{"x" => 1 / Process.get(:api_shape_tools_unset, 0)}}

  def clause_write(_input, _ctx), do: only_atoms("secret-argument")

  defp only_atoms(value) when is_atom(value), do: value

  # `Process.get/2` hides the value from the compiler, which would otherwise
  # warn that the call always fails or that the pattern can never match.
  def key_error_write(_input, _ctx) do
    :api_shape_tools_unset
    |> Process.get(%{token: "secret-argument"})
    |> Map.fetch!(:missing)
  end

  def match_error_write(_input, _ctx) do
    {:ok, _value} = Process.get(:api_shape_tools_unset, {:error, "secret-argument"})
  end

  def changeset_write(_input, _ctx) do
    changeset =
      {%{}, %{name: :string}}
      |> Ecto.Changeset.change(%{name: "secret-argument"})
      |> Ecto.Changeset.add_error(:name, "is invalid")

    raise Ecto.InvalidChangesetError, action: :insert, changeset: changeset
  end

  def secret_throw_write(_input, _ctx), do: throw({:error, "secret-argument"})

  def secret_exit_write(_input, _ctx), do: exit({:error, "secret-argument"})

  def echo_atom_throw_write(%{"v" => v}, _ctx), do: throw(String.to_atom(v))

  def echo_code_write(%{"v" => v}, _ctx), do: {:error, String.to_atom(v), "Refused.", %{}}

  def public_write(input, _ctx), do: {:ok, %{"echo" => Map.get(input, "text")}}
end
