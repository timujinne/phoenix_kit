defmodule PhoenixKit.API.ExecutorSharedTest do
  @moduledoc """
  The executor steps an approval repeats, as public functions: the tool must exist, be
  enabled and be within the scopes; the input must pass `max_items` and the closed schema;
  the handler context has one shape, with every key present.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiFlowHarness

  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.Registry
  alias PhoenixKit.API.Tool
  alias PhoenixKit.Test.ApiFlowTools

  @delete "flowkit.delete_items"

  setup do
    setup_flow()
    on_exit(fn -> ApiFlowTools.set_enabled(true) end)
    :ok
  end

  describe "authorize_tool/3" do
    test "a tool that exists, is enabled and whose scope is held" do
      assert {:ok, %Tool{name: @delete}} =
               Executor.authorize_tool(@delete, :admin, ["flowkit.items:delete"])
    end

    test "a scope that is not held names the scope" do
      assert {:error, :forbidden, _detail, %{required_scope: "flowkit.items:delete"}} =
               Executor.authorize_tool(@delete, :admin, ["flowkit.items:read"])
    end

    test "an unknown tool is not_found, and so is a public name asked on the admin side" do
      assert {:error, :not_found, _detail, _context} =
               Executor.authorize_tool("flowkit.nope", :admin, [])

      assert {:error, :not_found, _detail, _context} =
               Executor.authorize_tool("flowkit.mint_session", :admin, [])
    end

    test "a disabled module is module_disabled" do
      ApiFlowTools.set_enabled(false)

      assert {:error, :module_disabled, _detail, _context} =
               Executor.authorize_tool(@delete, :admin, ["flowkit.items:delete"])
    end
  end

  describe "validate_input/2" do
    setup do
      {:ok, tool} = Registry.find(@delete, :admin)
      %{tool: tool}
    end

    test "max_items is a hard limit", %{tool: tool} do
      assert {:ok, _} = Executor.validate_input(tool, %{"ids" => Enum.map(1..500, &"x#{&1}")})

      assert {:error, [%{path: "ids", limit: 500}]} =
               Executor.validate_input(tool, %{"ids" => Enum.map(1..501, &"x#{&1}")})
    end

    test "the closed schema: a wrong type and an unknown field are errors", %{tool: tool} do
      assert {:error, [%{path: "ids"} | _]} =
               Executor.validate_input(tool, %{"ids" => "not a list"})

      assert {:error, [%{path: path}]} =
               Executor.validate_input(tool, %{"ids" => ["a"], "surprise" => 1})

      assert path =~ "surprise"
    end
  end

  describe "context_from/1" do
    test "every key is always present, the keys are the ones context_keys/0 lists" do
      assert Enum.sort(Map.keys(Executor.context_from(%{}))) == Enum.sort(Executor.context_keys())

      assert Enum.sort(Map.keys(Executor.context_from(%{language: "en", dry_run?: true}))) ==
               Enum.sort(Executor.context_keys())
    end

    test "unknown fields are dropped, the defaults are the safe ones" do
      ctx = Executor.context_from(%{language: "de", surprise: 1})

      assert ctx.language == "de"
      refute Map.has_key?(ctx, :surprise)

      assert %{
               audience: :admin,
               hosts: [],
               dry_run?: false,
               approved_by_uuid: nil,
               confirmation_uuid: nil
             } = ctx

      assert ctx.progress.(%{"done" => 1}) == :ok
    end
  end
end
