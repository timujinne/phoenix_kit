defmodule PhoenixKit.API.PathsTest do
  @moduledoc """
  `PhoenixKit.API.Paths`, the one table of API paths that the router macro
  (`PhoenixKit.Integration`) and `PhoenixKit.API.BodyGuard` both read.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.Paths
  alias PhoenixKit.API.REST
  alias PhoenixKit.Utils.Routes

  describe "the entries" do
    test "are the admin and public REST and MCP paths, in that order" do
      segment = Paths.public_segment()

      assert Paths.entries() == [
               {["api", "admin", "v1"], :admin, false},
               {["api", segment, "v1"], :public, true},
               {["mcp", "admin"], :admin, false},
               {["mcp", segment], :public, false}
             ]
    end

    test "the public audience's segment is the one constant, and is not the admin's" do
      assert Paths.public_segment() == "public"
      refute Paths.public_segment() == "admin"
    end

    test "rest_path/1 and mcp_path/1 derive from the entries" do
      assert Paths.rest_path(:admin) == "/api/admin/v1"
      assert Paths.rest_path(:public) == "/api/#{Paths.public_segment()}/v1"
      assert Paths.mcp_path(:admin) == "/mcp/admin"
      assert Paths.mcp_path(:public) == "/mcp/#{Paths.public_segment()}"
    end
  end

  describe "uniqueness" do
    test "no path appears twice" do
      all = Enum.map(Paths.entries(), &elem(&1, 0))
      assert all == Enum.uniq(all)
    end
  end

  describe "forward data" do
    test "the plug follows the transport, the options follow the entry" do
      assert Paths.plug(["api", "admin", "v1"]) == REST
      assert Paths.plug(["mcp", "admin"]) == MCP

      for {_, audience, _} = entry <- Paths.entries() do
        assert Paths.plug_opts(entry) == [audience: audience]
      end
    end
  end

  describe "the router" do
    @router PhoenixKitWeb.Router

    test "forwards exactly the entries of Paths.entries/0" do
      prefix = String.split(Routes.prefix_base(), "/", trim: true)

      forwards =
        for %{plug: plug, plug_opts: opts, metadata: %{forward: forward}} <-
              @router.__routes__(),
            plug in [REST, MCP],
            uniq: true,
            do: {forward, plug, opts}

      expected =
        for {segments, _audience, _cors?} = entry <- Paths.entries() do
          {prefix ++ segments, Paths.plug(segments), Paths.plug_opts(entry)}
        end

      assert Enum.sort(forwards) == Enum.sort(expected)
    end
  end

  describe "the public segment" do
    # The code (not the docs) that builds or matches an API path.
    @code_files Path.wildcard("lib/phoenix_kit/api/**/*.ex") ++
                  [
                    "lib/phoenix_kit_web/integration.ex",
                    "lib/phoenix_kit/install/endpoint_integration.ex"
                  ]

    defp code_literals(file) do
      {:ok, ast} = file |> File.read!() |> Code.string_to_quoted()

      {_ast, literals} =
        Macro.prewalk(ast, [], fn
          {:@, _, [{doc, _, _}]}, acc when doc in [:moduledoc, :doc, :typedoc] -> {nil, acc}
          literal, acc when is_binary(literal) -> {literal, [literal | acc]}
          node, acc -> {node, acc}
        end)

      literals
    end

    test "is spelled in Paths and nowhere else in the code that builds a path" do
      spelled =
        for file <- @code_files,
            literal <- code_literals(file),
            literal == Paths.public_segment() or
              String.contains?(literal, [
                "api/#{Paths.public_segment()}",
                "mcp/#{Paths.public_segment()}"
              ]),
            do: {file, literal}

      assert spelled == [{"lib/phoenix_kit/api/paths.ex", Paths.public_segment()}]
    end
  end
end
