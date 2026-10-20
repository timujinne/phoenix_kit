defmodule PhoenixKit.API.PathsTest do
  @moduledoc """
  `PhoenixKit.API.Paths`, the one table of API paths that the router macro
  (`PhoenixKit.Integration`) and `PhoenixKit.API.BodyGuard` both read, and
  `PhoenixKit.API.Legacy`, whose alias paths it appends.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.API.Legacy
  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.Paths
  alias PhoenixKit.API.REST
  alias PhoenixKit.Utils.Routes

  defp canonical, do: for({_, _, _, :canonical} = entry <- Paths.entries(), do: entry)
  defp aliases, do: for({_, _, _, {:alias, _}} = entry <- Paths.entries(), do: entry)

  describe "the canonical entries" do
    test "are the admin and public REST and MCP paths, in that order" do
      segment = Paths.public_segment()

      assert canonical() == [
               {["api", "admin", "v1"], :admin, false, :canonical},
               {["api", segment, "v1"], :public, true, :canonical},
               {["mcp", "admin"], :admin, false, :canonical},
               {["mcp", segment], :public, false, :canonical}
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

  describe "the alias entries" do
    test "come from PhoenixKit.API.Legacy, are public, and point to the canonical path" do
      assert Enum.map(aliases(), &elem(&1, 0)) == Legacy.alias_paths()

      for {segments, audience, cors?, {:alias, successor}} <- aliases() do
        assert audience == :public
        assert hd(segments) in ["api", "mcp"]

        case hd(segments) do
          "api" ->
            assert cors?
            assert successor == Paths.rest_path(:public)

          "mcp" ->
            refute cors?
            assert successor == Paths.mcp_path(:public)
        end
      end
    end

    test "never collide with a canonical path" do
      all = Enum.map(Paths.entries(), &elem(&1, 0))
      assert all == Enum.uniq(all)
    end

    test "the helpers never return an alias" do
      alias_paths = Enum.map(Legacy.alias_paths(), &("/" <> Enum.join(&1, "/")))

      for audience <- [:admin, :public] do
        refute Paths.rest_path(audience) in alias_paths
        refute Paths.mcp_path(audience) in alias_paths
      end
    end
  end

  describe "forward data" do
    test "the plug follows the transport, the options follow the entry" do
      assert Paths.plug(["api", "admin", "v1"]) == REST
      assert Paths.plug(["mcp", "admin"]) == MCP

      for {_, audience, _, :canonical} = entry <- canonical() do
        assert Paths.plug_opts(entry) == [audience: audience]
      end

      for {segments, :public, _cors, {:alias, successor}} = entry <- aliases() do
        assert Paths.plug_opts(entry) ==
                 [
                   audience: :public,
                   deprecated: [path: "/" <> Enum.join(segments, "/"), successor: successor]
                 ]
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
        for {segments, _audience, _cors?, _kind} = entry <- Paths.entries() do
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
