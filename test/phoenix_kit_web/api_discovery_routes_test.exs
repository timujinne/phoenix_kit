defmodule PhoenixKitWeb.APIDiscoveryRoutesTest do
  @moduledoc """
  Where `GET /mcp` and `/.well-known/api-catalog` are declared by
  `phoenix_kit_routes/0`: at the kit prefix and at the site root without a
  duplicate declaration, the catalog at the root only, for a kit mounted under
  a prefix (the test router) and for one mounted at the root (a router compiled
  here with `url_prefix: "/"`; a second declaration of one path would be a
  compile error or a doubled route).
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Config

  defp get_paths(router) do
    for %{verb: :get, path: path, plug_opts: action} <- router.__routes__(),
        action in [:guide, :api_catalog],
        do: {path, action}
  end

  defp other_method_paths(router) do
    for %{verb: verb, path: path, plug_opts: :not_allowed} <- router.__routes__(),
        do: {verb, path}
  end

  describe "a kit mounted under a prefix (the test router)" do
    test "the guide is declared once at the prefix and once at the root; the catalog once, at the root" do
      prefix = Config.get_url_prefix()
      assert prefix != "/"

      assert Enum.sort(get_paths(PhoenixKitWeb.Router)) ==
               Enum.sort([
                 {"/mcp", :guide},
                 {prefix <> "/mcp", :guide},
                 {"/.well-known/api-catalog", :api_catalog}
               ])
    end

    test "every other method on /mcp is declared once per place" do
      prefix = Config.get_url_prefix()
      paths = PhoenixKitWeb.Router |> other_method_paths() |> Enum.map(&elem(&1, 1))

      assert Enum.sort(paths) == Enum.sort(["/mcp", prefix <> "/mcp"])
    end
  end

  describe "a kit mounted at the root" do
    setup do
      previous = Application.fetch_env(:phoenix_kit, :url_prefix)
      Application.put_env(:phoenix_kit, :url_prefix, "/")
      Config.clear_url_prefix_cache()

      on_exit(fn ->
        case previous do
          {:ok, value} -> Application.put_env(:phoenix_kit, :url_prefix, value)
          :error -> Application.delete_env(:phoenix_kit, :url_prefix)
        end

        Config.clear_url_prefix_cache()
      end)

      :ok
    end

    test "each path is declared once" do
      module = Module.concat(__MODULE__, "RootProbeRouter#{System.unique_integer([:positive])}")

      Code.compile_quoted(
        quote do
          defmodule unquote(module) do
            use PhoenixKitWeb, :router

            import PhoenixKitWeb.Integration
            import PhoenixKitWeb.Users.Auth

            pipeline :browser do
              plug :accepts, ["html"]
            end

            phoenix_kit_routes()
          end
        end
      )

      assert Enum.sort(get_paths(module)) ==
               Enum.sort([{"/mcp", :guide}, {"/.well-known/api-catalog", :api_catalog}])

      assert module |> other_method_paths() |> Enum.map(&elem(&1, 1)) == ["/mcp"]
    end
  end
end
