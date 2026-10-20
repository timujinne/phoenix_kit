defmodule PhoenixKit.Integration.Sitemap.RouterDiscoveryPublicApiTest do
  @moduledoc """
  The public API's own pages (the guide, the API catalog) and `/llms.txt` are
  answered with `404` while the public API is off or gated, so they must never
  be listed in `sitemap.xml` by the default router discovery.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Sitemap.Sources.RouterDiscovery
  alias PhoenixKit.Settings

  @base_url "https://example.test"

  setup do
    previous = Application.get_env(:phoenix_kit, :router)
    Application.put_env(:phoenix_kit, :router, PhoenixKitWeb.Router)
    {:ok, _} = Settings.update_boolean_setting("sitemap_router_discovery_enabled", true)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:phoenix_kit, :router, previous),
        else: Application.delete_env(:phoenix_kit, :router)
    end)

    :ok
  end

  test "the default filter keeps /mcp, the API catalog and /llms.txt out of the sitemap" do
    paths =
      [base_url: @base_url]
      |> RouterDiscovery.collect()
      |> Enum.map(&(&1.loc |> URI.parse() |> Map.fetch!(:path)))

    for path <- paths do
      refute path =~ ~r{(\A|/)mcp\z}, "listed: #{path}"
      refute path =~ "api-catalog", "listed: #{path}"
      refute path =~ "llms.txt", "listed: #{path}"
    end
  end
end
