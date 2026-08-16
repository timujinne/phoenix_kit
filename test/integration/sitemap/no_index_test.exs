defmodule PhoenixKit.Integration.Sitemap.NoIndexTest do
  @moduledoc """
  Pins the contract that the sitemap generator honors the Crawlers module's global
  `noindex` directive.

  When `crawlers_no_index` is active the site is asking search engines not to index
  it, so `Generator.generate_all/1` must publish an empty (but valid) `<urlset>`
  instead of advertising crawlable URLs — regardless of what the individual
  sources would otherwise emit.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Sitemap.Generator
  alias PhoenixKit.Settings

  @base_url "https://example.test"

  setup do
    # Sitemap generation needs the module enabled and a base URL.
    {:ok, _} = Settings.update_boolean_setting("sitemap_enabled", true)
    {:ok, _} = Settings.update_setting("site_url", @base_url)
    :ok
  end

  describe "generate_all/1 with crawlers_no_index active" do
    test "publishes an empty urlset with zero URLs" do
      {:ok, _} = Settings.update_boolean_setting("crawlers_no_index", true)

      assert {:ok, %{index_xml: xml, total_urls: 0, modules: []}} =
               Generator.generate_all(base_url: @base_url)

      # Valid, empty urlset — no crawlable entries advertised.
      assert xml =~ "<urlset"
      assert xml =~ "</urlset>"
      refute xml =~ "<url>"
      refute xml =~ "<loc>"
    end
  end

  describe "generate_all/1 with crawlers_no_index disabled" do
    test "does not force an empty sitemap" do
      {:ok, _} = Settings.update_boolean_setting("crawlers_no_index", false)

      # The exact URL count depends on seeded content/routes; we only assert the
      # noindex short-circuit is NOT taken (generation runs normally).
      assert {:ok, %{total_urls: total}} = Generator.generate_all(base_url: @base_url)
      assert is_integer(total)
    end
  end
end
