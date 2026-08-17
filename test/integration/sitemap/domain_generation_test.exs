defmodule PhoenixKit.Integration.Sitemap.DomainGenerationProviderStub do
  @moduledoc false
  def domains do
    [
      %{host: "gen.example.com", language: "en", primary: true},
      %{host: "gen.example.fr", language: "fr", primary: false}
    ]
  end
end

defmodule PhoenixKit.Integration.Sitemap.DomainGenerationDisabledSourceStub do
  @moduledoc """
  A sitemap source that is always disabled, used to prove that domain-mode
  generation in INDEX mode honors `enabled?/0` the same way the legacy
  per-module files do (unlike flat mode's documented force-collect).
  """
  @behaviour PhoenixKit.Modules.Sitemap.Sources.Source

  alias PhoenixKit.Modules.Sitemap.UrlEntry

  @impl true
  def source_name, do: :disabled_stub

  @impl true
  def enabled?, do: false

  @impl true
  def collect(_opts) do
    [
      UrlEntry.new(%{
        loc: "https://gen.example.com/secret-disabled-page",
        source: :disabled_stub
      })
    ]
  end
end

defmodule PhoenixKit.Integration.Sitemap.DomainGenerationTest do
  @moduledoc """
  End-to-end plumbing of DomainMode through Generator, FileStorage, Cache
  and the noindex branch: per-host files written, legacy set untouched,
  invalidate deletes domain files, noindex publishes empty per-host urlsets,
  stale host dirs cleaned up.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integration.Sitemap.DomainGenerationDisabledSourceStub, as: DisabledSource
  alias PhoenixKit.Integration.Sitemap.DomainGenerationProviderStub, as: Stub
  alias PhoenixKit.Modules.Sitemap
  alias PhoenixKit.Modules.Sitemap.Cache
  alias PhoenixKit.Modules.Sitemap.FileStorage
  alias PhoenixKit.Modules.Sitemap.Generator
  alias PhoenixKit.Settings

  @base_url "https://gen.example.com"

  setup do
    {:ok, _} = Settings.update_boolean_setting("sitemap_enabled", true)
    {:ok, _} = Settings.update_setting("site_url", @base_url)
    {:ok, _} = Settings.update_boolean_setting("crawlers_no_index", false)

    Application.put_env(:phoenix_kit, :sitemap_domains_provider, {Stub, :domains})

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
      Enum.each(FileStorage.list_domain_hosts(), &FileStorage.delete_domain_files/1)
    end)

    :ok
  end

  test "generation writes per-host files alongside the legacy set" do
    assert {:ok, _} = Generator.generate_all(base_url: @base_url)

    assert {:ok, com_path} = FileStorage.domain_file_path("gen.example.com")
    assert {:ok, fr_path} = FileStorage.domain_file_path("gen.example.fr")
    assert File.exists?(com_path)
    assert File.exists?(fr_path)
    assert File.exists?(FileStorage.file_path())

    assert File.read!(com_path) =~ "<urlset"
  end

  test "invalidate deletes domain files too" do
    {:ok, _} = Generator.generate_all(base_url: @base_url)
    assert FileStorage.list_domain_hosts() != []

    Cache.invalidate()
    assert FileStorage.list_domain_hosts() == []
  end

  test "noindex publishes empty urlsets per host" do
    {:ok, _} = Settings.update_boolean_setting("crawlers_no_index", true)
    assert {:ok, %{total_urls: 0}} = Generator.generate_all(base_url: @base_url)

    {:ok, com_path} = FileStorage.domain_file_path("gen.example.com")
    xml = File.read!(com_path)
    assert xml =~ "<urlset"
    refute xml =~ "<loc>"
  end

  test "stale host dirs are cleaned up on generation" do
    FileStorage.write_domain_sitemap("stale.example.org", "sitemap", "<urlset/>")
    assert "stale.example.org" in FileStorage.list_domain_hosts()

    {:ok, _} = Generator.generate_all(base_url: @base_url)
    refute "stale.example.org" in FileStorage.list_domain_hosts()
  end

  test "inactive provider leaves no domain dirs behind" do
    Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
    FileStorage.write_domain_sitemap("leftover.example.org", "sitemap", "<urlset/>")

    {:ok, _} = Generator.generate_all(base_url: @base_url)
    assert FileStorage.list_domain_hosts() == []
  end

  test "index mode domain files exclude disabled sources (no force-collect leak)" do
    # flat_mode?/0 is driven by router_discovery_enabled?/0 — disable it so
    # generation takes the INDEX path, where the legacy per-module files
    # have always honored `enabled?/0`. Domain-mode generation must match
    # that guarantee instead of unconditionally force-collecting (which
    # would leak a disabled source's URLs into the per-host files even
    # though they'd never appear in the legacy sitemap-index files).
    {:ok, _} = Settings.update_boolean_setting("sitemap_router_discovery_enabled", false)
    refute Sitemap.flat_mode?()

    original_sitemap_env = Application.get_env(:phoenix_kit, :sitemap, [])
    Application.put_env(:phoenix_kit, :sitemap, sources: [DisabledSource])

    on_exit(fn ->
      Application.put_env(:phoenix_kit, :sitemap, original_sitemap_env)
    end)

    assert {:ok, _} = Generator.generate_all(base_url: @base_url)

    {:ok, com_path} = FileStorage.domain_file_path("gen.example.com")
    refute File.read!(com_path) =~ "secret-disabled-page"
  end
end
