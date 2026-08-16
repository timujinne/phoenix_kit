defmodule PhoenixKit.Integration.Sitemap.DomainGenerationProviderStub do
  @moduledoc false
  def domains do
    [
      %{host: "gen.example.com", language: "en", primary: true},
      %{host: "gen.example.fr", language: "fr", primary: false}
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

  alias PhoenixKit.Integration.Sitemap.DomainGenerationProviderStub, as: Stub
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
end
