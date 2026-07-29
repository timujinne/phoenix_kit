defmodule PhoenixKit.Integration.Sitemap.DomainServingProviderStub do
  @moduledoc false
  def domains do
    [
      %{host: "serve.example.com", language: "en", primary: true},
      %{host: "serve.example.fr", language: "fr", primary: false}
    ]
  end
end

defmodule PhoenixKit.Integration.Sitemap.DomainServingTest do
  @moduledoc """
  Controller-level contract of domain mode (plan Task 3): a mapped request
  host serves its own domain file with its own ETag (304 round-trip), an
  unmapped host keeps the legacy set, and the >50k chunk path stays
  reachable regardless of flat mode.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Integration.Sitemap.DomainServingProviderStub, as: Stub
  alias PhoenixKit.Modules.Sitemap.FileStorage
  alias PhoenixKit.Modules.Sitemap.Generator
  alias PhoenixKit.Settings

  @base_url "https://serve.example.com"

  setup do
    {:ok, _} = Settings.update_boolean_setting("sitemap_enabled", true)
    {:ok, _} = Settings.update_setting("site_url", @base_url)
    {:ok, _} = Settings.update_boolean_setting("seo_no_index", false)

    Application.put_env(:phoenix_kit, :sitemap_domains_provider, {Stub, :domains})
    {:ok, _} = Generator.generate_all(base_url: @base_url)

    on_exit(fn ->
      Application.delete_env(:phoenix_kit, :sitemap_domains_provider)
      Enum.each(FileStorage.list_domain_hosts(), &FileStorage.delete_domain_files/1)
    end)

    :ok
  end

  test "mapped host serves its domain file; ETags differ per host", %{conn: conn} do
    com_conn = %{conn | host: "serve.example.com"} |> get("/phoenix_kit/sitemap.xml")
    fr_conn = %{conn | host: "serve.example.fr"} |> get("/phoenix_kit/sitemap.xml")

    assert response(com_conn, 200) =~ "<urlset"
    assert response(fr_conn, 200) =~ "<urlset"

    [com_etag] = get_resp_header(com_conn, "etag")
    [fr_etag] = get_resp_header(fr_conn, "etag")
    refute com_etag == "\"default\""
    refute com_etag == fr_etag

    conn304 =
      %{build_conn() | host: "serve.example.com"}
      |> put_req_header("if-none-match", com_etag)
      |> get("/phoenix_kit/sitemap.xml")

    assert conn304.status == 304
  end

  test "unmapped host keeps the legacy set", %{conn: conn} do
    legacy = %{conn | host: "unmapped.example.org"} |> get("/phoenix_kit/sitemap.xml")
    assert response(legacy, 200)
  end

  test "a mapped host's chunk filename resolves in its domain dir even in flat mode", %{
    conn: conn
  } do
    # Simulate a split: write a chunk file directly; flat mode must not 404 it.
    :ok = FileStorage.write_domain_sitemap("serve.example.com", "sitemap-2", "<urlset/>")
    {:ok, _} = Settings.update_boolean_setting("sitemap_router_discovery_enabled", true)

    chunk = %{conn | host: "serve.example.com"} |> get("/phoenix_kit/sitemaps/sitemap-2.xml")
    assert response(chunk, 200) =~ "<urlset"
  end
end
