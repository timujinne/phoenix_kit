defmodule PhoenixKit.Modules.Crawlers.Web.Controller do
  @moduledoc """
  Serves `/llms.txt` for the Crawlers module.

  Mounted at the site root and under the kit prefix, mirroring
  `/sitemap.xml`'s reasoning: tools look for these files at the root, and the
  prefixed copy exists so prefix-only installs still have the endpoint.

  404s when the Crawlers module is disabled — a policy document served from a
  switched-off policy module would be a lie about who is deciding.
  """
  use PhoenixKitWeb, :controller

  alias PhoenixKit.API.PublicDiscovery
  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.LlmsTxt
  alias PhoenixKit.WebsiteAccess.Gate

  @cache_max_age 3600

  def llms_txt(conn, _params) do
    if Crawlers.module_enabled?() do
      conn
      |> put_resp_content_type("text/markdown")
      |> put_resp_header("cache-control", "public, max-age=#{@cache_max_age}")
      |> put_api_section()
    else
      send_resp(conn, 404, "Not Found")
    end
  end

  # While the public API is published (`PhoenixKit.API.PublicDiscovery.check/1`)
  # the file ends with its section and points to the API catalog. With the
  # website gate on that depends on the client address, so a shared cache must
  # not keep the answer.
  defp put_api_section(conn) do
    case PublicDiscovery.check(conn) do
      {:ok, _tools} ->
        origin = PublicDiscovery.origin(conn)

        conn
        |> PublicDiscovery.put_link(PublicDiscovery.catalog_link(origin))
        |> put_gate_cache_control()
        |> send_resp(200, LlmsTxt.build(api_section: PublicDiscovery.llms_section(origin)))

      :hidden ->
        send_resp(conn, 200, LlmsTxt.build())
    end
  end

  defp put_gate_cache_control(conn) do
    if Gate.enabled?(),
      do: put_resp_header(conn, "cache-control", "private, no-store"),
      else: conn
  end
end
