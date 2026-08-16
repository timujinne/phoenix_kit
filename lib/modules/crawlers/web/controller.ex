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

  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.LlmsTxt

  @cache_max_age 3600

  def llms_txt(conn, _params) do
    if Crawlers.module_enabled?() do
      conn
      |> put_resp_content_type("text/markdown")
      |> put_resp_header("cache-control", "public, max-age=#{@cache_max_age}")
      |> send_resp(200, LlmsTxt.build())
    else
      send_resp(conn, 404, "Not Found")
    end
  end
end
