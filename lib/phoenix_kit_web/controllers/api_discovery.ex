defmodule PhoenixKitWeb.Controllers.ApiDiscovery do
  @moduledoc """
  The public pages about the public API: the guide `GET /mcp` and the API
  catalog `GET /.well-known/api-catalog`.

  Both answer from `PhoenixKit.API.PublicDiscovery`, whose one predicate decides
  whether anything is published; when it is not, they answer the same `404`
  problem document as the public API itself. They are routed beside
  `/llms.txt`: no session, no CSRF, no `CrawlerBlocker`.

  `/mcp` answers in this order: visibility (`404`), method (`405`, any
  method but `GET` and `HEAD`), representation (`406` for a client that asked
  for an event stream only), then `200`. A hidden guide therefore never names
  the MCP server.
  """
  use PhoenixKitWeb, :controller

  alias PhoenixKit.API.Problem
  alias PhoenixKit.API.PublicDiscovery
  alias PhoenixKit.API.PublicDiscovery.Accept
  alias PhoenixKit.API.PublicDiscovery.GuideHTML
  alias PhoenixKit.API.PublicDiscovery.GuideMarkdown

  @doc "The guide, as HTML or Markdown."
  def guide(conn, params) do
    case PublicDiscovery.check(conn) do
      {:ok, tools} -> negotiate(conn, params, tools)
      :hidden -> not_found(conn)
    end
  end

  @doc "Any method but `GET` and `HEAD` on `/mcp`: this is the guide, not the MCP server."
  def not_allowed(conn, _params) do
    case PublicDiscovery.check(conn) do
      {:ok, _tools} ->
        conn
        |> put_resp_header("allow", "GET, HEAD")
        |> Problem.send(
          :method_not_allowed,
          "This is the guide. The MCP server is #{mcp_url(conn)}.",
          %{allow: "GET, HEAD"}
        )

      :hidden ->
        not_found(conn)
    end
  end

  @doc "The API catalog (RFC 9727)."
  def api_catalog(conn, _params) do
    case PublicDiscovery.check(conn) do
      {:ok, _tools} ->
        origin = PublicDiscovery.origin(conn)

        conn
        |> put_resp_header("content-type", PublicDiscovery.catalog_content_type())
        |> put_resp_header("access-control-allow-origin", "*")
        |> put_resp_header("cache-control", PublicDiscovery.cache_control())
        |> PublicDiscovery.put_link(PublicDiscovery.catalog_link(origin))
        |> send_resp(200, JSON.encode!(PublicDiscovery.api_catalog(origin)))

      :hidden ->
        not_found(conn)
    end
  end

  defp negotiate(conn, params, tools) do
    case Accept.representation(params["format"], get_req_header(conn, "accept")) do
      :not_acceptable ->
        conn
        |> put_resp_header("vary", "accept")
        |> Problem.send(
          :not_acceptable,
          "This is the guide, not the MCP server. The MCP server is #{mcp_url(conn)}.",
          %{}
        )

      representation ->
        send_guide(conn, representation, PublicDiscovery.guide(conn, tools))
    end
  end

  defp send_guide(conn, representation, guide) do
    {content_type, body} = document(representation, guide)

    conn
    |> put_resp_header("content-type", content_type)
    |> put_resp_header("content-language", guide.language)
    |> put_resp_header("vary", "accept")
    |> put_resp_header("cache-control", PublicDiscovery.cache_control())
    |> PublicDiscovery.put_link(PublicDiscovery.catalog_link(guide.origin))
    |> send_resp(200, body)
  end

  defp document(:html, guide), do: {"text/html; charset=utf-8", GuideHTML.render(guide)}

  defp document(:markdown, guide),
    do: {"text/markdown; charset=utf-8", GuideMarkdown.render(guide)}

  defp mcp_url(conn), do: conn |> PublicDiscovery.origin() |> PublicDiscovery.mcp_url()

  # The public API's own 404, as `PhoenixKit.API.Auth` answers it.
  defp not_found(conn), do: Problem.send(conn, :not_found, "", %{})
end
