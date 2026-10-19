defmodule PhoenixKit.API.PublicDiscovery do
  @moduledoc """
  What the install publishes, without a key, about its public API: the guide
  `GET /mcp`, the API catalog `/.well-known/api-catalog` (RFC 9727), the `Link`
  headers that point to them and the API section of `/llms.txt`.

  Everything here is built from `PhoenixKit.API.Registry.visible_tools/2` of
  the **public** audience on every request (nothing is cached), so a module
  that is switched off or a tool hidden in Settings -> API is gone from the
  documents at once. Nothing here names the admin API: a document served
  without a key never mentions an admin path, tool, scope or permission.

  ## One predicate

  `check/1` and `visible?/1` decide whether anything is published at all, and
  every document and header of this module asks it:

    1. the public API switch is on (`PhoenixKit.API.Config.public_enabled?/0`);
    2. the website password gate does not hide the site from this client
       (`PhoenixKit.API.Auth.gated?/2`): a gated pre-production site publishes
       nothing it would not serve through the API itself;
    3. at least one public tool is visible. The list is returned, so one
       request walks the registry once.

  ## Which host a document names

  The `Host` header is never trusted by itself (`PhoenixKit.API.RequestContext`
  defaults its `:hosts` to the request host, so "the host is one of the hosts"
  proves nothing on a default install). `origin/1` uses the request host only
  when it is a well-formed hostname **and** one of the hosts
  `PhoenixKit.API.MCP.Origin.known_hosts/1` lists (the canonical host and the
  hosts the `:api_request_context` hook explicitly returns); else it uses
  `PhoenixKit.API.MCP.Origin.canonical_origin/0`. Never
  `PhoenixKit.Utils.Routes.base_url/0`, which reads the database uncached.

  The scheme and the port never come from the request either, whatever its
  `Host` port or `X-Forwarded-Proto` say: the canonical host is named by
  `canonical_origin/0` as it is, any other known host takes the canonical
  scheme and the canonical port (none when that is the scheme's default).
  The documents are cached publicly, so a request must not shape them.

  The API and the guide live under the kit's URL prefix (`PhoenixKit.Utils.Routes.path/1`);
  `/llms.txt` and `/.well-known/*` are origin-root URLs.
  """

  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.MCP.Origin
  alias PhoenixKit.API.PublicDiscovery.Guide
  alias PhoenixKit.API.Registry
  alias PhoenixKit.API.RequestContext
  alias PhoenixKit.API.Tool
  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.RecipientLocale
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.WebsiteAccess.Gate

  @host_grammar ~r/\A[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\z/

  @catalog_path "/.well-known/api-catalog"

  @catalog_content_type ~s(application/linkset+json; profile="https://www.rfc-editor.org/info/rfc9727")

  @doc """
  Whether anything is published for `conn`, with the public tools that make it
  so. The three parts are checked in the order of the moduledoc, cheapest first.
  """
  @spec check(Plug.Conn.t()) :: {:ok, [Tool.t()]} | :hidden
  def check(%Plug.Conn{} = conn) do
    with true <- Config.public_enabled?(),
         false <- Auth.gated?(conn, :public),
         [_ | _] = tools <- Registry.visible_tools(:public, :all) do
      {:ok, tools}
    else
      _hidden -> :hidden
    end
  end

  @doc "Whether anything is published for `conn` (`check/1`)."
  @spec visible?(Plug.Conn.t()) :: boolean()
  def visible?(%Plug.Conn{} = conn), do: match?({:ok, _tools}, check(conn))

  @doc """
  The `Cache-Control` of a published document.

  While the website gate is on the answer depends on the client address, so a
  shared cache must not keep it.
  """
  @spec cache_control() :: String.t()
  def cache_control do
    if Gate.enabled?(), do: "private, no-store", else: "public, max-age=300"
  end

  # --- hosts and URLs -----------------------------------------------------------

  @doc """
  The origin (`scheme://host[:port]`) the documents for `conn` name, by the
  rule of the moduledoc.
  """
  @spec origin(Plug.Conn.t()) :: String.t()
  def origin(%Plug.Conn{host: host} = conn) do
    canonical = Origin.canonical_origin()
    %URI{host: canonical_host} = URI.parse(canonical)
    host = String.downcase(host)

    cond do
      host == canonical_host ->
        canonical

      Regex.match?(@host_grammar, host) and host in Origin.known_hosts(conn) ->
        Origin.origin_with_host(canonical, host)

      true ->
        canonical
    end
  end

  @doc "The URL of the guide under `origin`."
  @spec guide_url(String.t()) :: String.t()
  def guide_url(origin), do: origin <> Routes.path("/mcp")

  @doc "The URL of the public MCP server under `origin`."
  @spec mcp_url(String.t()) :: String.t()
  def mcp_url(origin), do: origin <> Routes.path("/mcp/shop")

  @doc "The URL of the public REST API under `origin`."
  @spec api_url(String.t()) :: String.t()
  def api_url(origin), do: origin <> Routes.path("/api/shop/v1")

  @doc "The URL of the public OpenAPI description under `origin`."
  @spec openapi_url(String.t()) :: String.t()
  def openapi_url(origin), do: api_url(origin) <> "/openapi.json"

  @doc "The URL of the API catalog: at the origin root, whatever the URL prefix."
  @spec catalog_url(String.t()) :: String.t()
  def catalog_url(origin), do: origin <> @catalog_path

  @doc "The URL of `/llms.txt`: at the origin root, whatever the URL prefix."
  @spec llms_url(String.t()) :: String.t()
  def llms_url(origin), do: origin <> "/llms.txt"

  # --- language -----------------------------------------------------------------

  @doc """
  The language a page for `context` is written in: the domain's language
  reduced to a locale `PhoenixKitWeb.Gettext` has a catalogue for, else `"en"`.
  """
  @spec language(RequestContext.t()) :: String.t()
  def language(%{language: language}) when is_binary(language) do
    locale = RecipientLocale.gettext_locale(language)

    if locale in Gettext.known_locales(PhoenixKitWeb.Gettext), do: locale, else: "en"
  end

  # --- the guide ----------------------------------------------------------------

  @doc """
  The content of the guide for `conn`, as one map the two renderers
  (`PhoenixKit.API.PublicDiscovery.GuideHTML`, `PhoenixKit.API.PublicDiscovery.GuideMarkdown`)
  turn into text. `tools` is the list `check/1` returned.
  """
  @spec guide(Plug.Conn.t(), [Tool.t()]) :: map()
  def guide(%Plug.Conn{} = conn, tools) when is_list(tools) do
    context = RequestContext.resolve(conn)
    Guide.build(origin(conn), language(context), tools, Settings.get_project_title())
  end

  # --- the API catalog ------------------------------------------------------------

  @doc "The `Content-Type` of the API catalog."
  @spec catalog_content_type() :: String.t()
  def catalog_content_type, do: @catalog_content_type

  @doc "The API catalog (RFC 9727 linkset) naming the origin's public API."
  @spec api_catalog(String.t()) :: map()
  def api_catalog(origin) do
    api = api_url(origin)

    %{
      "linkset" => [
        %{"anchor" => catalog_url(origin), "item" => [%{"href" => api}]},
        %{
          "anchor" => api,
          "service-desc" => [%{"href" => openapi_url(origin), "type" => "application/json"}],
          "service-doc" => [%{"href" => guide_url(origin), "type" => "text/html"}]
        }
      ]
    }
  end

  # --- Link headers -----------------------------------------------------------------

  @doc """
  Adds `value` to the `Link` header of `conn`, after the value an earlier plug
  may have set (one header, values joined by a comma, as RFC 8288 allows). A
  value that is already there is not repeated, and a blank earlier header is
  ignored.
  """
  @spec put_link(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_link(%Plug.Conn{} = conn, value) when is_binary(value) do
    earlier =
      conn
      |> Plug.Conn.get_resp_header("link")
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))

    if value in Enum.flat_map(earlier, &String.split(&1, ~r/,\s*(?=<)/)),
      do: conn,
      else: Plug.Conn.put_resp_header(conn, "link", Enum.join(earlier ++ [value], ", "))
  end

  @doc "The `Link` header value that points to the API catalog."
  @spec catalog_link(String.t()) :: String.t()
  def catalog_link(origin), do: ~s(<#{catalog_url(origin)}>; rel="api-catalog")

  @doc """
  The `Link` header of `GET /api/shop/v1`, the tool list: the OpenAPI
  description and the guide. Added on a `200` only, and only when the guide
  is published; the check runs when the answer is sent.
  """
  @spec put_list_links(Plug.Conn.t()) :: Plug.Conn.t()
  def put_list_links(%Plug.Conn{} = conn) do
    Plug.Conn.register_before_send(conn, fn conn ->
      with 200 <- conn.status, true <- visible?(conn) do
        origin = origin(conn)

        put_link(
          conn,
          ~s(<#{openapi_url(origin)}>; rel="service-desc", <#{guide_url(origin)}>; rel="service-doc")
        )
      else
        _no_links -> conn
      end
    end)
  end

  @doc """
  Adds `Link: <guide>; rel="service-doc"` to the `405` of `GET /mcp/shop` when
  the guide is published.
  """
  @spec put_service_doc_link(Plug.Conn.t()) :: Plug.Conn.t()
  def put_service_doc_link(%Plug.Conn{} = conn) do
    if visible?(conn) do
      put_link(conn, ~s(<#{guide_url(origin(conn))}>; rel="service-doc"))
    else
      conn
    end
  end

  # --- llms.txt ---------------------------------------------------------------------

  @doc "The API section of `/llms.txt` for `origin`, to append after the operator's text."
  @spec llms_section(String.t()) :: String.t()
  def llms_section(origin) do
    """
    ## Shop API and MCP

    - [How to connect](#{guide_url(origin)}): MCP server and REST API for the shop, no key needed
    - [MCP server](#{mcp_url(origin)}): Streamable HTTP
    - [OpenAPI](#{openapi_url(origin)})
    """
  end
end
