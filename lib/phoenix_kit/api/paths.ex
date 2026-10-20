defmodule PhoenixKit.API.Paths do
  @moduledoc """
  The one table of API paths. The router macro (`PhoenixKitWeb.Integration`)
  forwards every entry to its plug, and `PhoenixKit.API.BodyGuard` guards every
  entry, so the two cannot disagree about where the API lives.

  The axis of the API is the audience, not a module: modules own the names of
  their tools (`catalogue.set_prices`), the paths are

      /api/admin/v1   /mcp/admin     the admin audience, with a key
      /api/public/v1  /mcp/public    the public audience, without one

  under the kit's URL prefix. The segment that names the public audience is
  `public_segment/0`, the only place it is spelled: renaming the public
  prefix is a change of that one line.

  ## Entries

  `entries/0` lists `{segments, audience, cors?, kind}`:

    * `segments`, the path under the URL prefix, split by `/`;
    * `audience`, `:admin` or `:public`, which decides the plug's options and
      the switch `PhoenixKit.API.BodyGuard` looks at;
    * `cors?`, whether the answers carry the CORS headers of the public REST
      audience (`PhoenixKit.API.REST`), the guard's included;
    * `kind`, `:canonical`, or `{:alias, canonical_path}` for a deprecated
      path (`PhoenixKit.API.Legacy`) that is served by the same plug as
      `canonical_path`.

  Anything that builds a URL for a client (`PhoenixKit.API.OpenAPI`,
  `PhoenixKit.API.PublicDiscovery`) takes `rest_path/1` and `mcp_path/1`,
  which are canonical by construction: no document, catalog, guide or `Link`
  header advertises an alias.

  ## A deprecated path

  The forward of an alias carries `deprecated: [path: ..., successor: ...]`
  next to `audience:`. `PhoenixKit.API.Auth` then puts `Deprecation`
  (`PhoenixKit.API.Legacy.deprecation/0`) and `Link: <canonical>;
  rel="successor-version"` on every answer it lets through to the transport
  (`put_deprecation/2`), and logs the first use of the path on a node once.
  A request the API turns away with its bare `404` (switch off, website
  password gate) carries neither: such a path reveals nothing.
  """

  require Logger

  alias PhoenixKit.API.Legacy
  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.PublicDiscovery
  alias PhoenixKit.API.REST
  alias PhoenixKit.Utils.Routes

  @public_segment "public"

  @type segments :: [String.t()]
  @type kind :: :canonical | {:alias, String.t()}
  @type entry :: {segments(), :admin | :public, boolean(), kind()}

  @doc """
  The path segment that names the public audience in `/api/<segment>/v1` and
  `/mcp/<segment>`: the one place it is spelled.
  """
  @spec public_segment() :: String.t()
  def public_segment, do: @public_segment

  @doc """
  Every path the API answers on, canonical entries first and then the
  deprecated aliases. See the moduledoc for the shape.
  """
  @spec entries() :: [entry()]
  def entries do
    [
      {["api", "admin", "v1"], :admin, false, :canonical},
      {["api", @public_segment, "v1"], :public, true, :canonical},
      {["mcp", "admin"], :admin, false, :canonical},
      {["mcp", @public_segment], :public, false, :canonical}
    ] ++ Enum.map(Legacy.alias_paths(), &alias_entry/1)
  end

  defp alias_entry(["api" | _] = segments),
    do: {segments, :public, true, {:alias, rest_path(:public)}}

  defp alias_entry(["mcp" | _] = segments),
    do: {segments, :public, false, {:alias, mcp_path(:public)}}

  @doc "The canonical path of the REST API of `audience`, without the URL prefix."
  @spec rest_path(:admin | :public) :: String.t()
  def rest_path(:admin), do: path(["api", "admin", "v1"])
  def rest_path(:public), do: path(["api", @public_segment, "v1"])

  @doc "The canonical path of the MCP endpoint of `audience`, without the URL prefix."
  @spec mcp_path(:admin | :public) :: String.t()
  def mcp_path(:admin), do: path(["mcp", "admin"])
  def mcp_path(:public), do: path(["mcp", @public_segment])

  @doc "The path of `segments` as `forward` takes it: `\"/api/admin/v1\"`."
  @spec path(segments()) :: String.t()
  def path(segments), do: "/" <> Enum.join(segments, "/")

  @doc "The plug that serves the path made of `segments`: REST under `api`, MCP under `mcp`."
  @spec plug(segments()) :: module()
  def plug(["api" | _]), do: REST
  def plug(["mcp" | _]), do: MCP

  @doc """
  The options of the `forward` of `entry`: the audience, and for an alias the
  `:deprecated` pair the plugs read (`PhoenixKit.API.Auth`).
  """
  @spec plug_opts(entry()) :: keyword()
  def plug_opts({_segments, audience, _cors?, :canonical}), do: [audience: audience]

  def plug_opts({segments, audience, _cors?, {:alias, successor}}),
    do: [audience: audience, deprecated: [path: path(segments), successor: successor]]

  @doc """
  Marks the answers to `conn` as those of a deprecated path: `Deprecation`, a
  `Link: <canonical URL>; rel="successor-version"` appended to any `Link` the
  request already has, and, the first time the node sees the path, one
  `info` line in the log. `nil` (a canonical path) changes nothing.

  The canonical URL is the one `PhoenixKit.API.PublicDiscovery` names, on the
  host it trusts.
  """
  @spec put_deprecation(Plug.Conn.t(), keyword() | nil) :: Plug.Conn.t()
  def put_deprecation(conn, nil), do: conn

  def put_deprecation(%Plug.Conn{} = conn, deprecated) do
    path = Keyword.fetch!(deprecated, :path)
    successor = Keyword.fetch!(deprecated, :successor)
    log_once(path, successor)

    conn
    |> Plug.Conn.put_resp_header("deprecation", Legacy.deprecation())
    |> PublicDiscovery.put_link(
      ~s(<#{PublicDiscovery.origin(conn)}#{Routes.path(successor)}>; rel="successor-version")
    )
  end

  # One line per path per node: a client that keeps calling the old path must
  # not fill the log. A concurrent first pair of requests may log twice.
  defp log_once(path, successor) do
    key = {__MODULE__, :deprecation_logged, path}

    unless :persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.info(
        "[PhoenixKit.API] the deprecated path #{path} was used; it is served until 3.0.0, " <>
          "clients should move to #{successor}"
      )
    end
  end
end
