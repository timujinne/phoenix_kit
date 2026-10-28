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

  `entries/0` lists `{segments, audience, cors?}`:

    * `segments`, the path under the URL prefix, split by `/`;
    * `audience`, `:admin` or `:public`, which decides the plug's options and
      the switch `PhoenixKit.API.BodyGuard` looks at;
    * `cors?`, whether the answers carry the CORS headers of the public REST
      audience (`PhoenixKit.API.REST`), the guard's included;

  Anything that builds a URL for a client (`PhoenixKit.API.OpenAPI`,
  `PhoenixKit.API.PublicDiscovery`) takes `rest_path/1` and `mcp_path/1`,
  which are the only paths the API answers on.
  """

  alias PhoenixKit.API.MCP
  alias PhoenixKit.API.REST

  @public_segment "public"

  @type segments :: [String.t()]
  @type entry :: {segments(), :admin | :public, boolean()}

  @doc """
  The path segment that names the public audience in `/api/<segment>/v1` and
  `/mcp/<segment>`: the one place it is spelled.
  """
  @spec public_segment() :: String.t()
  def public_segment, do: @public_segment

  @doc """
  Every path the API answers on. See the moduledoc for the shape.
  """
  @spec entries() :: [entry()]
  def entries do
    [
      {["api", "admin", "v1"], :admin, false},
      {["api", @public_segment, "v1"], :public, true},
      {["mcp", "admin"], :admin, false},
      {["mcp", @public_segment], :public, false}
    ]
  end

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

  @doc "The options of the `forward` of `entry`: the audience."
  @spec plug_opts(entry()) :: keyword()
  def plug_opts({_segments, audience, _cors?}), do: [audience: audience]
end
