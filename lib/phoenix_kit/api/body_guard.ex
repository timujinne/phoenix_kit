defmodule PhoenixKit.API.BodyGuard do
  @moduledoc """
  Endpoint plug that bounds and parses the body of API requests and
  normalises the percent-encoded prefix of an API path (see "Encoded segments
  of the path" below).

  `Plug.Parsers` runs in the host's endpoint, before the router, with an 8 MB
  default limit, and it answers a malformed JSON body with an exception page
  in whatever format Phoenix picks. A plug inside the API router cannot
  change either, so this plug sits in the endpoint, immediately before
  `Plug.Parsers`:

      plug Plug.RequestId
      plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]

      plug PhoenixKit.API.BodyGuard

      plug Plug.Parsers,
        parsers: [:urlencoded, :multipart, :json],
        ...

  `mix phoenix_kit.install` and `mix phoenix_kit.update` insert it.

  ## What it does

  For `POST`, `PUT`, `PATCH` and `DELETE` requests to the machine API (every path
  of `PhoenixKit.API.Paths.entries/0`: `<prefix>/api/admin/v1`,
  `<prefix>/api/public/v1`, `<prefix>/mcp/admin`, `<prefix>/mcp/public` and the
  deprecated aliases of the public two, where `<prefix>` is the kit's URL
  prefix) **while the API of that path's audience is reachable by the client**
  (the switch is on, `api_admin_enabled` for `/api/admin/v1` and `/mcp/admin`,
  `api_public_enabled` for the public paths, and, for the public audience, the
  website password gate does not turn the client away) it reads
  the body, at most
  `PhoenixKit.API.Config.max_body_bytes/0` (2 MB), and decodes it as JSON,
  whatever the `content-type` says. Then it fills `body_params` and `params`,
  which makes `Plug.Parsers` skip the request:

    * an empty body is `%{}`;
    * a JSON object is that map;
    * any other JSON value (an array, a number) is `%{"_json" => value}`, the
      shape `Plug.Parsers.JSON` uses;
    * a body over the limit is answered `413 payload_too_large`;
    * a body that is not JSON, or holds a number the decoder cannot take (an
      integer of a million digits), is answered `400 invalid_json`; on the MCP
      paths that 400 is a JSON-RPC `-32700` parse error
      (`application/json`, `id: null`).

  The `413` and, on the REST paths, the `400` are `application/problem+json`,
  see `PhoenixKit.API.Problem`. On
  the public REST paths they also carry `access-control-allow-origin: *` and
  `access-control-expose-headers`, as every other answer of the public REST
  audience does (`PhoenixKit.API.REST`), so a browser agent can read them; the admin audience and MCP send no CORS header.
  On a deprecated alias (`PhoenixKit.API.Legacy`) they carry its `Deprecation` header and
  successor `Link`, as the answers of the API behind it do (`PhoenixKit.API.Paths.put_deprecation/2`).

  While the switch is off, or the website password gate is on and the
  client's address is not on its allow-list (the public audience only), the
  API answers every request with a bare `404` and never looks at the body
  (`PhoenixKit.API.Auth`), so the guard reads and judges nothing: no 2 MB
  read, no `413` or `400` where a `404` is due, and a gated site does not
  reveal that its public API is switched on. It only sets `body_params` to
  `%{}`, without reading, so that `Plug.Parsers` (next in the endpoint) skips
  the request instead of raising on a body nobody wants. The switch is read
  through `PhoenixKit.API.Config` and the gate through
  `PhoenixKit.API.Auth.gated?/2`, the same cached settings reads `Auth` uses;
  an unreadable switch counts as off.

  ## Cost before authentication

  The guard runs before `PhoenixKit.API.Auth` and before any rate bucket, so
  a client that has not authenticated can make the node read up to 2 MB per
  request and decode it as JSON (a deeply nested `[[[...]]]` body of that size
  takes about 0.25 s of CPU and, measured, about 40 times the body size in
  process heap, some 90 MB for a 2 MB body; an unterminated one is refused in
  about 0.3 s),
  and the `413` and `400` answers are not counted against the pre-auth
  failure bucket (`PhoenixKit.API.RateLimit.record_auth_failure/1` is reached
  from `Auth` only). Accepted: `Plug.Parsers` of the stock endpoint has the
  same cost before authentication, so the guard does not make it worse, and
  it only acts while the switch of the audience is on. As with the key
  lookups in `Auth`, the throttle limits the answers, not the reads. A
  deployment that needs a bound puts it in front of the node (the reverse
  proxy's body size and request rate limits).

  Every other path passes untouched, with its body unread: the matching is by
  whole path segments, so `/apiary` is not `/api`, bare `/mcp` is not
  `/mcp/admin`, and the storage routes under `/api/upload` and `/api/files`
  keep their own, larger, limits. The segments are percent-decoded before they
  are compared, the way the router decodes them (`/api/%61dmin/v1` is
  `/api/admin/v1`); a segment with a malformed escape (`%zz`) is compared as
  it was sent.

  ## Encoded segments of the path

  Phoenix's `forward` strips its own prefix from the *raw* `path_info`, so a
  request whose guarded prefix is written percent-encoded
  (`/api/%61dmin/v1/x`, which the router matches as `/api/admin/v1/x`) would
  raise a `MatchError` there, a 500 for a crafted URL. The guard therefore
  replaces the segments of the matched prefix by their decoded form, for every
  method and whatever the switch says, and leaves the rest of `path_info`
  as sent. The request then takes the same road as the plain path.

  The forwards of the machine API depend on this plug for that: a host whose
  endpoint does not have it yet (it has not run `mix phoenix_kit.update`)
  answers such a crafted URL with a 500 from inside the router. Every future
  forward under an API prefix (the MCP endpoints) inherits the dependency.
  """

  @behaviour Plug

  import Plug.Conn

  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.MCP.Rpc
  alias PhoenixKit.API.Paths
  alias PhoenixKit.API.Problem
  alias PhoenixKit.API.REST
  alias PhoenixKit.Utils.Routes

  @body_methods ["POST", "PUT", "PATCH", "DELETE"]

  # Path segments under the kit's URL prefix, the audience whose switch
  # decides whether the guard acts on them, and whether the guard's own
  # answers carry the CORS header (the public REST audience only, as
  # `PhoenixKit.API.REST` does): the table the router forwards, aliases
  # included. Each MCP endpoint follows the audience of its own name; bare
  # `/mcp` and other `/mcp/...` paths are not guarded. An alias also carries the
  # `:deprecated` pair its forward gets, for the guard's own answers.
  @guarded for {segments, audience, cors?, _kind} = entry <- Paths.entries(),
               do: {segments, audience, cors?, Paths.plug_opts(entry)[:deprecated]}

  # Bytes asked of the socket per read; the total is bounded separately.
  @read_chunk 1_048_576

  @impl Plug
  def init(opts), do: opts

  @impl Plug
  def call(%Plug.Conn{} = conn, _opts) do
    case match(conn) do
      nil ->
        conn

      {audience, cors?, deprecated, prefix_length} ->
        conn
        |> decode_prefix(prefix_length)
        |> put_private(:phoenix_kit_api_deprecated, deprecated)
        |> body(audience, cors?)
    end
  end

  defp body(
         %Plug.Conn{method: method, body_params: %Plug.Conn.Unfetched{}} = conn,
         audience,
         cors?
       )
       when method in @body_methods do
    if reachable?(conn, audience), do: guard(conn, cors?), else: switched_off(conn)
  end

  defp body(conn, _audience, _cors?), do: conn

  @doc """
  Whether `conn` is a request to a guarded API path.

  The path is compared segment by segment, under the kit's URL prefix
  (`PhoenixKit.Utils.Routes.prefix_base/0`), an empty segment
  (`/api//admin/v1`) is dropped the way the router drops it, and each segment
  is percent-decoded the way the router decodes it.
  """
  @spec guarded?(Plug.Conn.t()) :: boolean()
  def guarded?(%Plug.Conn{} = conn), do: match(conn) != nil

  # `{audience, cors?, prefix_length}` of a guarded path, nil for any other
  # path; `prefix_length` is the number of leading segments that make up the
  # URL prefix and the guarded path. The router (`Phoenix.Router`'s `call/2`)
  # matches `URI.decode/1`d segments, so the guard must compare the same:
  # `/api/%61dmin/v1` reaches the admin API.
  defp match(%Plug.Conn{path_info: segments}) do
    prefix = Routes.prefix_base() |> String.split("/", trim: true)
    decoded = decode_segments(segments)

    Enum.find_value(@guarded, fn {path, audience, cors?, deprecated} ->
      if List.starts_with?(decoded, prefix ++ path),
        do: {audience, cors?, deprecated, length(prefix) + length(path)}
    end)
  end

  # The matched prefix in decoded form (see "Encoded segments of the path" in
  # the moduledoc); the segments after it stay as sent.
  defp decode_prefix(%Plug.Conn{path_info: segments} = conn, prefix_length) do
    {prefix, rest} = Enum.split(segments, prefix_length)
    %{conn | path_info: decode_segments(prefix) ++ rest}
  end

  # This runs for every request through the endpoint, so the common path with
  # nothing percent-encoded in it is returned as it is.
  defp decode_segments(segments) do
    if Enum.any?(segments, &String.contains?(&1, "%")),
      do: Enum.map(segments, &decode_segment/1),
      else: segments
  end

  # `URI.decode/1` leaves a malformed escape (`%zz`) as it is on Elixir 1.19;
  # a version that raises `ArgumentError` there must not crash the endpoint,
  # so the segment is then compared as sent and, being unlike any guarded
  # segment, matches nothing.
  defp decode_segment(segment) do
    URI.decode(segment)
  rescue
    ArgumentError -> segment
  end

  # The same two questions, in the same order, as `PhoenixKit.API.Auth`: the
  # switch first, then (public audience) the website password gate.
  defp reachable?(_conn, :admin), do: Config.admin_enabled?()

  defp reachable?(conn, :public) do
    Config.public_enabled?() and not Auth.gated?(conn, :public)
  end

  # The API is off for this client (switched off, or hidden by the website
  # gate): `Auth` will answer a bare 404 and never looks at the body. Nothing
  # is read; an empty map in `body_params` only keeps `Plug.Parsers`, which
  # runs next, from raising on a body nobody wants.
  defp switched_off(conn), do: put_body(conn, %{})

  defp guard(conn, cors?) do
    max = Config.max_body_bytes()

    if declared_length(conn) > max do
      too_large(conn, max, cors?)
    else
      read(conn, max, cors?)
    end
  end

  # One byte more than the limit, so a body of exactly `max` bytes is read to
  # the end and one byte over it is recognised.
  defp read(conn, max, cors?) do
    case read_body(conn, length: max + 1, read_length: @read_chunk) do
      {:ok, body, conn} when byte_size(body) <= max -> parse(conn, body, cors?)
      {:ok, _body, conn} -> too_large(conn, max, cors?)
      {:more, _partial, conn} -> too_large(conn, max, cors?)
      {:error, _reason} -> unreadable(conn, cors?)
    end
  end

  defp parse(conn, body, cors?) do
    if String.trim(body) == "" do
      put_body(conn, %{})
    else
      decode(conn, body, cors?)
    end
  end

  defp decode(conn, body, cors?) do
    case safe_decode(body) do
      {:ok, %{} = map} -> put_body(conn, map)
      {:ok, value} -> put_body(conn, %{"_json" => value})
      {:error, _reason} -> invalid_json(conn, cors?)
    end
  end

  # `JSON.decode/1` raises instead of returning an error for one kind of input
  # inside the size limit: an integer of a million digits raises
  # `SystemLimitError`. The bytes are the client's, and a number the decoder
  # cannot hold is the client's invalid request, not a 500 before
  # authentication. Any other exception is a bug and surfaces.
  defp safe_decode(body) do
    JSON.decode(body)
  rescue
    SystemLimitError -> {:error, :number_too_large}
  end

  defp put_body(conn, map), do: %{conn | body_params: map, params: map}

  defp declared_length(conn) do
    with [value | _] <- get_req_header(conn, "content-length"),
         {length, ""} <- Integer.parse(value) do
      length
    else
      _ -> 0
    end
  end

  defp too_large(conn, max, cors?) do
    conn
    |> put_cors(cors?)
    |> put_deprecation()
    |> Problem.send(:payload_too_large, "The request body is larger than #{max} bytes.", %{
      limit_bytes: max
    })
  end

  defp invalid_json(conn, cors?),
    do:
      parse_failure(
        conn,
        cors?,
        "The request body is not valid JSON or holds a number that is too large."
      )

  defp unreadable(conn, cors?),
    do: parse_failure(conn, cors?, "The request body could not be read.")

  # On the MCP paths a body that is not JSON is a JSON-RPC parse error (HTTP
  # 400, id null): an MCP client reads that, not a problem document.
  defp parse_failure(conn, cors?, text) do
    if mcp?(conn) do
      conn
      |> put_deprecation()
      |> Rpc.send_error(400, nil, :parse_error, "Parse error: " <> text)
    else
      conn |> put_cors(cors?) |> put_deprecation() |> Problem.send(:invalid_json, text, %{})
    end
  end

  # The guard answers before `PhoenixKit.API.Auth` marks an alias, so it marks its own
  # answers on one the same way.
  defp put_deprecation(conn),
    do: Paths.put_deprecation(conn, conn.private[:phoenix_kit_api_deprecated])

  # Only guarded paths get here, and the only guarded `mcp` paths are the MCP
  # endpoints of `PhoenixKit.API.Paths`.
  defp mcp?(%Plug.Conn{path_info: segments}) do
    prefix = Routes.prefix_base() |> String.split("/", trim: true)
    List.starts_with?(segments, prefix ++ ["mcp"])
  end

  # The answers of the public REST audience are readable by a browser agent
  # (`PhoenixKit.API.REST`); the guard answers before REST runs.
  defp put_cors(conn, true), do: REST.put_public_cors(conn)
  defp put_cors(conn, false), do: conn
end
