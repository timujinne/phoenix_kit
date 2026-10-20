defmodule PhoenixKit.API.MCP.Origin do
  @moduledoc """
  The `Origin` check of the MCP transport, against DNS rebinding.

  A request without an `Origin` header (every client that is not a browser)
  passes. A request with one must name a host this install knows, else it is
  answered `403 origin_not_allowed` before any key is looked at (the MCP plug
  runs this as the `:before_auth` hook of `PhoenixKit.API.Auth`).

  ## What is allowed

    * the install's canonical host: the host of the `site_url` setting, else
      of the endpoint's URL (the same source as `PhoenixKit.Utils.Routes.base_url/0`,
      read through the settings cache because this check runs before any rate
      limit);
    * when the host app configures `config :phoenix_kit, :api_request_context,
      {Module, :function}`, the `:hosts` that function **explicitly returns**
      (every domain of a multi-domain install). A hook that returns no
      `:hosts` key (a hook that sets only language and currency), an empty or
      non-string list, junk, or that raises or throws contributes nothing. The
      hook is called with the conn, and it runs again later in the same request
      when the request context is resolved, so it must be cheap and free of side
      effects;
    * the entries of the `api_mcp_allowed_origins` setting, which are full
      origins: `https://client.example` matches scheme, host and port. An entry
      without `://` never matches (the Settings page stores only full origins).

  The request's own `Host` header is deliberately **not** on the list. A
  DNS-rebinding page sends `Host: evil.test` and `Origin: http://evil.test`;
  both come from the attacker, so a list built from the `Host` header would
  admit it. The default `PhoenixKit.API.RequestContext` host list is exactly
  that header, and `RequestContext.resolve/1` keeps it whenever a hook returns
  no `:hosts` or fails, which is why this module does not use `resolve/1` and
  calls the hook itself.

  An origin with userinfo, a path, a query, a fragment, a scheme other than
  `http` or `https`, no host (`null`, `file://`), surrounding whitespace or
  bytes that are not valid UTF-8 is never allowed. A request with two `Origin`
  headers is refused.
  """

  import Plug.Conn

  alias PhoenixKit.API.Config
  alias PhoenixKit.API.LogSafe
  alias PhoenixKit.API.Problem
  alias PhoenixKit.Settings

  require Logger

  @last_resort_origin "http://localhost:4000"
  @fallback_flag {__MODULE__, :fallback_warned}

  @doc """
  Passes `conn` when it has no `Origin` header or an allowed one; otherwise
  sends `403 origin_not_allowed` and halts.
  """
  @spec check(Plug.Conn.t()) :: Plug.Conn.t()
  def check(%Plug.Conn{} = conn) do
    case get_req_header(conn, "origin") do
      [] ->
        conn

      [origin] ->
        if allowed?(origin, known_hosts(conn), Config.mcp_allowed_origins()),
          do: conn,
          else: refuse(conn, origin)

      several ->
        refuse(conn, Enum.join(several, ", "))
    end
  end

  @doc """
  Whether `origin` (the value of an `Origin` header) is allowed, given the
  `hosts` this install serves and the `configured` entries of
  `api_mcp_allowed_origins`.
  """
  @spec allowed?(String.t(), [String.t()], [String.t()]) :: boolean()
  def allowed?(origin, hosts, configured)
      when is_binary(origin) and is_list(hosts) and is_list(configured) do
    case parse(origin) do
      {:ok, parsed} ->
        host_known?(parsed.host, hosts) or Enum.any?(configured, &configured_match?(&1, parsed))

      :error ->
        false
    end
  end

  # --- the list of hosts ------------------------------------------------------

  @doc """
  The hostnames this install is known to serve, lowercase and without ports:
  the canonical host first, then the hosts the `:api_request_context` hook
  explicitly returns (see the moduledoc). The request's own `Host` header is
  never on the list.

  Public for the other documents the install publishes about itself
  (`PhoenixKit.API.PublicDiscovery`), which must not trust the `Host` header
  either.
  """
  @spec known_hosts(Plug.Conn.t()) :: [String.t()]
  def known_hosts(conn) do
    (canonical_hosts() ++ hook_hosts(conn))
    |> Enum.map(&hostname/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
  end

  @doc """
  The canonical origin, `scheme://host[:port]`: that of the `site_url` setting
  (read through the settings cache), else of the endpoint's URL, else of the
  static configuration, else `http://localhost:4000`. A rung that is set but
  unusable (no scheme, not `http(s)`, no host) is skipped. The host is
  lowercase and a default port is left out.

  The last two rungs mean the install never said what its public address is:
  that is logged once per boot. It never raises.

  The same source as `PhoenixKit.Utils.Routes.base_url/0`, but without its
  uncached database read, so a public request can use it.
  """
  @spec canonical_origin() :: String.t()
  def canonical_origin do
    site_url_origin() || endpoint_origin() || fallback_origin()
  rescue
    _ -> fallback_origin()
  end

  @doc """
  `origin` (as `canonical_origin/0` returns it) with `host` in place of its
  host: the scheme and the port are kept.
  """
  @spec origin_with_host(String.t(), String.t()) :: String.t()
  def origin_with_host(origin, host) when is_binary(origin) and is_binary(host) do
    %URI{scheme: scheme, port: port} = URI.parse(origin)
    "#{scheme}://#{host_text(host)}#{port_suffix(scheme, port)}"
  end

  defp site_url_origin do
    case cached_site_url() do
      site_url when is_binary(site_url) and site_url != "" -> origin_of(site_url)
      _unset -> nil
    end
  end

  defp endpoint_origin do
    case PhoenixKit.Config.get_parent_endpoint_url() do
      {:ok, url} -> origin_of(url)
      :error -> nil
    end
  end

  defp fallback_origin do
    {rung, origin} =
      try do
        case origin_of(PhoenixKit.Config.get_base_url()) do
          nil -> {"the built-in default", @last_resort_origin}
          origin -> {"the static configuration", origin}
        end
      rescue
        _ -> {"the built-in default", @last_resort_origin}
      end

    warn_once(rung, origin)
    origin
  end

  defp warn_once(rung, origin) do
    unless :persistent_term.get(@fallback_flag, false) do
      :persistent_term.put(@fallback_flag, true)

      Logger.warning(
        "MCP.Origin: the canonical origin is #{origin}, from #{rung}: the site_url " <>
          "setting is unset or unusable and the endpoint has no usable URL. The public " <>
          "API guide, catalog and llms.txt name this address; set site_url to the site's " <>
          "public address."
      )
    end
  end

  defp origin_of(url) when is_binary(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: scheme, host: host, port: port}}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        "#{scheme}://#{host_text(host)}#{port_suffix(scheme, port)}"

      _unusable ->
        nil
    end
  end

  defp host_text(host) do
    host = String.downcase(host)
    if String.contains?(host, ":"), do: "[" <> host <> "]", else: host
  end

  defp port_suffix(scheme, port) do
    if port in [nil, URI.default_port(scheme)], do: "", else: ":#{port}"
  end

  # Not `Routes.base_url/0`: it reads the `site_url` setting uncached, and this
  # check runs for every request that carries an Origin, before any limiter.
  defp canonical_hosts do
    case URI.new(base_url()) do
      {:ok, %URI{host: host}} when is_binary(host) and host != "" -> [host]
      _unusable -> []
    end
  rescue
    # No answer is a closed door: only the configured origins remain.
    _ -> []
  end

  defp base_url do
    case cached_site_url() do
      site_url when is_binary(site_url) and site_url != "" ->
        String.trim_trailing(site_url, "/")

      _unset ->
        PhoenixKit.Config.get_dynamic_base_url()
    end
  end

  defp cached_site_url, do: Settings.get_setting_cached("site_url", "")

  # The hosts the host app's hook EXPLICITLY returns, else []. Never the Host
  # header: `RequestContext.resolve/1` is not used here because its merge
  # leaves `hosts` at `[conn.host]` for a hook that returns only language and
  # currency, and for a hook that raises.
  defp hook_hosts(conn) do
    case Application.get_env(:phoenix_kit, :api_request_context) do
      nil ->
        []

      {module, fun} when is_atom(module) and is_atom(fun) ->
        call_hook(module, fun, conn)

      other ->
        Logger.warning(
          "[PhoenixKit.API] :api_request_context must be {module, function}, got #{inspect(other)}; no hosts taken from it"
        )

        []
    end
  end

  defp call_hook(module, fun, conn) do
    case apply(module, fun, [conn]) do
      %{} = result -> explicit_hosts(result)
      _other -> []
    end
  rescue
    error ->
      Logger.warning(
        "[PhoenixKit.API] #{inspect(module)}.#{fun}/1 raised #{LogSafe.exception_label(error)}; no hosts taken from it"
      )

      []
  catch
    kind, reason ->
      Logger.warning(
        "[PhoenixKit.API] #{inspect(module)}.#{fun}/1 #{kind}: #{LogSafe.shape(reason)}; no hosts taken from it"
      )

      []
  end

  defp explicit_hosts(result) do
    case Map.get(result, :hosts) do
      hosts when is_list(hosts) and hosts != [] ->
        if Enum.all?(hosts, &is_binary/1), do: hosts, else: []

      _missing_or_bad ->
        []
    end
  end

  defp host_known?(host, hosts), do: Enum.any?(hosts, &(hostname(&1) == host))

  # --- matching ---------------------------------------------------------------

  # A browser origin: scheme://host[:port], nothing else.
  defp parse(origin) do
    if String.valid?(origin), do: parse_valid(origin), else: :error
  end

  # `URI.new/1` raises on bytes that are not UTF-8 instead of returning an error.
  defp parse_valid(origin) do
    case URI.new(origin) do
      {:ok,
       %URI{
         scheme: scheme,
         host: host,
         port: port,
         userinfo: nil,
         query: nil,
         fragment: nil,
         path: path
       }}
      when is_binary(scheme) and is_binary(host) and host != "" and path in [nil, ""] ->
        scheme = String.downcase(scheme)

        if scheme in ["http", "https"],
          do: {:ok, %{scheme: scheme, host: String.downcase(host), port: port}},
          else: :error

      _not_an_origin ->
        :error
    end
  end

  defp configured_match?(entry, parsed) do
    entry = entry |> String.trim() |> String.trim_trailing("/")

    # Only a full origin counts. An entry without a scheme never matches: the
    # Settings -> API page stores nothing else.
    if String.contains?(entry, "://") do
      case parse(entry) do
        {:ok, wanted} -> wanted == parsed
        :error -> false
      end
    else
      false
    end
  end

  # "Example.Test", "example.test:4000" and "[::1]:4000" -> the lowercase hostname.
  # An entry written with a scheme is a misconfiguration; it matches nothing
  # (`nil` never equals a parsed host).
  defp hostname(entry) do
    entry = entry |> String.trim() |> String.downcase()

    if String.contains?(entry, "://") do
      nil
    else
      case URI.new("//" <> entry) do
        {:ok, %URI{host: host}} when is_binary(host) and host != "" -> host
        _unparsable -> entry
      end
    end
  end

  # --- the answer -------------------------------------------------------------

  defp refuse(conn, origin) do
    Problem.send(
      conn,
      :origin_not_allowed,
      "This Origin is not allowed. An administrator can add it to the allowed MCP origins in Settings -> API.",
      %{origin: origin |> String.replace_invalid() |> LogSafe.take_codepoints(200)}
    )
  end
end
