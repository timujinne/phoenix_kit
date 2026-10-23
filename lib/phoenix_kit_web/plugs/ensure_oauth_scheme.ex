defmodule PhoenixKitWeb.Plugs.EnsureOAuthScheme do
  @moduledoc """
  Ensures correct HTTPS scheme for OAuth callback URL generation behind reverse proxies.

  This plug checks (in order):
  1. `X-Forwarded-Proto` header (nginx/apache standard), believed only from a
     trusted proxy (`PhoenixKit.Utils.IpAddress.trusted_proxy?/1`, which
     follows `config :phoenix_kit, :trusted_proxies`); from any other peer
     the header is ignored
  2. Explicit `:phoenix_kit, :oauth_base_url` config (an empty string counts
     as unset)
  3. Endpoint URL configuration (`url: [scheme:, host:, port:]`)

  Step 3 fills in what the endpoint does not state, so that a production
  install keeps working without any OAuth setting:

  * scheme — the endpoint's `:scheme` if given, else `https` when its `:port`
    is 443, else the request's own scheme when BOTH the endpoint's host and the
    request's host are loopback (a local dev server stays `http`), else
    `https`. Providers accept an `http` redirect URI only for localhost, so
    `https` is the safe default for any other host; a leftover
    `url: [host: "localhost"]` in a production endpoint does not make a request
    for another host `http`.
  * host — the endpoint's `:host`, else the request's host.
  * port — the endpoint's `:port`; else 443 when the scheme is `https`, else
    the request's port.

  What this changes in practice: the scheme and the port of the callback URL.
  The host of the callback is still taken by Ueberauth from the request
  (`X-Forwarded-Host` or `Host`), not from the endpoint `url:`, so the host
  the endpoint names does not replace the one the request arrived with.
  Compared with always forcing `https` on 443:

  * a plain-http dev server on a loopback host keeps `http` and its own port;
  * an endpoint `url: [host: ..., port: 4000]` without a `:scheme` now yields
    `https` on 4000 (it was `https` on 443);
  * a deployment with no endpoint `url:` on a non-loopback host still gets
    `https` on 443, as before.

  A deployment that serves plain `http` on a non-loopback host, or terminates
  TLS on a port other than 443 behind a proxy that is not trusted, must say so
  with `url: [scheme: ..., port: ...]` or `:oauth_base_url`.

  ## Usage

  Automatically included in OAuth controller. No manual setup required.

  ## Configuration (Optional)

  For edge cases where headers aren't available:

      config :phoenix_kit,
        oauth_base_url: "https://example.com"

  """

  import Plug.Conn

  alias PhoenixKit.Utils.IpAddress

  def init(opts), do: opts

  def call(conn, _opts) do
    cond do
      # 1. Check X-Forwarded-Proto header (standard for nginx/apache)
      forwarded_proto = get_forwarded_proto(conn) ->
        apply_scheme(conn, forwarded_proto)

      # 2. Check explicit oauth_base_url config
      base_url = non_empty(PhoenixKit.Config.get_string(:oauth_base_url, "")) ->
        apply_base_url(conn, base_url)

      # 3. Check endpoint URL config
      true ->
        apply_endpoint_config(conn)
    end
  end

  defp get_forwarded_proto(conn) do
    case get_req_header(conn, "x-forwarded-proto") do
      [proto | _] when proto in ["https", "http"] ->
        if IpAddress.trusted_proxy?(conn.remote_ip), do: proto

      _ ->
        nil
    end
  end

  defp non_empty(""), do: nil
  defp non_empty(value), do: value

  defp apply_scheme(conn, "https"), do: %{conn | scheme: :https, port: 443}
  defp apply_scheme(conn, _), do: conn

  defp apply_base_url(conn, base_url) when is_binary(base_url) do
    uri = URI.parse(base_url)

    %{
      conn
      | scheme: parse_scheme(uri.scheme),
        host: uri.host || conn.host,
        port: uri.port || default_port(uri.scheme)
    }
  end

  defp apply_endpoint_config(conn) do
    url_config = endpoint_url_config(conn)
    host = url_config[:host] || conn.host
    {scheme, port} = scheme_and_port(conn, url_config, host)

    %{conn | scheme: scheme, host: host, port: port}
  end

  defp scheme_and_port(conn, url_config, host) do
    port = url_port(url_config[:port])

    cond do
      url_config[:scheme] ->
        case parse_scheme(url_config[:scheme]) do
          :https -> {:https, port || 443}
          scheme -> {scheme, port || conn.port}
        end

      port == 443 ->
        {:https, 443}

      loopback?(host) and loopback?(conn.host) ->
        {conn.scheme, port || conn.port}

      true ->
        {:https, port || 443}
    end
  end

  # Phoenix accepts the endpoint `url: [port: ...]` as an integer, a numeric string or
  # `{:system, env_var}`; `conn.port` must stay an integer and `443` must match as one.
  defp url_port(port) when is_integer(port), do: port
  defp url_port({:system, env_var}), do: url_port(System.get_env(env_var))

  defp url_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {port, ""} -> port
      _ -> nil
    end
  end

  defp url_port(_), do: nil

  defp endpoint_url_config(conn) do
    case Phoenix.Controller.endpoint_module(conn) do
      nil -> []
      endpoint -> get_endpoint_url_config(endpoint)
    end
  rescue
    KeyError -> []
  end

  defp loopback?(host) when is_binary(host) do
    host in ["localhost", "127.0.0.1", "::1", "[::1]"] or String.ends_with?(host, ".localhost")
  end

  defp loopback?(_), do: false

  defp get_endpoint_url_config(endpoint_module) do
    # Get otp_app from endpoint config (correct way)
    otp_app = endpoint_module.config(:otp_app)

    case Application.get_env(otp_app, endpoint_module) do
      nil -> []
      config -> Keyword.get(config, :url, [])
    end
  end

  defp parse_scheme("https"), do: :https
  defp parse_scheme("http"), do: :http
  defp parse_scheme(_), do: :https

  defp default_port("https"), do: 443
  defp default_port("http"), do: 80
  defp default_port(_), do: 443
end
