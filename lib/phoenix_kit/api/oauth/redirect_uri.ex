defmodule PhoenixKit.API.OAuth.RedirectUri do
  @moduledoc """
  The rules for the places an authorization code may be sent: what a client may register and
  when a requested `redirect_uri` counts as one of them.

  A registered URI is `https`, or `http` to the loopback (`127.0.0.1`, `[::1]` or
  `localhost`); it has a host, no userinfo, no fragment and no wildcard. Custom schemes
  (`app://`) are not supported.

  `allowed?/2` is an exact comparison, except for the loopback IP literals (`127.0.0.1` and
  `[::1]`), where the port is ignored (RFC 8252 section 7.3): a native application takes any
  free port. `localhost` is matched exactly, port included. The scheme and the host are compared
  in lower case; the path and the query are compared as written, so a differently
  percent-encoded path is another URI.
  """

  @max_length 2048
  @loopback_ips ["127.0.0.1", "[::1]", "::1"]

  @doc "The longest URI accepted."
  @spec max_length() :: pos_integer()
  def max_length, do: @max_length

  @doc """
  Whether `uri` may be registered: a string no longer than `max_length/0` that parses to an
  `https` URI, or an `http` one to a loopback host, with a host, no userinfo, no fragment, no
  wildcard (`*`) and no control character.
  """
  @spec valid?(term()) :: boolean()
  def valid?(uri), do: match?({:ok, _parts}, parse(uri))

  @doc "Whether `requested` is one of `registered` (see the moduledoc)."
  @spec allowed?(term(), [String.t()]) :: boolean()
  def allowed?(requested, registered) when is_list(registered) do
    case parse(requested) do
      {:ok, wanted} ->
        Enum.any?(registered, fn candidate ->
          case parse(candidate) do
            {:ok, known} -> same?(wanted, known)
            :error -> false
          end
        end)

      :error ->
        false
    end
  end

  def allowed?(_requested, _registered), do: false

  @doc "The host of a URI that parses (as shown on the consent screen); `nil` otherwise."
  @spec host(term()) :: String.t() | nil
  def host(uri) do
    case parse(uri) do
      {:ok, %{host: host}} -> host
      :error -> nil
    end
  end

  @doc "Whether `uri` points to the loopback (a native application on the same machine)."
  @spec loopback?(term()) :: boolean()
  def loopback?(uri) do
    case parse(uri) do
      {:ok, %{host: host}} -> host in @loopback_ips or host == "localhost"
      :error -> false
    end
  end

  defp parse(uri) when is_binary(uri) and byte_size(uri) <= @max_length do
    with true <- String.printable?(uri) and not String.contains?(uri, ["*", " ", "\\"]),
         {:ok, %URI{scheme: scheme, host: host, userinfo: nil, fragment: nil} = parsed} <-
           URI.new(uri),
         scheme when scheme in ["http", "https"] <- scheme && String.downcase(scheme),
         true <- is_binary(host) and host != "",
         host = String.downcase(host),
         true <- scheme == "https" or loopback_host?(host) do
      {:ok,
       %{
         scheme: scheme,
         host: host,
         port: parsed.port,
         path: parsed.path || "",
         query: parsed.query
       }}
    else
      _ -> :error
    end
  end

  defp parse(_uri), do: :error

  defp loopback_host?(host), do: host in ["127.0.0.1", "::1", "[::1]", "localhost"]

  defp same?(wanted, known) do
    wanted.scheme == known.scheme and wanted.host == known.host and
      wanted.path == known.path and wanted.query == known.query and ports_match?(wanted, known)
  end

  # The port is ignored for the loopback IP literals only.
  defp ports_match?(%{host: host}, _known) when host in @loopback_ips, do: true
  defp ports_match?(wanted, known), do: wanted.port == known.port
end
