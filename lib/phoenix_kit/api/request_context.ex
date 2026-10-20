defmodule PhoenixKit.API.RequestContext do
  @moduledoc """
  What the API knows about the request besides who sent it: the language and
  currency to answer in, the hosts this install serves, and the base URL for
  absolute links.

  Core's defaults are deliberately plain:

    * `:language` is the install's primary language
      (`PhoenixKit.Utils.Multilang.primary_language/0`);
    * `:currency` is `nil`, because core does not depend on Billing. A
      module that knows a base currency fills it;
    * `:hosts` is the request host;
    * `:base_url` is `scheme://host[:port]` of the request.

  A host app overrides any of `:language`, `:currency` and `:hosts` per
  request (a multi-domain install maps the domain to a language and a
  currency):

      config :phoenix_kit, :api_request_context, {MyApp.ApiContext, :resolve}

  The function takes the `Plug.Conn` and returns a map with any of those three
  keys. A key of the wrong type is ignored. A function that raises is logged
  and the defaults are used, so a bug in the hook cannot take the API down.
  The log names the hook, the exception module and the shape of a bad result,
  never their values: the hook gets the whole connection, headers included.

  A call without a connection (`PhoenixKit.API.Executor.execute_as/5`, on behalf of a
  live session) has no request to read: its caller passes the context as options and
  `from_options/1` takes it as given. The hook is not called there, because it expects a
  `Plug.Conn`.
  """

  require Logger

  alias PhoenixKit.API.LogSafe
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKit.Utils.Multilang

  @type t :: %{
          language: String.t(),
          currency: String.t() | nil,
          hosts: [String.t()],
          base_url: String.t() | nil
        }

  @doc "Resolves the context of `conn`."
  @spec resolve(Plug.Conn.t()) :: t()
  def resolve(%Plug.Conn{} = conn) do
    Map.merge(defaults(conn), host_overrides(conn))
  end

  @doc """
  The context of a call without a connection, from `options` (`:language`, `:currency`,
  `:hosts`, `:base_url`). A missing option, or one of the wrong type, gets the default:
  the install's primary language, no currency, no hosts, no base URL. An element of
  `options` that is not a `{key, value}` pair is ignored.
  """
  @spec from_options(keyword()) :: t()
  def from_options(options) when is_list(options) do
    given =
      for {key, value} <- options,
          key in [:language, :currency, :hosts, :base_url],
          into: %{},
          do: {key, value}

    base_url =
      case Map.get(given, :base_url) do
        url when is_binary(url) and url != "" -> url
        _other -> nil
      end

    %{language: Multilang.primary_language(), currency: nil, hosts: [], base_url: base_url}
    |> Map.merge(given |> Map.delete(:base_url) |> sanitize())
  end

  defp defaults(conn) do
    %{
      language: Multilang.primary_language(),
      currency: nil,
      hosts: [conn.host],
      base_url: base_url(conn)
    }
  end

  defp host_overrides(conn) do
    case Application.get_env(:phoenix_kit, :api_request_context) do
      nil ->
        %{}

      {module, fun} when is_atom(module) and is_atom(fun) ->
        call_hook(module, fun, conn)

      other ->
        Logger.warning(
          "[PhoenixKit.API] :api_request_context must be {module, function}, got #{inspect(other)}"
        )

        %{}
    end
  end

  defp call_hook(module, fun, conn) do
    case apply(module, fun, [conn]) do
      %{} = result when not is_struct(result) -> sanitize(result)
      other -> bad_hook(module, fun, "returned #{LogSafe.shape(other)}")
    end
  rescue
    # The hook is handed the whole connection: the headers (the bearer token)
    # and the body params (client tokens) must not reach the log, so only the
    # exception module (and a fixed message) is logged.
    error -> bad_hook(module, fun, "raised #{LogSafe.exception_label(error)}")
  catch
    kind, reason -> bad_hook(module, fun, "#{kind}: #{LogSafe.shape(reason)}")
  end

  defp bad_hook(module, fun, what) do
    Logger.warning("[PhoenixKit.API] #{inspect(module)}.#{fun}/1 #{what}; using the defaults")
    %{}
  end

  defp sanitize(result) do
    Enum.reduce(result, %{}, fn
      {:language, language}, acc when is_binary(language) and language != "" ->
        Map.put(acc, :language, language)

      {:currency, currency}, acc when is_binary(currency) or is_nil(currency) ->
        Map.put(acc, :currency, currency)

      {:hosts, hosts}, acc when is_list(hosts) and hosts != [] ->
        if Enum.all?(hosts, &is_binary/1), do: Map.put(acc, :hosts, hosts), else: acc

      _other, acc ->
        acc
    end)
  end

  defp base_url(conn) do
    scheme = scheme(conn)
    "#{scheme}://#{conn.host}#{port_suffix(scheme, conn.port)}"
  end

  # Behind a TLS-terminating proxy the connection itself is plain HTTP. The
  # forwarded protocol is believed only from a local peer, the default rule
  # of `PhoenixKit.Utils.IpAddress.client_address/1`. It does not follow
  # `config :phoenix_kit, :trusted_proxies`.
  defp scheme(conn) do
    forwarded =
      conn
      |> Plug.Conn.get_req_header("x-forwarded-proto")
      |> List.first()
      |> forwarded_scheme()

    if forwarded && IpAddress.local_address?(conn.remote_ip) do
      forwarded
    else
      Atom.to_string(conn.scheme)
    end
  end

  defp forwarded_scheme(nil), do: nil

  defp forwarded_scheme(value) do
    case value |> String.split(",") |> hd() |> String.trim() |> String.downcase() do
      scheme when scheme in ["http", "https"] -> scheme
      _ -> nil
    end
  end

  defp port_suffix("http", port) when port in [80, nil], do: ""
  defp port_suffix("https", port) when port in [443, 80, nil], do: ""
  defp port_suffix(_scheme, port), do: ":#{port}"
end
