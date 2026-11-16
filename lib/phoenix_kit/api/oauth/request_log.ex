defmodule PhoenixKit.API.OAuth.RequestLog do
  @moduledoc """
  Keeps the consent capability URL (`<prefix>/oauth/consent/<token>`) out of the application log.

  The routes of that page are declared `log: false`, but that only silences the router's own
  "Processing with ..." and "Parameters" lines. The path was still written by two other lines,
  both before the router runs:

    * the request line `GET /path` of the endpoint's `Plug.Telemetry` (`Phoenix.Logger`, `:info`).
      Its only switch is the `:log` option of that plug, which takes `{module, function, args}`
      and calls it with the connection; `level/1` is made for it:

      plug Plug.Telemetry,
        event_prefix: [:phoenix, :endpoint],
        log: {PhoenixKit.API.OAuth.RequestLog, :level, []}

      `level/1` answers `false` for the consent paths and `:info`, the plug's default, for every
      other path. A host whose `Plug.Telemetry` has no `:log` option writes that line for the
      consent page: the host's endpoint is the host's to edit.
    * the `[RequestTimer]` lines of the kit's own `PhoenixKitWeb.Plugs.RequestTimer`, which
      writes the path at `:debug` and `:info`: it logs `path/1`, in which the token is replaced.

  A token in a line of the log is of no use to a reader of the log alone, however: a request is
  found only for the browser that started it (`PhoenixKit.API.OAuth.Requests`).
  """

  alias PhoenixKit.Utils.Routes

  @doc "`false` for a path of the consent page, `:info` otherwise."
  @spec level(Plug.Conn.t()) :: Logger.level() | false
  def level(%Plug.Conn{request_path: path}) when is_binary(path) do
    if String.starts_with?(path, Routes.path("/oauth/consent/")), do: false, else: :info
  end

  def level(_conn), do: :info

  @doc """
  The path of `conn` as it may be written to the log: the token of a consent path is replaced by
  `[FILTERED]` (the word Phoenix uses for a parameter it hides), any other path is as it is.
  """
  @spec path(Plug.Conn.t()) :: String.t()
  def path(%Plug.Conn{request_path: path}) when is_binary(path) do
    prefix = Routes.path("/oauth/consent/")

    case path do
      ^prefix <> rest ->
        [_token | tail] = String.split(rest, "/", parts: 2)
        Enum.join([prefix <> "[FILTERED]" | tail], "/")

      _ ->
        path
    end
  end
end
