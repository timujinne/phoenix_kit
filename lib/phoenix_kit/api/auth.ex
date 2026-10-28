defmodule PhoenixKit.API.Auth do
  @moduledoc """
  Plug that admits a request to the machine API: steps 1 to 3 of the request
  flow (API switch, refusal of a credential in the URL, authentication;
  `PhoenixKit.API.Executor` runs the rest). The order below is the order of
  the code.

  Every transport mounts it first, with the audience of the endpoint:

      plug PhoenixKit.API.Auth, audience: :admin

  In order, it:

    1. assigns `:phoenix_kit_api_request_id`: the `x-request-id` response
       header when `Plug.RequestId` set one (an id the client sent is
       reused there) and it matches `\\A[A-Za-z0-9_=+/-]+\\z`; any other id,
       and no id at all, gets a fresh random one. The id goes into
       problem bodies and log lines, so nothing else is let through;
    2. answers `404` when the audience's switch is off
       (`PhoenixKit.API.Config.admin_enabled?/0`, `public_enabled?/0`; a
       settings read error counts as off), and, for the public audience, while
       the website password gate is on and the client's address is not on the
       gate's allow-list. Nothing else is done for such a request: no database
       read beyond the cached settings;
    3. refuses a credential in the URL with `400 token_in_url`, before any
       authentication (`token_in_url?/1`);
    4. for the admin audience, authenticates the `Authorization: Bearer
       pk_...` key with `PhoenixKit.API.Keys.verify/2` (always, whatever
       the state of the IP's failure bucket). For the public audience it
       assigns an anonymous actor.


  An optional `:before_auth` hook, `{module, function}`, is called with the
  conn after step 3 and before step 4. The MCP transport uses it to refuse a
  foreign `Origin`. The function must return a conn; a halted conn ends the
  request, so a refusal costs no key lookup and is not charged to the
  failed-authentication bucket. A hook that raises answers `500
  internal_error`.

  On success it assigns `:phoenix_kit_api_actor`, a `PhoenixKit.API.Actor`
  whose `scopes` are the key's effective scopes of this request. On failure
  it sends a problem document and halts: `401 unauthorized` for a missing,
  malformed, unknown, revoked or expired key or a dead owner (one answer for
  all of them, so a probe learns nothing), `403 ip_not_allowed` for a key used
  from outside its allowed addresses.

  ## Failed-authentication throttle

  Failures are counted per client IP (`PhoenixKit.API.RateLimit`), and only
  after the key has been verified and rejected: the plug asks
  `RateLimit.check_preauth/1` (a peek that charges nothing) **after a
  failure**. If the IP's bucket is exhausted the failure is answered `429
  rate_limited` and is not charged again; otherwise it is charged
  (`RateLimit.record_auth_failure/1`) and answered `401` or `403`. A request
  with a valid key never reaches that code, so a neighbour guessing keys from
  the same address cannot lock the accounting system out. The throttle
  limits the answers, not the lookups: every guess still costs one indexed
  read of the key table (an unknown prefix is never cached).
  """

  @behaviour Plug

  import Plug.Conn

  require Logger

  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.LogSafe
  alias PhoenixKit.API.Problem
  alias PhoenixKit.API.RateLimit
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKit.WebsiteAccess.AllowedAddresses
  alias PhoenixKit.WebsiteAccess.Gate

  @credential_params ~w(confirm_token api_key apikey api-key authorization bearer access_token token secret)

  @doc """
  The credential names core knows by heart. `credential_name?/1` adds every name that
  ends in `_token`.

  The boot-time log filter (`PhoenixKit.boot/1`) is built from this list, and Phoenix
  filters a parameter whose name *contains* one of its entries, so `token` also
  keeps every `*_token` out of the log: a name refused here never reaches the log in
  clear text.
  """
  @spec credential_params() :: [String.t()]
  def credential_params, do: @credential_params

  @doc """
  Whether `name` is the name of a credential: one of `credential_params/0`, or any name
  that ends in `_token` (`access_token`, `session_token`, `claim_token`), compared
  without regard to case. `token_count` and `tokens_issued` are not.

  The one rule behind the refusal of a credential in a URL and the redaction of a
  credential from a stored answer (`PhoenixKit.API.Idempotency`).
  """
  @spec credential_name?(term()) :: boolean()
  def credential_name?(name) when is_binary(name) do
    name = String.downcase(name)
    name in @credential_params or String.ends_with?(name, "_token")
  end

  def credential_name?(_name), do: false

  @audiences [:admin, :public]

  @impl Plug
  def init(opts) do
    audience = Keyword.fetch!(opts, :audience)

    unless audience in @audiences do
      raise ArgumentError,
            "PhoenixKit.API.Auth :audience must be :admin or :public, got: #{inspect(audience)}"
    end

    [audience: audience]
    |> put_option(opts, :before_auth, &before_auth!/1)
  end

  defp put_option(init, opts, key, validate) do
    case Keyword.fetch(opts, key) do
      :error -> init
      {:ok, value} -> init ++ [{key, validate.(value)}]
    end
  end

  defp before_auth!({module, function} = hook) when is_atom(module) and is_atom(function),
    do: hook

  defp before_auth!(other) do
    raise ArgumentError,
          "PhoenixKit.API.Auth :before_auth must be {module, function}, got: #{inspect(other)}"
  end

  @impl Plug
  def call(conn, opts) do
    audience = Keyword.fetch!(opts, :audience)
    conn = assign_request_id(conn)

    cond do
      not api_enabled?(audience) -> Problem.send(conn, :not_found, "", %{})
      gated?(conn, audience) -> Problem.send(conn, :not_found, "", %{})
      true -> screen(conn, audience, opts)
    end
  end

  defp screen(conn, audience, opts) do
    if token_in_url?(conn) do
      token_in_url(conn, audience)
    else
      conn |> run_before_auth(opts) |> admit(audience)
    end
  end

  @doc """
  Whether the query string carries a credential: a parameter whose name is a
  credential (`credential_name?/1`: `api_key`, `authorization`, `token`, `secret`,
  anything ending in `_token` and so on; any case, with or without a `[]` suffix),
  or any parameter whose value starts with `pk_` (any case, after trimming spaces).

  Names and values are compared after percent-decoding, so `%61pi_key=...`
  is caught too.
  """
  @spec token_in_url?(Plug.Conn.t()) :: boolean()
  def token_in_url?(%Plug.Conn{query_string: ""}), do: false

  def token_in_url?(%Plug.Conn{query_string: query}) do
    query
    |> URI.query_decoder()
    |> Enum.any?(fn {name, value} -> param_credential?(name) or credential_value?(value) end)
  end

  defp param_credential?(name),
    do: name |> String.split("[", parts: 2) |> hd() |> credential_name?()

  # Any value that starts with `pk_` is refused, whatever its parameter name
  # and on both audiences: a key may sit under a name nobody listed, and the
  # public audience has no business with a `pk_` value either. A search for a
  # `pk_`-prefixed word in the query string is refused too; that is intended.
  defp credential_value?(value),
    do: value |> String.trim() |> String.downcase() |> String.starts_with?("pk_")

  defp api_enabled?(:admin), do: Config.admin_enabled?()
  defp api_enabled?(:public), do: Config.public_enabled?()

  # The caller's pre-authentication check. It runs after everything that
  # answers without work (switch, gate, credential in the URL) and before any
  # key is looked at.
  defp run_before_auth(conn, opts) do
    case Keyword.get(opts, :before_auth) do
      nil -> conn
      {module, function} -> apply_hook(conn, module, function)
    end
  end

  defp apply_hook(conn, module, function) do
    case apply(module, function, [conn]) do
      %Plug.Conn{} = result -> result
      other -> hook_failed(conn, module, function, "returned #{LogSafe.shape(other)}")
    end
  rescue
    error -> hook_failed(conn, module, function, "raised #{LogSafe.exception_label(error)}")
  catch
    kind, reason -> hook_failed(conn, module, function, "#{kind}: #{LogSafe.shape(reason)}")
  end

  defp hook_failed(conn, module, function, what) do
    Logger.error(
      "[PhoenixKit.API] the pre-authentication hook #{inspect(module)}.#{function}/1 #{what} " <>
        "(request #{conn.assigns[:phoenix_kit_api_request_id]})"
    )

    Problem.send(conn, :internal_error, "The request could not be checked.", %{})
  end

  defp admit(%Plug.Conn{halted: true} = conn, _audience), do: conn
  defp admit(conn, :admin), do: authenticate(conn)
  defp admit(conn, :public), do: assign(conn, :phoenix_kit_api_actor, anonymous(conn))

  @doc """
  Whether the website password gate hides the API of `audience` from the
  client of `conn`.

  While the gate is on, the public API is as private as the site: it would
  otherwise hand a gated pre-production site's catalogue and customer data to anyone.
  Addresses on the gate's allow-list pass, like they do for the site. The
  admin API is not gated: it has its own keys.

  Only `PhoenixKit.WebsiteAccess.Gate.enabled?/0` and the address list are
  asked: the gate's session helpers need a fetched session, which an API
  request does not have. Both reads have the semantics of the site gate
  itself: `PhoenixKit.Settings` folds a read error into the setting's default
  (gate off), exactly as `PhoenixKitWeb.Plugs.WebsiteAccess` does for the
  site, so the gate is not made stricter here than it is for the pages it
  protects. The API switch, which is read first, fails closed.

  `PhoenixKit.API.BodyGuard` asks the same question, so a request this
  function turns away is not read or judged there either.
  """
  @spec gated?(Plug.Conn.t(), :admin | :public) :: boolean()
  def gated?(conn, :public),
    do: Gate.enabled?() and not AllowedAddresses.allowed?(client_ip(conn))

  def gated?(_conn, :admin), do: false

  defp token_in_url(conn, :admin) do
    Problem.send(
      conn,
      :token_in_url,
      "Credentials must be sent in the Authorization header, never in the URL.",
      %{}
    )
  end

  # The public API has no Authorization header: a client token travels in the request body.
  defp token_in_url(conn, :public) do
    Problem.send(
      conn,
      :token_in_url,
      "Credentials and client tokens must be sent in the request body, never in the URL.",
      %{}
    )
  end

  defp assign_request_id(conn) do
    request_id =
      case get_resp_header(conn, "x-request-id") do
        [id | _] -> if Problem.safe_request_id?(id), do: id, else: Problem.new_request_id()
        [] -> Problem.new_request_id()
      end

    conn
    |> put_resp_header("x-request-id", request_id)
    |> assign(:phoenix_kit_api_request_id, request_id)
  end

  defp anonymous(conn), do: %Actor{kind: :anonymous, ip: client_ip(conn)}

  defp client_ip(conn), do: IpAddress.client_address(conn) || "unknown"

  # --- admin: bearer key ----------------------------------------------------

  defp authenticate(conn) do
    ip = client_ip(conn)

    # The key is verified first, always: a valid key is never refused for its
    # IP's failures. The failure bucket is consulted only after a rejection.
    case verify(conn, ip) do
      {:ok, %Actor{} = actor} -> assign(conn, :phoenix_kit_api_actor, %{actor | ip: ip})
      {:error, reason} -> reject(conn, ip, reason)
    end
  rescue
    error ->
      # The exception module and the request id only: the message of an
      # exception raised near a bearer token may quote the token.
      Logger.error(
        "[PhoenixKit.API] authentication failed unexpectedly " <>
          "(request #{conn.assigns[:phoenix_kit_api_request_id]}): #{inspect(error.__struct__)}"
      )

      Problem.send(conn, :internal_error, "The request could not be authenticated.", %{})
  end

  defp verify(conn, ip) do
    with {:ok, token} <- bearer_token(conn),
         prefix when is_binary(prefix) <- Keys.token_prefix(token) do
      Keys.verify(token, ip)
    else
      {:error, _reason} = error -> error
      nil -> {:error, :invalid_token}
    end
  end

  defp bearer_token(conn) do
    case get_req_header(conn, "authorization") do
      [value] -> parse_bearer(value)
      _missing_or_repeated -> {:error, :invalid_token}
    end
  end

  defp parse_bearer(value) do
    case value |> String.trim() |> String.split(~r/\s+/, parts: 2) do
      [scheme, token] ->
        if String.downcase(scheme) == "bearer",
          do: {:ok, String.trim(token)},
          else: {:error, :invalid_token}

      _ ->
        {:error, :invalid_token}
    end
  end

  # A rejected key. An IP whose failure bucket is used up is answered 429 and
  # not charged again; any other IP is charged and answered 401 (403 for a key
  # used from an address it does not allow).
  defp reject(conn, ip, reason) do
    case RateLimit.check_preauth(ip) do
      {:error, retry_after} ->
        Problem.send(conn, :rate_limited, "Too many failed authentication attempts.", %{
          retry_after: retry_after
        })

      :ok ->
        :ok = RateLimit.record_auth_failure(ip)
        rejected(conn, reason)
    end
  end

  defp rejected(conn, :ip_not_allowed),
    do: Problem.send(conn, :ip_not_allowed, "This key cannot be used from your address.", %{})

  defp rejected(conn, _reason) do
    Problem.send(
      conn,
      :unauthorized,
      "The API key is missing, invalid, revoked or expired.",
      %{}
    )
  end
end
