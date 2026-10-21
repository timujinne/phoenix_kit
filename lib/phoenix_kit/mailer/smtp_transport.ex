defmodule PhoenixKit.Mailer.SmtpTransport do
  @moduledoc """
  Builds the gen_smtp/Swoosh connection options for an SMTP integration.

  Extracted so that *sending* and *"Test Connection"* are driven by literally the
  same options — a check that connects differently from the sender is a check
  that can lie in either direction. It is a pure function of the credentials map
  and depends on nothing else in the tree (in particular not on
  `PhoenixKit.Integrations`, which would otherwise close a
  Integrations → Validators → Mailer → Integrations cycle).

  It does not decide *where* a connection may go: options for a personal
  connection must pass `PhoenixKit.Mailer.SmtpEndpointPolicy.enforce/3` before
  a socket opens, as `PhoenixKit.Mailer` and `PhoenixKit.Integrations.Validators`
  do.

  ## Operator settings

  Everything below is derived from the `smtp` provider's setup fields. All of
  them are optional; left blank, the transport behaves exactly as it did when
  the port was the only signal:

    * `security` — `auto` (default) | `ssl` | `starttls` | `starttls_optional` |
      `none`. `auto` reproduces the historical rule: port 465 means implicit
      TLS, anything else means STARTTLS — required when credentials are present,
      opportunistic when they are not.
    * `verify_cert` — `verify_peer` (default) | `verify_none`.
    * `ca_cert` — PEM bundle for a private/self-signed CA. Replaces the system
      store for this connection.
    * `auth` — `if_available` (default) | `always` | `never`. Carried in the
      built options, so the Test Connection probe reads the operator's choice
      instead of guessing (it still upgrades `if_available` → `always` for the
      probe only — see `PhoenixKit.Integrations.Validators.smtp/1` — because a
      tolerated AUTH failure would let a wrong password pass the check).
    * `timeout` — seconds; maps to gen_smtp's `:timeout`.

  ## TLS

  gen_smtp supplies **no** TLS options of its own, and OTP's `:ssl` now defaults
  to `verify: :verify_peer` with no CA store. Left alone, that means:

    * implicit TLS (465, `ssl: true`) dies on connect with
      `{:options, :incompatible, [verify: :verify_peer, cacerts: :undefined]}`;
    * STARTTLS (`tls: :always`) fails the handshake with `:tls_failed`.

  So the options below are load-bearing, not decoration. They ride on `sockopts`
  for implicit TLS (gen_smtp hands those straight to `:ssl.connect/4`) and on
  `tls_options` for STARTTLS.

  Note that passing `tls_options` *replaces* gen_smtp's default
  `[{versions, ['tlsv1', 'tlsv1.1', 'tlsv1.2']}]` wholesale (it merges with
  `lists:ukeymerge/3`). That is deliberate: we take OTP's defaults, which drop
  the long-dead TLS 1.0/1.1 and allow TLS 1.3.

  ## Certificate verification is not optional when credentials are on the wire

  If no CA store can be found we refuse to build a config for a relay that
  expects a password (`{:error, :no_ca_store}`) rather than silently falling back
  to `verify: :verify_none` — an unauthenticated TLS peer can present any
  certificate, terminate the connection and harvest the AUTH exchange. A relay
  that takes no credentials has nothing to protect, so it degrades instead.

  An operator who *chooses* `verify_none` (or `security: none`) gets what they
  asked for: the point of those settings is the internal relay with a
  self-signed certificate, or none at all. They are never reached by `auto`.
  """

  require Logger

  @doc """
  Returns `{:ok, options}` for gen_smtp/`Swoosh.Adapters.SMTP`, or `{:error, reason}`.

  Reasons: `{:invalid_smtp_port, term}`, `{:invalid_security, term}`,
  `{:invalid_verify_cert, term}`, `{:invalid_auth, term}`,
  `{:invalid_timeout, term}`, `:invalid_ca_cert`, `:no_ca_store`.
  """
  @spec config(map()) :: {:ok, keyword()} | {:error, term()}
  def config(creds) when is_map(creds), do: config(creds, cacerts())

  @doc """
  Same as `config/1`, with the trusted CA store supplied explicitly.

  The options are a pure function of the credentials and the CA store; `config/1`
  simply reads the store from the system. Passing it in makes the fail-closed
  branch — no CA store, credentials on the wire — reachable from a test.
  """
  @spec config(map(), [binary()] | [tuple()]) :: {:ok, keyword()} | {:error, term()}
  def config(creds, cacerts) when is_map(creds) and is_list(cacerts) do
    with {:ok, port} <- parse_port(creds["port"]),
         {:ok, security} <- parse_security(creds["security"]),
         {:ok, verify} <- parse_verify_cert(creds["verify_cert"]),
         {:ok, auth} <- parse_auth(creds["auth"]),
         {:ok, timeout} <- parse_timeout(creds["timeout"]),
         {:ok, store} <- resolve_cacerts(creds["ca_cert"], cacerts, security, verify),
         {:ok, transport} <- transport(security, port, creds, verify, store) do
      base = [
        relay: creds["host"],
        port: port,
        username: creds["username"],
        password: creds["password"],
        # An explicitly configured smarthost is an address, not a domain to
        # resolve: gen_smtp would otherwise MX-look-up the relay and connect to
        # whatever the MX records point at, while we pin SNI and the hostname
        # check to the configured name — a guaranteed certificate mismatch.
        no_mx_lookups: true,
        auth: auth
      ]

      {:ok, base ++ timeout_option(timeout) ++ transport}
    end
  end

  # Setup fields are typed `:number` but travel through LiveView form params and
  # JSONB storage as strings — normalize either shape. A port we cannot parse
  # would silently become gen_smtp's default (25) and relay to an unintended
  # server, so it is an error, not a fallback.
  defp parse_port(port) when is_integer(port), do: {:ok, port}

  defp parse_port(port) when is_binary(port) do
    case Integer.parse(port) do
      {int, _} -> {:ok, int}
      :error -> {:error, {:invalid_smtp_port, port}}
    end
  end

  defp parse_port(port), do: {:error, {:invalid_smtp_port, port}}

  # Blank (never configured, or cleared in the form) means "keep deciding from
  # the port", which is what every connection created before these fields
  # existed relies on.
  defp parse_security(value) when value in [nil, "", "auto"], do: {:ok, :auto}
  defp parse_security("ssl"), do: {:ok, :ssl}
  defp parse_security("starttls"), do: {:ok, :starttls}
  defp parse_security("starttls_optional"), do: {:ok, :starttls_optional}
  defp parse_security("none"), do: {:ok, :none}
  defp parse_security(other), do: {:error, {:invalid_security, other}}

  defp parse_verify_cert(value) when value in [nil, "", "verify_peer"], do: {:ok, :verify_peer}
  defp parse_verify_cert("verify_none"), do: {:ok, :verify_none}
  defp parse_verify_cert(other), do: {:error, {:invalid_verify_cert, other}}

  # gen_smtp's own default is :if_available; keep it so an existing connection
  # sends exactly as it did before the field existed.
  defp parse_auth(value) when value in [nil, "", "if_available"], do: {:ok, :if_available}
  defp parse_auth("always"), do: {:ok, :always}
  defp parse_auth("never"), do: {:ok, :never}
  defp parse_auth(other), do: {:error, {:invalid_auth, other}}

  defp parse_timeout(value) when value in [nil, ""], do: {:ok, nil}

  defp parse_timeout(value) when is_integer(value) and value > 0, do: {:ok, value}

  # The remainder has to be empty: `Integer.parse/1` is happy to return 30 for
  # "30s" or "30 minutes", and silently sending on a timeout the operator did
  # not type is worse than telling them the field is wrong.
  defp parse_timeout(value) when is_binary(value) do
    case Integer.parse(String.trim(value)) do
      {int, ""} when int > 0 -> {:ok, int}
      _ -> {:error, {:invalid_timeout, value}}
    end
  end

  defp parse_timeout(value), do: {:error, {:invalid_timeout, value}}

  defp timeout_option(nil), do: []
  defp timeout_option(seconds), do: [timeout: seconds * 1000]

  # A pasted PEM bundle replaces the system store for this connection only.
  # `pem_decode/1` returns [] for anything that is not PEM at all, which is the
  # one shape worth rejecting outright — silently falling back to the system
  # store would leave the operator staring at a handshake failure with a CA they
  # believe is installed.
  # Nothing to resolve when no TLS options will be built: rejecting a plaintext
  # relay because of a stale PEM in a field it never reads is an error about a
  # certificate that would not have been used.
  defp resolve_cacerts(_pem, _system_store, :none, _verify), do: {:ok, []}
  defp resolve_cacerts(_pem, _system_store, _security, :verify_none), do: {:ok, []}

  defp resolve_cacerts(pem, system_store, _security, _verify),
    do: resolve_cacerts(pem, system_store)

  defp resolve_cacerts(pem, system_store) when pem in [nil, ""], do: {:ok, system_store}

  defp resolve_cacerts(pem, _system_store) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [] ->
        {:error, :invalid_ca_cert}

      entries ->
        ders = for {:Certificate, der, :not_encrypted} <- entries, do: der
        if ders == [], do: {:error, :invalid_ca_cert}, else: {:ok, ders}
    end
  rescue
    _ -> {:error, :invalid_ca_cert}
  end

  defp resolve_cacerts(_pem, _system_store), do: {:error, :invalid_ca_cert}

  # `auto`: port 465 = implicit TLS (SMTPS). gen_smtp decides the protocol solely
  # from the `ssl` option (`gen_smtp_client.erl` — `ssl: true` → ssl socket, else
  # plaintext tcp); `tls` only drives a STARTTLS upgrade *after* a plaintext
  # connect, so `tls: :always` on 465 would open plaintext to an SMTPS port.
  defp transport(:auto, 465, creds, verify, store), do: transport(:ssl, 465, creds, verify, store)

  defp transport(:auto, port, creds, verify, store) do
    # Credentials on the wire: mandatory, verified STARTTLS. Fail closed rather
    # than let a stripped STARTTLS capability downgrade us to plaintext. Nothing
    # to protect: still offer verified TLS, but do not refuse a relay without it.
    mode = if credentials?(creds), do: :starttls, else: :starttls_optional
    transport(mode, port, creds, verify, store)
  end

  defp transport(:ssl, _port, creds, verify, store) do
    case tls_options(creds, verify, store) do
      {:ok, tls_opts} -> {:ok, [ssl: true, sockopts: tls_opts]}
      {:error, _} = error -> error
    end
  end

  defp transport(:starttls, _port, creds, verify, store) do
    case tls_options(creds, verify, store) do
      {:ok, tls_opts} -> {:ok, [tls: :always, tls_options: tls_opts]}
      {:error, _} = error -> error
    end
  end

  defp transport(:starttls_optional, _port, creds, verify, store) do
    case tls_options(creds, verify, store) do
      {:ok, tls_opts} -> {:ok, [tls: :if_available, tls_options: tls_opts]}
      {:error, _} = error -> error
    end
  end

  # Explicitly plaintext. gen_smtp's default for `tls` is :if_available, so the
  # only way to truly stay in the clear is to say :never — otherwise a relay that
  # advertises STARTTLS would still be upgraded, which is not what the operator
  # picked.
  defp transport(:none, _port, _creds, _verify, _store), do: {:ok, [tls: :never]}

  defp tls_options(_creds, :verify_none, _store), do: {:ok, [verify: :verify_none]}

  defp tls_options(creds, :verify_peer, []) do
    if credentials?(creds) do
      {:error, :no_ca_store}
    else
      Logger.warning(
        "No system CA certificates found — SMTP TLS certificate verification is disabled " <>
          "for this credential-less relay. Install a CA bundle to enable it."
      )

      {:ok, [verify: :verify_none]}
    end
  end

  defp tls_options(creds, :verify_peer, cacerts) do
    {:ok,
     [
       verify: :verify_peer,
       # NOT optional, and not a copy-paste default: gen_smtp's own socket
       # layer ships `{depth, 0}` (smtp_socket.erl:43,52) and merges it into
       # whatever we pass. Depth 0 means "no intermediate CAs allowed", so
       # every real certificate chain (leaf + intermediate) fails
       # verification and the handshake dies with `:tls_failed`. Verified
       # against a live relay: omit this key and the connection fails 4/4;
       # set it to anything >= 1 and it succeeds. 10 is the conventional
       # ceiling for a chain.
       depth: 10,
       cacerts: cacerts,
       server_name_indication: sni(creds["host"]),
       customize_hostname_check: [
         match_fun: :public_key.pkix_verify_hostname_match_fun(:https)
       ]
     ]}
  end

  defp sni(host) when is_binary(host) and host != "", do: to_charlist(host)
  defp sni(_host), do: :disable

  defp cacerts do
    :public_key.cacerts_get()
  rescue
    _ -> []
  end

  defp credentials?(creds), do: not (blank?(creds["username"]) and blank?(creds["password"]))

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false
end
