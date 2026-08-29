defmodule PhoenixKit.Users.OAuthConfig do
  @moduledoc """
  Runtime OAuth configuration management using database credentials.

  This module provides functions to configure OAuth providers at runtime
  by reading credentials from the database and updating the application
  configuration dynamically.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  alias PhoenixKit.Config
  alias PhoenixKit.Integrations.Probe
  alias PhoenixKit.Settings
  require Logger

  # Real issued secrets sit far above this floor — Google's are 24+
  # characters (35 with the current GOCSPX- prefix), GitHub OAuth App
  # secrets are 40 hex characters, Facebook's App Secret is 32 hex
  # characters. This is a plausibility floor, not a per-provider format
  # check (provider formats are not ours to pin down and can change without
  # notice) — it exists to catch the incident that prompted it: a
  # 9-character Google secret saved silently and passed the old "Test
  # Credentials" button (which checked only for non-emptiness) for four
  # days. See dev_docs I135.
  @min_secret_length 16

  @google_token_url "https://oauth2.googleapis.com/token"
  # Syntactically valid, never dereferenced anywhere real: the `code` sent
  # alongside it is always fabricated (see `google_live_check/1`), so this
  # exists only to satisfy the token endpoint's redirect_uri parameter, not
  # to receive a redirect.
  @google_test_redirect_uri "https://phoenixkit.invalid/oauth/callback"
  @google_test_timeout 8_000

  @doc """
  Configures all OAuth providers from database settings.

  This function reads OAuth credentials from the database and updates
  the application configuration at runtime. It should be called:
  - On application startup
  - After updating OAuth credentials via admin UI

  Skips configuration if OAuth is disabled in settings (oauth_enabled = false).

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.configure_providers()
      :ok
  """
  def configure_providers do
    # Always configure Ueberauth base with available providers
    # This ensures Ueberauth has providers configured even if oauth_enabled is false
    # The oauth_enabled flag controls UI visibility, not the underlying OAuth infrastructure
    configure_ueberauth_base()
    configure_google()
    configure_github()
    configure_facebook()

    :ok
  end

  @doc """
  Configures a specific OAuth provider from database settings.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.configure_provider(:google)
      :ok
  """
  def configure_provider(provider) when provider in [:google, :github, :facebook] do
    case provider do
      :google -> configure_google()
      :github -> configure_github()
      :facebook -> configure_facebook()
    end
  end

  # Configure base Ueberauth with available providers
  defp configure_ueberauth_base do
    providers = build_provider_list()

    base_path = PhoenixKit.Config.UeberAuth.get_base_path()

    # Use PhoenixKit.Config.UeberAuth to set the configuration
    Config.UeberAuth.set_all(
      base_path: base_path,
      providers: providers
    )

    if providers != %{} do
      Logger.info(
        "OAuth: Configured Ueberauth with providers: #{inspect(Map.keys(providers))} at base_path: #{base_path}"
      )
    else
      Logger.info(
        "OAuth: Configured Ueberauth with no active providers at base_path: #{base_path}"
      )
    end
  end

  # Build the list of available providers based on configured credentials
  # Uses direct database reads to avoid cache race conditions
  defp build_provider_list do
    providers = %{}

    # Add Google if credentials exist (direct DB read)
    providers =
      if Settings.has_oauth_credentials_direct?(:google) and
           Settings.get_boolean_setting("oauth_google_enabled", false) do
        Map.put(providers, :google, {Ueberauth.Strategy.Google, []})
      else
        providers
      end

    # Add GitHub if credentials exist (direct DB read)
    providers =
      if Settings.has_oauth_credentials_direct?(:github) and
           Settings.get_boolean_setting("oauth_github_enabled", false) do
        # `user:email` is required, not cosmetic. The strategy's default scope is
        # "" (deps/ueberauth_github/.../github.ex:76), and without this scope the
        # token cannot read GET /user/emails — so the strategy stores the user
        # WITHOUT an "emails" key and PhoenixKit has no way to learn whether
        # GitHub verified the address. With the verified-email requirement on,
        # that means every GitHub sign-in to an existing account is refused.
        # Read-only access to the address list is also the minimum scope that
        # answers the question.
        Map.put(providers, :github, {Ueberauth.Strategy.Github, [default_scope: "user:email"]})
      else
        providers
      end

    # Add Facebook if credentials exist (direct DB read)
    providers =
      if Settings.has_oauth_credentials_direct?(:facebook) and
           Settings.get_boolean_setting("oauth_facebook_enabled", false) do
        Map.put(providers, :facebook, {Ueberauth.Strategy.Facebook, []})
      else
        providers
      end

    providers
  end

  # Configure Google OAuth
  # Uses direct DB read to avoid cache race conditions after settings update
  defp configure_google do
    if Settings.get_boolean_setting("oauth_google_enabled", false) do
      credentials = Settings.get_oauth_credentials_direct(:google)

      if credentials.client_id != "" and credentials.client_secret != "" do
        config = [
          client_id: credentials.client_id,
          client_secret: credentials.client_secret
        ]

        Config.UeberAuth.set_provider_strategy_config(
          :google,
          Ueberauth.Strategy.Google.OAuth,
          config
        )

        Logger.info("OAuth: Configured Google OAuth provider")
      else
        Logger.warning("OAuth: Google enabled but credentials not configured")
      end
    end
  end

  # Configure GitHub OAuth
  # Uses direct DB read to avoid cache race conditions after settings update
  defp configure_github do
    if Settings.get_boolean_setting("oauth_github_enabled", false) do
      credentials = Settings.get_oauth_credentials_direct(:github)

      if credentials.client_id != "" and credentials.client_secret != "" do
        config = [
          client_id: credentials.client_id,
          client_secret: credentials.client_secret
        ]

        Config.UeberAuth.set_provider_strategy_config(
          :github,
          Ueberauth.Strategy.Github.OAuth,
          config
        )

        Logger.info("OAuth: Configured GitHub OAuth provider")
      else
        Logger.warning("OAuth: GitHub enabled but credentials not configured")
      end
    end
  end

  # Configure Facebook OAuth
  # Uses direct DB read to avoid cache race conditions after settings update
  defp configure_facebook do
    if Settings.get_boolean_setting("oauth_facebook_enabled", false) do
      credentials = Settings.get_oauth_credentials_direct(:facebook)

      if credentials.app_id != "" and credentials.app_secret != "" do
        config = [
          client_id: credentials.app_id,
          client_secret: credentials.app_secret
        ]

        Config.UeberAuth.set_provider_strategy_config(
          :facebook,
          Ueberauth.Strategy.Facebook.OAuth,
          config
        )

        Logger.info("OAuth: Configured Facebook OAuth provider")
      else
        Logger.warning("OAuth: Facebook enabled but credentials not configured")
      end
    end
  end

  @doc """
  Validates OAuth credentials for a specific provider.

  Returns `{:ok, provider}` if credentials are valid, or `{:error, reason}` if not.
  Uses direct database read for accurate validation.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.validate_credentials(:google)
      {:ok, :google}
  """
  def validate_credentials(provider) when provider in [:google, :github, :facebook] do
    credentials = Settings.get_oauth_credentials_direct(provider)
    validate_credentials_map(provider, credentials)
  end

  # Shared by validate_credentials/1 (DB-backed) and test_connection/2
  # (caller-supplied map, e.g. unsaved form values) so both paths apply
  # the exact same missing-field rules.
  defp validate_credentials_map(:google, credentials),
    do: validate_google_credentials(credentials)

  defp validate_credentials_map(:github, credentials),
    do: validate_github_credentials(credentials)

  defp validate_credentials_map(:facebook, credentials),
    do: validate_facebook_credentials(credentials)

  defp validate_google_credentials(credentials) do
    case find_missing_google_credentials(credentials) do
      [] -> {:ok, :google}
      missing -> {:error, missing_credentials_message(:google, missing)}
    end
  end

  defp validate_github_credentials(credentials) do
    case find_missing_github_credentials(credentials) do
      [] -> {:ok, :github}
      missing -> {:error, missing_credentials_message(:github, missing)}
    end
  end

  defp find_missing_google_credentials(credentials) do
    []
    |> add_if_missing(gettext("Client ID"), credentials.client_id)
    |> add_if_missing(gettext("Client Secret"), credentials.client_secret)
  end

  defp find_missing_github_credentials(credentials) do
    []
    |> add_if_missing(gettext("Client ID"), credentials.client_id)
    |> add_if_missing(gettext("Client Secret"), credentials.client_secret)
  end

  defp validate_facebook_credentials(credentials) do
    case find_missing_facebook_credentials(credentials) do
      [] -> {:ok, :facebook}
      missing -> {:error, missing_credentials_message(:facebook, missing)}
    end
  end

  defp find_missing_facebook_credentials(credentials) do
    []
    |> add_if_missing(gettext("App ID"), credentials.app_id)
    |> add_if_missing(gettext("App Secret"), credentials.app_secret)
  end

  defp missing_credentials_message(provider, missing) do
    gettext("Missing %{provider} OAuth credentials: %{fields}",
      provider: provider_name(provider),
      fields: Enum.join(missing, ", ")
    )
  end

  # A field consisting of only whitespace ("   ") is not a value — the old
  # `value == ""` check let it through as if it were a real, non-empty
  # credential.
  defp add_if_missing(list, field_name, value) do
    if blank?(value) do
      [field_name | list]
    else
      list
    end
  end

  defp blank?(nil), do: true
  defp blank?(value) when is_binary(value), do: String.trim(value) == ""
  defp blank?(_), do: false

  @doc """
  Validates the *format* of a single OAuth secret value.

  Independent of `test_connection/2` below — this needs no network and no
  already-saved state, so it is cheap enough to run on every settings save,
  not just on a "Test Credentials" click. A blank value is not an error:
  OAuth is opt-in per provider, and an unconfigured secret is a legitimate
  state (`PhoenixKit.Settings.Setting.optional_settings/0` already allows
  these keys to be empty). A value that is only whitespace, or implausibly
  short (see `@min_secret_length`), is rejected with a message naming why.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.validate_secret_format(:google, "")
      :ok

      iex> {:error, _reason} = PhoenixKit.Users.OAuthConfig.validate_secret_format(:google, "short")
  """
  @spec validate_secret_format(atom(), String.t() | nil) :: :ok | {:error, String.t()}
  def validate_secret_format(_provider, nil), do: :ok
  def validate_secret_format(_provider, ""), do: :ok

  def validate_secret_format(provider, value)
      when provider in [:google, :github, :facebook] and is_binary(value) do
    trimmed = String.trim(value)

    cond do
      trimmed == "" ->
        {:error,
         gettext("%{provider} secret cannot be only whitespace",
           provider: provider_name(provider)
         )}

      String.length(trimmed) < @min_secret_length ->
        {:error,
         gettext(
           "%{provider} secret looks too short to be real (%{length} characters, expected at least %{min}) — double-check you copied the whole value",
           provider: provider_name(provider),
           length: String.length(trimmed),
           min: @min_secret_length
         )}

      true ->
        :ok
    end
  end

  @doc """
  Tests OAuth credentials for a specific provider against the database.

  Reads the currently-saved credentials and delegates to `test_connection/2`
  — see that function for what "testing" actually does per provider.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.test_connection(:google)
      {:error, "Missing Google OAuth credentials: Client Secret, Client ID"}
  """
  def test_connection(provider) when provider in [:google, :github, :facebook] do
    test_connection(provider, Settings.get_oauth_credentials_direct(provider))
  end

  @doc """
  Tests OAuth credentials for a specific provider against an explicit
  credentials map, instead of reading from the database.

  Use this to validate unsaved form values (e.g. an admin "Test
  Credentials" button) before the settings are saved — `test_connection/1`
  would otherwise validate the stale, already-persisted credentials.

  Three distinct outcomes, never conflated:

    * `{:ok, message}` — the credentials were accepted. For Google, this
      means Google's own token endpoint authenticated the client_id/secret
      pair (see `google_live_check/1`). For GitHub/Facebook, no live
      network round trip is made yet (see the moduledoc note below) — this
      means only that the fields are present and not implausibly short.
    * `{:error, message}` — the credentials were rejected: missing, blank,
      too short to be real, or (Google) actively refused by the provider.
    * `{:error, message}` — could not reach the provider at all (timeout,
      DNS failure, connection refused) or got back a response that could
      not be classified as either of the above. This is a DIFFERENT
      situation from a rejection and must never be reported as one — an
      admin in a network-isolated deployment must not read "invalid
      credentials" when the real story is "no route to Google".

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.test_connection(:github, %{client_id: "x", client_secret: "0123456789abcdef"})
      {:ok, "GitHub OAuth credentials are properly formatted. Initiate OAuth flow to test actual connection."}
  """
  def test_connection(provider, %{} = credentials)
      when provider in [:google, :github, :facebook] do
    with {:ok, _provider} <- validate_credentials_map(provider, credentials),
         :ok <- validate_secret_format(provider, Map.get(credentials, secret_field(provider))) do
      provider
      |> live_test_result(credentials)
      |> tap(&log_test_result(provider, &1))
    else
      {:error, reason} ->
        Logger.warning("OAuth: #{provider_name(provider)} connection test failed: #{reason}")
        {:error, reason}
    end
  end

  defp secret_field(:google), do: :client_secret
  defp secret_field(:github), do: :client_secret
  defp secret_field(:facebook), do: :app_secret

  # Google: an actual network round trip against Google's own token
  # endpoint, bounded by `PhoenixKit.Integrations.Probe` (the same
  # deadline/isolation wrapper the Integrations "Test Connection" checks
  # use, rather than reinventing timeout-and-crash handling here).
  defp live_test_result(:google, credentials) do
    Probe.run(fn -> google_live_check(credentials) end, @google_test_timeout)
  end

  # GitHub/Facebook: no live network round trip (yet). Chosen deliberately
  # over reaching for all three at once — see dev_docs I135 report for the
  # full reasoning. In short: the reported incident and the mechanism this
  # task specifies are both Google-specific (Google's authorization_code
  # exchange cleanly separates "bad client" from "bad code" via
  # invalid_client/invalid_grant); GitHub's `/login/oauth/access_token` and
  # Facebook's `/oauth/access_token` would need their own from-scratch
  # verification of the same three-outcome property before being trusted
  # here, which this change does not do. Format is already known-good at
  # this point (`validate_credentials_map/2` + `validate_secret_format/2`
  # both passed), so this is an honest "looks right" verdict, not a
  # "verified against the provider" one — same wording the button always
  # used for these two providers, now just gettext-wrapped and only reached
  # when the format checks actually passed.
  defp live_test_result(provider, _credentials) when provider in [:github, :facebook] do
    {:ok,
     gettext(
       "%{provider} OAuth credentials are properly formatted. Initiate OAuth flow to test actual connection.",
       provider: provider_name(provider)
     )}
  end

  defp google_live_check(%{client_id: client_id, client_secret: client_secret}) do
    @google_token_url
    |> Req.post(
      form: [
        client_id: client_id,
        client_secret: client_secret,
        code: "phoenix-kit-credential-check-#{System.unique_integer([:positive])}",
        grant_type: "authorization_code",
        redirect_uri: @google_test_redirect_uri
      ],
      receive_timeout: @google_test_timeout,
      retry: false
    )
    |> interpret_google_token_response()
  end

  @doc false
  # Pure: a Req-response-shaped tuple in, an operator-facing verdict out —
  # public so the three-way classification is unit-testable against
  # synthetic Google responses, without a network round trip (see
  # oauth_config_test.exs). The two documented outcomes for POSTing a
  # syntactically-valid-but-fabricated authorization `code` to Google's
  # token endpoint (RFC 6749 §5.2):
  #
  #   "invalid_client" -> Google does not recognize this client_id/secret
  #                        pair — the credentials themselves are wrong.
  #   "invalid_grant"  -> Google authenticated the client fine and only
  #                        rejected the (deliberately fake) code — the
  #                        credentials are right.
  #
  # Anything else — a different error code, an unexpected status, or a
  # transport failure — is INCONCLUSIVE, never coerced into either verdict.
  # Confirmed live (dev_docs I135 report): Google's own front door can
  # answer a well-formed request with a generic anti-abuse "invalid_request"
  # page instead of a real invalid_client/invalid_grant, so a response we
  # cannot positively classify must not be read as either a yes or a no.
  def interpret_google_token_response({:ok, %{body: %{"error" => "invalid_client"}}}) do
    {:error,
     gettext(
       "Google rejected these credentials (invalid_client) — the Client ID and Client Secret do not match a registered Google OAuth app"
     )}
  end

  def interpret_google_token_response({:ok, %{body: %{"error" => "invalid_grant"}}}) do
    {:ok,
     gettext(
       "Google accepted these credentials. (The test authorization code was rejected, as expected — a full sign-in still requires the real OAuth flow.)"
     )}
  end

  def interpret_google_token_response({:ok, %{status: status}}) do
    {:error,
     gettext(
       "Google gave an inconclusive response (status %{status}) while checking these credentials — try again in a moment",
       status: status
     )}
  end

  def interpret_google_token_response({:error, reason}) do
    Logger.warning(
      "OAuth: Google credential check could not reach the provider: #{inspect(reason)}"
    )

    {:error,
     gettext(
       "Could not reach Google to verify these credentials — check network connectivity and try again"
     )}
  end

  defp log_test_result(provider, {:ok, _message}) do
    Logger.info("OAuth: #{provider_name(provider)} connection test successful")
  end

  defp log_test_result(provider, {:error, reason}) do
    Logger.warning("OAuth: #{provider_name(provider)} connection test failed: #{reason}")
  end

  defp provider_name(:google), do: "Google"
  defp provider_name(:github), do: "GitHub"
  defp provider_name(:facebook), do: "Facebook"
end
