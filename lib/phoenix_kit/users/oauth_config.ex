defmodule PhoenixKit.Users.OAuthConfig do
  @moduledoc """
  Runtime OAuth configuration management using database credentials.

  This module provides functions to configure OAuth providers at runtime
  by reading credentials from the database and updating the application
  configuration dynamically.
  """

  alias PhoenixKit.Config
  alias PhoenixKit.Settings
  require Logger

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
    missing = find_missing_google_credentials(credentials)

    if missing == [] do
      {:ok, :google}
    else
      {:error, "Missing Google OAuth credentials: #{Enum.join(missing, ", ")}"}
    end
  end

  defp validate_github_credentials(credentials) do
    missing = find_missing_github_credentials(credentials)

    if missing == [] do
      {:ok, :github}
    else
      {:error, "Missing GitHub OAuth credentials: #{Enum.join(missing, ", ")}"}
    end
  end

  defp find_missing_google_credentials(credentials) do
    []
    |> add_if_missing("Client ID", credentials.client_id)
    |> add_if_missing("Client Secret", credentials.client_secret)
  end

  defp find_missing_github_credentials(credentials) do
    []
    |> add_if_missing("Client ID", credentials.client_id)
    |> add_if_missing("Client Secret", credentials.client_secret)
  end

  defp validate_facebook_credentials(credentials) do
    missing = find_missing_facebook_credentials(credentials)

    if missing == [] do
      {:ok, :facebook}
    else
      {:error, "Missing Facebook OAuth credentials: #{Enum.join(missing, ", ")}"}
    end
  end

  defp find_missing_facebook_credentials(credentials) do
    []
    |> add_if_missing("App ID", credentials.app_id)
    |> add_if_missing("App Secret", credentials.app_secret)
  end

  defp add_if_missing(list, field_name, value) do
    if value == "" do
      [field_name | list]
    else
      list
    end
  end

  @doc """
  Tests OAuth connection for a specific provider.

  This function validates the credentials format but does not make actual API calls.
  For true connection testing, OAuth flow needs to be initiated through the browser.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.test_connection(:google)
      {:ok, "Google OAuth credentials are properly formatted"}
  """
  def test_connection(provider) when provider in [:google, :github, :facebook] do
    test_connection_result(provider, validate_credentials(provider))
  end

  @doc """
  Tests OAuth credentials for a specific provider against an explicit
  credentials map, instead of reading from the database.

  Use this to validate unsaved form values (e.g. an admin "Test
  Credentials" button) before the settings are saved — `test_connection/1`
  would otherwise validate the stale, already-persisted credentials.

  ## Examples

      iex> PhoenixKit.Users.OAuthConfig.test_connection(:google, %{client_id: "x", client_secret: "y"})
      {:ok, "Google OAuth credentials are properly formatted. Initiate OAuth flow to test actual connection."}
  """
  def test_connection(provider, %{} = credentials)
      when provider in [:google, :github, :facebook] do
    test_connection_result(provider, validate_credentials_map(provider, credentials))
  end

  defp test_connection_result(provider, {:ok, _provider}) do
    Logger.info(
      "OAuth: #{provider_name(provider)} connection test successful - credentials validated"
    )

    {:ok,
     "#{provider_name(provider)} OAuth credentials are properly formatted. Initiate OAuth flow to test actual connection."}
  end

  defp test_connection_result(provider, {:error, reason}) do
    Logger.warning("OAuth: #{provider_name(provider)} connection test failed: #{reason}")
    {:error, reason}
  end

  defp provider_name(:google), do: "Google"
  defp provider_name(:github), do: "GitHub"
  defp provider_name(:facebook), do: "Facebook"
end
