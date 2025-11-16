defmodule PhoenixKitWeb.Plugs.RateLimiter do
  @moduledoc """
  Rate limiting plug for protecting authentication endpoints from brute-force attacks.

  This plug uses Hammer to implement configurable rate limiting based on IP address
  or other identifiers. It helps prevent:

  - Brute-force login attempts
  - Password reset abuse
  - Magic link flooding
  - Account enumeration attacks
  - Denial of Service (DoS)

  ## Usage

  In your router or controller:

      plug PhoenixKitWeb.Plugs.RateLimiter,
        key: "login",
        limit: 5,
        window_ms: 60_000,
        by: :ip

  ## Options

  - `key` (required) - Unique identifier for this rate limit (e.g., "login", "password_reset")
  - `limit` (optional) - Maximum number of requests allowed in the time window (default: 5)
  - `window_ms` (optional) - Time window in milliseconds (default: 60_000 = 1 minute)
  - `by` (optional) - Rate limit identifier strategy:
    - `:ip` - Rate limit by IP address (default)
    - `:email` - Rate limit by email address from params
    - `:combined` - Rate limit by combination of IP and email
  - `error_message` (optional) - Custom error message to display
  - `redirect_to` (optional) - Path to redirect to when rate limited (default: "/")

  ## Examples

      # Basic IP-based rate limiting (5 requests per minute)
      plug PhoenixKitWeb.Plugs.RateLimiter,
        key: "login",
        limit: 5,
        window_ms: 60_000

      # Stricter password reset limiting (3 requests per 5 minutes)
      plug PhoenixKitWeb.Plugs.RateLimiter,
        key: "password_reset",
        limit: 3,
        window_ms: 300_000,
        error_message: "Too many password reset attempts. Please try again later."

      # Email-based rate limiting
      plug PhoenixKitWeb.Plugs.RateLimiter,
        key: "magic_link",
        limit: 3,
        window_ms: 60_000,
        by: :email

  ## Rate Limit Headers

  This plug adds the following headers to help clients understand rate limits:

  - `X-RateLimit-Limit` - Maximum requests allowed in window
  - `X-RateLimit-Remaining` - Remaining requests in current window
  - `X-RateLimit-Reset` - Time when the rate limit window resets (Unix timestamp)

  ## Configuration

  The Hammer backend is configured in config/config.exs:

      config :hammer,
        backend: {Hammer.Backend.ETS, [
          expiry_ms: 60_000 * 60 * 2,
          cleanup_interval_ms: 60_000 * 10
        ]}

  For production with Redis:

      config :hammer,
        backend: {Hammer.Backend.Redis, [
          expiry_ms: 60_000 * 60 * 4,
          redis_url: System.get_env("REDIS_URL")
        ]}

  ## Security Considerations

  - **IP Spoofing**: Ensure your load balancer/proxy properly sets `X-Forwarded-For` header
  - **Distributed Systems**: Use Redis backend for multi-node deployments
  - **Rate Limit Bypass**: Consider combining IP and email-based limiting for critical endpoints
  - **Logging**: All rate limit violations are logged for security monitoring
  """

  import Plug.Conn
  import Phoenix.Controller, only: [put_flash: 3, redirect: 2]

  require Logger

  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.IpAddress

  @doc """
  Initializes the rate limiter plug with the provided options.
  """
  def init(opts) do
    key = Keyword.fetch!(opts, :key)
    limit = Keyword.get(opts, :limit, 5)
    window_ms = Keyword.get(opts, :window_ms, 60_000)
    by = Keyword.get(opts, :by, :ip)
    error_message = Keyword.get(opts, :error_message, default_error_message())
    redirect_to = Keyword.get(opts, :redirect_to, "/")

    %{
      key: key,
      limit: limit,
      window_ms: window_ms,
      by: by,
      error_message: error_message,
      redirect_to: redirect_to
    }
  end

  @doc """
  Checks rate limits and either allows the request or blocks it.
  """
  def call(conn, opts) do
    # Check if rate limiting is globally enabled
    if rate_limiting_enabled?() do
      identifier = get_identifier(conn, opts.by)
      rate_limit_key = "#{opts.key}:#{identifier}"

      case Hammer.check_rate(rate_limit_key, opts.window_ms, opts.limit) do
        {:allow, count} ->
          # Request allowed - add rate limit headers
          conn
          |> add_rate_limit_headers(opts.limit, count, opts.window_ms)
          |> put_private(:rate_limit_key, rate_limit_key)

        {:deny, limit} ->
          # Rate limit exceeded - log and block
          log_rate_limit_violation(identifier, opts.key, limit, opts.window_ms)

          conn
          |> add_rate_limit_headers(opts.limit, opts.limit, opts.window_ms)
          |> put_flash(:error, opts.error_message)
          |> redirect(to: opts.redirect_to)
          |> halt()
      end
    else
      # Rate limiting disabled - allow all requests
      conn
    end
  end

  # Get unique identifier for rate limiting based on strategy
  defp get_identifier(conn, :ip) do
    IpAddress.extract_from_conn(conn)
  end

  defp get_identifier(conn, :email) do
    email = get_email_from_params(conn)
    email || IpAddress.extract_from_conn(conn)
  end

  defp get_identifier(conn, :combined) do
    ip = IpAddress.extract_from_conn(conn)
    email = get_email_from_params(conn)
    "#{ip}:#{email || "anonymous"}"
  end

  # Extract email from various parameter formats
  defp get_email_from_params(conn) do
    params = conn.params

    cond do
      # Standard nested format: %{"user" => %{"email" => "..."}}
      is_map(params["user"]) and is_binary(params["user"]["email"]) ->
        params["user"]["email"]

      # Magic link format: %{"magic_link" => %{"email" => "..."}}
      is_map(params["magic_link"]) and is_binary(params["magic_link"]["email"]) ->
        params["magic_link"]["email"]

      # Direct format: %{"email" => "..."}
      is_binary(params["email"]) ->
        params["email"]

      # Email not found
      true ->
        nil
    end
  end

  # Add rate limit headers to response
  defp add_rate_limit_headers(conn, limit, current_count, window_ms) do
    remaining = max(limit - current_count, 0)
    reset_time = System.system_time(:second) + div(window_ms, 1000)

    conn
    |> put_resp_header("x-ratelimit-limit", to_string(limit))
    |> put_resp_header("x-ratelimit-remaining", to_string(remaining))
    |> put_resp_header("x-ratelimit-reset", to_string(reset_time))
  end

  # Log rate limit violations for security monitoring
  defp log_rate_limit_violation(identifier, key, limit, window_ms) do
    Logger.warning("Rate limit exceeded",
      identifier: identifier,
      rate_limit_key: key,
      limit: limit,
      window_ms: window_ms,
      event: "rate_limit_violation"
    )
  end

  # Check if rate limiting is globally enabled via settings
  defp rate_limiting_enabled? do
    Settings.get_boolean_setting("auth_rate_limiting_enabled", true)
  end

  # Default error message for rate limit violations
  defp default_error_message do
    "Too many requests. Please try again later."
  end

  @doc """
  Manually check rate limit without blocking the request.

  Useful for custom rate limiting logic or displaying warnings.

  ## Examples

      case PhoenixKitWeb.Plugs.RateLimiter.check_limit("login:192.168.1.1", 60_000, 5) do
        {:allow, count} -> IO.puts("Allowed, attempt #{count}")
        {:deny, _limit} -> IO.puts("Rate limited")
      end
  """
  def check_limit(key, window_ms, limit) do
    Hammer.check_rate(key, window_ms, limit)
  end

  @doc """
  Reset rate limit for a specific identifier.

  Useful for administrative purposes or after successful authentication.

  ## Examples

      PhoenixKitWeb.Plugs.RateLimiter.reset_limit("login:192.168.1.1")
  """
  def reset_limit(key) do
    Hammer.delete_buckets(key)
  end

  @doc """
  Get current rate limit status for an identifier.

  Returns tuple with {current_count, limit, window_ms, time_remaining_ms}

  ## Examples

      {count, limit, window, remaining} = PhoenixKitWeb.Plugs.RateLimiter.get_status("login:192.168.1.1", 60_000, 5)
      IO.puts("Used #{count}/#{limit} attempts, resets in #{remaining}ms")
  """
  def get_status(key, window_ms, limit) do
    case Hammer.check_rate(key, window_ms, limit) do
      {:allow, count} ->
        {count, limit, window_ms, window_ms - (System.system_time(:millisecond) % window_ms)}

      {:deny, _} ->
        {limit, limit, window_ms, 0}
    end
  end
end
