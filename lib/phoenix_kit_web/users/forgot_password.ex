defmodule PhoenixKitWeb.Users.ForgotPassword do
  @moduledoc """
  LiveView for password reset request.

  Allows users to request a password reset by providing their email address.
  Sends password reset instructions via email if the account exists.

  ## Security Features

  - Rate limiting to prevent abuse (3 requests per 5 minutes per IP)
  - Timing attack protection via async processing and fake work simulation
  - Generic messages to prevent user enumeration
  - All operations logged for security monitoring
  """
  use PhoenixKitWeb, :live_view

  require Logger

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.{IpAddress, Routes}

  def mount(_params, _session, socket) do
    {:ok, assign(socket, form: to_form(%{}, as: "user"), sending: false)}
  end

  def handle_event("send_email", %{"user" => %{"email" => email}}, socket) do
    # Check rate limit before processing
    ip_address = get_connect_info(socket, :peer_data) |> IpAddress.extract_ip_address()
    rate_limit_key = "auth:password_reset:#{ip_address}"

    case Hammer.check_rate(rate_limit_key, 300_000, 3) do
      {:allow, _count} ->
        # Rate limit check passed - process request asynchronously
        socket =
          socket
          |> assign(:sending, true)
          |> start_async(:send_reset_email, fn -> process_password_reset(email) end)

        {:noreply, socket}

      {:deny, _limit} ->
        # Rate limit exceeded
        Logger.warning("Password reset rate limit exceeded",
          ip: ip_address,
          email: email,
          event: "rate_limit_violation"
        )

        {:noreply,
         socket
         |> put_flash(
           :error,
           "Too many password reset requests. Please try again in a few minutes."
         )
         |> redirect(to: "/")}
    end
  end

  # Handle async task completion
  def handle_async(:send_reset_email, {:ok, _result}, socket) do
    info =
      "If your email is in our system, you will receive instructions to reset your password shortly."

    {:noreply,
     socket
     |> assign(:sending, false)
     |> put_flash(:info, info)
     |> redirect(to: "/")}
  end

  def handle_async(:send_reset_email, {:exit, reason}, socket) do
    Logger.error("Password reset email task failed: #{inspect(reason)}")

    # Still show generic message to prevent information disclosure
    info =
      "If your email is in our system, you will receive instructions to reset your password shortly."

    {:noreply,
     socket
     |> assign(:sending, false)
     |> put_flash(:info, info)
     |> redirect(to: "/")}
  end

  # Process password reset request with timing attack protection
  defp process_password_reset(email) do
    case Auth.get_user_by_email(email) do
      %Auth.User{} = user ->
        # User exists - send actual reset email
        Auth.deliver_user_reset_password_instructions(
          user,
          &Routes.url("/users/reset-password/#{&1}")
        )

        Logger.info("Password reset email sent", email: email)
        {:ok, :email_sent}

      nil ->
        # User not found - simulate work to prevent timing attacks
        # Generate fake token to match real processing time
        _fake_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

        # Simulate email sending delay (50-150ms)
        Process.sleep(:rand.uniform(100) + 50)

        Logger.info("Password reset requested for non-existent email", email: email)
        {:ok, :no_user}
    end
  end
end
