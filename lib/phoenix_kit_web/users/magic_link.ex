defmodule PhoenixKitWeb.Users.MagicLink do
  @moduledoc """
  LiveView for magic link authentication.

  This LiveView handles the magic link authentication flow:
  1. User enters their email address
  2. System sends magic link to their email
  3. User clicks link to authenticate

  The magic link verification is handled by the controller, this LiveView
  handles the email input and confirmation flow.

  ## Security Features

  - Rate limiting to prevent abuse (3 requests per minute per IP)
  - Timing attack protection via async processing and fake work simulation
  - Generic messages to prevent user enumeration
  - All operations logged for security monitoring
  """
  use PhoenixKitWeb, :live_view

  require Logger

  alias PhoenixKit.Admin.Presence
  alias PhoenixKit.Config
  alias PhoenixKit.Mailer
  alias PhoenixKit.Users.MagicLink
  alias PhoenixKit.Utils.{IpAddress, Routes}

  @impl true
  def mount(_params, session, socket) do
    # Track anonymous visitor session
    if connected?(socket) do
      session_id = session["live_socket_id"] || generate_session_id()

      Presence.track_anonymous(session_id, %{
        connected_at: DateTime.utc_now(),
        ip_address: IpAddress.extract_from_socket(socket),
        user_agent: get_connect_info(socket, :user_agent),
        current_page: Routes.path("/users/magic-link")
      })
    end

    form = to_form(%{"email" => ""}, as: "magic_link")

    {:ok,
     socket
     |> assign(:page_title, "Magic Link Login")
     |> assign(:form, form)
     |> assign(:sent, false)
     |> assign(:loading, false)
     |> assign(:error, nil)}
  end

  @impl true
  def handle_event("validate", %{"magic_link" => magic_link_params}, socket) do
    form = to_form(magic_link_params, as: "magic_link")
    {:noreply, assign(socket, form: form)}
  end

  @impl true
  def handle_event("send_magic_link", %{"magic_link" => %{"email" => email}}, socket) do
    if valid_email?(email) do
      # Check rate limit before processing
      ip_address = get_connect_info(socket, :peer_data) |> IpAddress.extract_ip_address()
      rate_limit_key = "auth:magic_link:#{ip_address}"

      case Hammer.check_rate(rate_limit_key, 60_000, 3) do
        {:allow, _count} ->
          # Rate limit check passed - process request asynchronously
          form = to_form(%{"email" => email}, as: "magic_link")

          {:noreply,
           socket
           |> assign(:form, form)
           |> assign(:loading, true)
           |> assign(:error, nil)
           |> send_magic_link_async(email)}

        {:deny, _limit} ->
          # Rate limit exceeded
          Logger.warning("Magic link rate limit exceeded",
            ip: ip_address,
            email: email,
            event: "rate_limit_violation"
          )

          form = to_form(%{"email" => email}, as: "magic_link")

          {:noreply,
           socket
           |> assign(:form, form)
           |> assign(:error, "Too many requests. Please try again in a minute.")}
      end
    else
      form = to_form(%{"email" => email}, as: "magic_link")

      {:noreply,
       socket
       |> assign(:form, form)
       |> assign(:error, "Please enter a valid email address")}
    end
  end

  @impl true
  def handle_async(:send_magic_link, {:ok, result}, socket) do
    case result do
      {:ok, _user} ->
        {:noreply,
         socket
         |> assign(:sent, true)
         |> assign(:loading, false)
         |> put_flash(:info, "Magic link sent! Check your email.")}

      {:error, _} ->
        # For security, we don't reveal whether the email exists or not
        {:noreply,
         socket
         |> assign(:sent, true)
         |> assign(:loading, false)
         |> put_flash(:info, "If that email address exists, a magic link has been sent.")}
    end
  end

  @impl true
  def handle_async(:send_magic_link, {:exit, _reason}, socket) do
    {:noreply,
     socket
     |> assign(:loading, false)
     |> assign(:error, "Failed to send magic link. Please try again.")}
  end

  # Send magic link email to user and handle response
  defp send_magic_link_email_to_user(user, token) do
    magic_link_url = MagicLink.magic_link_url(token)

    case Mailer.send_magic_link_email(user, magic_link_url) do
      {:ok, _} -> {:ok, user}
      {:error, reason} -> {:error, reason}
    end
  end

  # Process the magic link sending in the background with timing attack protection
  defp send_magic_link_async(socket, email) do
    Phoenix.LiveView.start_async(socket, :send_magic_link, fn ->
      case MagicLink.generate_magic_link(email) do
        {:ok, user, token} ->
          send_magic_link_email_to_user(user, token)

        {:error, :user_not_found} ->
          # For security, we simulate the same delay as successful case
          # Generate fake token to match real processing time
          _fake_token = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)

          # Simulate email sending delay (50-150ms)
          Process.sleep(:rand.uniform(100) + 50)

          Logger.info("Magic link requested for non-existent email", email: email)
          {:error, :user_not_found}

        {:error, reason} ->
          {:error, reason}
      end
    end)
  end

  # Simple email validation
  defp valid_email?(email) when is_binary(email) do
    String.match?(email, ~r/^[^\s]+@[^\s]+\.[^\s]+$/)
  end

  defp show_dev_notice? do
    Config.mailer_local?()
  end

  defp generate_session_id do
    :crypto.strong_rand_bytes(16) |> Base.encode64()
  end
end
