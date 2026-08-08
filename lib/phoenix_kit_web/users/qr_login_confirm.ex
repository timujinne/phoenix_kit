defmodule PhoenixKitWeb.Users.QrLoginConfirm do
  @moduledoc """
  Phone-side approval screen for QR device-handoff login.

  Opened on the user's already-signed-in phone (via the QR the desktop
  shows). It displays the requesting device and, on the user's **explicit**
  Approve, calls `PhoenixKit.Users.QrLogin.approve/2` — minting the login
  token that signs the waiting browser in. There is no auto-approve: this
  screen is the defense against QR-jacking.

  Authenticated route — the phone must already be signed in. If it isn't,
  the authenticated pipeline redirects to the login page first.
  """
  use PhoenixKitWeb, :live_view

  alias PhoenixKit.Users.QrLogin, as: QrLoginContext
  alias PhoenixKit.Utils.Routes

  def mount(%{"token" => token}, _session, socket) do
    socket =
      socket
      |> assign(:token, token)
      |> assign(:project_title, PhoenixKit.Settings.get_project_title())
      |> assign(:page_title, gettext("Approve sign-in"))

    cond do
      # Disabling the setting must act as an immediate kill switch — even
      # for a request minted while it was on.
      not QrLoginContext.enabled?() ->
        {:ok,
         socket
         |> put_flash(:error, gettext("QR code sign-in is not available."))
         |> redirect(
           to:
             Routes.safe_destination(socket,
               scope: socket.assigns[:phoenix_kit_current_scope]
             )
         )}

      # peek/2 is a read-only, idempotent ETS lookup, but gate it behind
      # connected? anyway so a future non-ETS (e.g. DB/Redis) keyfob store
      # doesn't get queried on both the dead and the connected mount.
      connected?(socket) ->
        {state, meta} =
          case QrLoginContext.peek(token) do
            {:ok, %{state: :pending, meta: meta}} -> {:pending, meta}
            {:ok, %{state: :approved, meta: meta}} -> {:approved, meta}
            # not_found / expired both present as "expired" to the user —
            # the code is no longer actionable either way.
            _ -> {:expired, %{}}
          end

        {:ok, socket |> assign(:kf_state, state) |> assign(:meta, meta)}

      true ->
        {:ok, socket |> assign(:kf_state, :pending) |> assign(:meta, %{})}
    end
  end

  def handle_event("keyfob_approve", _params, socket) do
    if QrLoginContext.enabled?() do
      user = socket.assigns.phoenix_kit_current_user

      case QrLoginContext.approve(socket.assigns.token, user.uuid) do
        :ok ->
          QrLoginContext.log_approval(user, socket.assigns.meta)
          {:noreply, assign(socket, :kf_state, :approved)}

        {:error, reason} ->
          {:noreply,
           socket
           |> assign(:kf_state, error_state(reason))
           |> put_flash(:error, error_message(reason))}
      end
    else
      # The setting was disabled after this page loaded — refuse the
      # approval instead of letting an in-flight flow complete.
      {:noreply,
       socket
       |> assign(:kf_state, :expired)
       |> put_flash(:error, gettext("QR code sign-in is not available."))}
    end
  end

  def handle_event("keyfob_deny", _params, socket) do
    QrLoginContext.deny(socket.assigns.token)
    {:noreply, assign(socket, :kf_state, :denied)}
  end

  # A no-longer-pending request (expired / consumed / already approved on
  # another device) renders as "expired"; a genuine deny is separate.
  defp error_state(:not_pending), do: :expired
  defp error_state(:expired), do: :expired
  defp error_state(_), do: :expired

  defp error_message(:not_pending),
    do: gettext("This sign-in was already handled.")

  defp error_message(_),
    do: gettext("This sign-in request expired or is no longer valid.")

  defp confirm_labels do
    %{
      title: gettext("Approve this sign-in?"),
      subtitle: gettext("A browser is asking to sign in as you."),
      browser: gettext("Browser"),
      os: gettext("Device"),
      ip: gettext("IP address"),
      location: gettext("Location"),
      requested_at: gettext("Requested"),
      warning:
        gettext("Only approve if this is you. Approving signs that browser in to your account."),
      approve: gettext("Approve"),
      deny: gettext("Deny"),
      approved: gettext("Signed in"),
      approved_hint: gettext("You can close this page."),
      denied: gettext("Request denied."),
      expired: gettext("This request expired or was already used.")
    }
  end
end
