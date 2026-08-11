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

  require Logger

  alias PhoenixKit.Users.QrLogin, as: QrLoginContext
  alias PhoenixKit.Utils.Routes

  def mount(%{"token" => token}, _session, socket) do
    socket =
      socket
      |> assign(:token, token)
      |> assign(:project_title, PhoenixKit.Settings.get_project_title())
      |> assign(:page_title, gettext("Approve sign-in"))

    # Disabling the setting must act as an immediate kill switch — even for a
    # request minted while it was on.
    if QrLoginContext.enabled?() do
      # Looked up on the dead render as well as the connected one.
      #
      # This used to be gated behind `connected?` so a future non-ETS (DB /
      # Redis) keyfob store wouldn't be queried twice per mount. That saved
      # one read of a read-only, idempotent lookup, and cost the thing this
      # screen exists for: the disconnected render assigned `meta: %{}`, and
      # every row in the device panel is behind a presence guard, so the
      # panel came up EMPTY while the heading, the warning and both buttons
      # rendered fully and looked ready.
      #
      # So the one screen whose whole job is "here is the device asking to
      # sign in as you — is this you?" presented a complete, confident
      # approval prompt with the identifying information silently missing.
      # Usually that window is too short to notice; behind a proxy that does
      # not forward the WebSocket upgrade cleanly it lasts as long as the
      # transport takes to fall back, and it is paid again on every remount.
      # Training people to approve before the details arrive defeats the
      # defense this page is.
      #
      # One extra read is the cheaper side of that trade by a wide margin.
      {state, meta} = look_up(token)
      {:ok, socket |> assign(:kf_state, state) |> assign(:meta, meta)}
    else
      {:ok,
       socket
       |> put_flash(:error, gettext("QR code sign-in is not available."))
       |> redirect(
         to: Routes.safe_destination(socket, scope: socket.assigns[:phoenix_kit_current_scope])
       )}
    end
  end

  # The `case` matches return values, so a store that RAISES instead of
  # answering would go straight past it — and this runs on the disconnected
  # render, where that is a 500 page rather than a LiveView that quietly
  # remounts.
  #
  # keyfob's own store no longer does that (0.1.1 made its reads total, which
  # is why the dependency is pinned there). But `Keyfob.Store` is a behaviour
  # a host may implement over anything — Redis, a database, a cluster-wide
  # cache — and the one thing every one of those has in common is that it can
  # be unreachable in ways ETS cannot. Core cannot assume a stranger's
  # implementation is total.
  #
  # A store that cannot answer means the request is not actionable, which is
  # what "expired" already tells the user — so say that, and log the reason
  # rather than showing them a stack trace.
  @doc false
  # Public only so the raise path can be tested directly.
  def look_up(token) do
    case QrLoginContext.peek(token) do
      {:ok, %{state: :pending, meta: meta}} -> {:pending, meta}
      {:ok, %{state: :approved, meta: meta}} -> {:approved, meta}
      # not_found / expired both present as "expired" to the user — the code
      # is no longer actionable either way.
      _ -> {:expired, %{}}
    end
  rescue
    error ->
      Logger.warning("[PhoenixKit.QrLoginConfirm] could not read the request: #{inspect(error)}")
      {:expired, %{}}
  catch
    # `rescue` alone does not cover this, and this is the shape the failure
    # actually takes. The comment above is right that a host `Keyfob.Store`
    # over Redis or a database "can be unreachable in ways ETS cannot" — and
    # the way those stores are reached is a `GenServer.call`, which EXITS
    # (`:noproc` when the process is gone, `:timeout` when it is wedged)
    # rather than raising. This module's own dependency note says so in as
    # many words: before keyfob 0.1.1 an unreachable store made its reads
    # raise "and its GenServer-backed calls EXIT".
    #
    # So the guard covered one of the two failure modes it was added for, and
    # the uncovered one is the more likely of the pair for exactly the
    # third-party stores the guard exists to survive — on the dead render,
    # where the comment above notes the cost is a 500 page.
    :exit, reason ->
      Logger.warning(
        "[PhoenixKit.QrLoginConfirm] store did not answer: #{inspect(reason)} — " <>
          "presenting the request as expired"
      )

      {:expired, %{}}
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

  # Defensive, and the reason is specific to this page.
  #
  # It is an authenticated mount, so the auth `on_mount` subscribes it to that
  # user's scope topic, and every one of those hooks passes a message it does
  # not recognise through to the LiveView (`{:cont, socket}`). This module had
  # no `handle_info` at all, so any such message was a FunctionClauseError —
  # and a LiveView that crashes here does not fail visibly. The client rejoins
  # and reloads the page, which on the approval screen looks like the scan
  # "not working" rather than like an error.
  #
  # Nothing is known to send one today. That is exactly why it costs nothing
  # to survive, and the log line names the message if something ever does.
  def handle_info(msg, socket) do
    Logger.debug("[PhoenixKit.QrLoginConfirm] ignoring unexpected message: #{inspect(msg)}")
    {:noreply, socket}
  end

  @doc false
  # Does this request carry anything that actually identifies the device?
  #
  # `requested_at` is stamped for every request, so its presence says nothing
  # about whether we know WHO is asking — only these four do, and every one of
  # them is absent when the underlying connect-info or geo lookup is
  # unavailable.
  #
  # Public only so it can be tested directly: it decides whether this screen
  # shows a bare empty panel or says the device could not be determined, and
  # reaching it through a full render drags in settings and a database.
  def identifying_details?(meta) do
    Enum.any?([:browser, :os, :ip, :location], &present?(Map.get(meta, &1)))
  end

  defp present?(value), do: is_binary(value) and String.trim(value) != ""

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
