defmodule PhoenixKitWeb.Users.ReferralGate do
  @moduledoc """
  Where the invite-only gate parks an account that has not been admitted yet.

  With `referral_codes_required` on, an account can be created by any route —
  password, magic link, OAuth — but cannot use the application until it has
  satisfied the requirement. Every authentication gate redirects here; this
  page is what unblocks it. See the "Invite-only access gate" section of
  `PhoenixKit.Users.Referrals` for the full rule set.

  Deliberate properties, all of them inherited from the same reasoning that
  hardened the registration form:

  - **Submit-only.** There is no `phx-change`, so a code is checked when the
    user says they are done, not on every keystroke. Per-keystroke checking
    both burns the rate limit on half-typed codes and hands an attacker a much
    faster oracle.
  - **One message for every failure.** Wrong, expired, inactive, used up — all
    of them read the same. Distinguishing them confirms which guesses named a
    real code. Operators get the real reason from `Logger.debug`.
  - **Limited per account as well as per IP.** This screen is behind login, so
    an IP-keyed limit alone is defeated by making another account.

  A user who cannot get a code is not stranded: log-out is reachable from here,
  and it is deliberately the only other thing that is.
  """
  use PhoenixKitWeb, :live_view

  require Logger

  alias PhoenixKit.Users.RateLimiter
  alias PhoenixKit.Users.Referrals
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKit.Utils.Routes

  @impl true
  def mount(params, session, socket) do
    user = socket.assigns[:phoenix_kit_current_user]

    # `:context` threads the socket's router so `"/"` is only used where the
    # host actually declares a root route. Without it the resolver synthesises
    # `"/"` literally, which 404s on any host that has no root route — exactly
    # the configuration core-owned redirect destinations exists to handle.
    destination =
      Routes.post_auth_path([params["return_to"], session["user_return_to"]],
        context: socket,
        scope: socket.assigns[:phoenix_kit_current_scope]
      )

    cond do
      is_nil(user) ->
        # Nothing to admit. Sending them to log-in rather than rendering an
        # empty form avoids a page that asks an anonymous visitor for a code
        # and then has nowhere to put it.
        {:ok, redirect(socket, to: Routes.path("/users/log-in"))}

      # Prefer the mounted scope (the user form would have to rebuild one to
      # evaluate the full-access exemption), but fall back to the user rather
      # than passing `nil`: `access_satisfied?/1` answers `true` for a subject
      # it cannot judge — correct for an anonymous visitor, and a silent
      # admission for a logged-in one whose scope assign is missing.
      Referrals.access_satisfied?(socket.assigns[:phoenix_kit_current_scope] || user) ->
        # Already admitted — covers a code redeemed in another tab, an
        # invitation that arrived while this page sat open, and an operator
        # switching invite-only off.
        {:ok, redirect(socket, to: destination)}

      true ->
        {:ok,
         socket
         |> assign(:page_title, gettext("Enter your referral code"))
         |> assign(:destination, destination)
         |> assign(:error, nil)
         |> assign(:ip_address, IpAddress.extract_from_socket(socket))
         |> assign(:form, to_form(%{"code" => ""}, as: "referral"))}
    end
  end

  @impl true
  def handle_event("redeem", %{"referral" => %{"code" => code}}, socket) do
    user = socket.assigns.phoenix_kit_current_user

    with :ok <- RateLimiter.check_referral_redemption_rate_limit(user.uuid),
         {:ok, %{} = validated} <- validate(code, socket) do
      admit(socket, user, validated)
    else
      {:error, :rate_limit_exceeded} ->
        {:noreply, reject(socket, code, gettext("Too many attempts. Please try again shortly."))}

      # A blank submission, or an enabled-but-not-required config. Neither can
      # admit anyone, so both read as a plain rejection rather than falling
      # through to `admit/3` with nothing to record.
      {:ok, nil} ->
        {:noreply, reject(socket, code, gettext("That code can't be used"))}

      {:error, message} when is_binary(message) ->
        {:noreply, reject(socket, code, message)}

      # Anything else — an unexpected limiter shape, a future error atom. A
      # `with` whose else clauses are not exhaustive raises `WithClauseError`
      # and takes the page down, on the one page a parked user can reach.
      other ->
        Logger.warning("[ReferralGate] unexpected validation result: #{inspect(other)}")
        {:noreply, reject(socket, code, gettext("That code can't be used"))}
    end
  end

  defp validate(code, socket) do
    Referrals.validate_for_signup(code,
      enabled?: true,
      required?: true,
      context: :submit,
      ip_address: socket.assigns.ip_address
    )
  end

  defp admit(socket, user, validated_code) do
    # `redeem/2` claims the use and marks the account in ONE transaction.
    # Separately, a failed mark after a successful claim would burn a use of a
    # possibly single-use code and leave the user still parked — and retrying
    # the same code would now legitimately fail.
    case Referrals.redeem(user, validated_code.code) do
      {:ok, _user} ->
        {:noreply,
         socket
         |> put_flash(:info, gettext("Welcome! Your referral code has been accepted."))
         |> redirect(to: socket.assigns.destination)}

      {:error, reason} ->
        # Includes losing the last use of a code to someone else between
        # validation and redemption. Nothing was consumed, so the generic
        # rejection is honest here; the real reason goes to the log.
        Logger.info("[ReferralGate] #{user.uuid} could not redeem a code: #{inspect(reason)}")

        {:noreply, reject(socket, "", gettext("That code can't be used"))}
    end
  end

  defp reject(socket, code, message) do
    socket
    |> assign(:error, message)
    |> assign(:form, to_form(%{"code" => code}, as: "referral"))
  end
end
