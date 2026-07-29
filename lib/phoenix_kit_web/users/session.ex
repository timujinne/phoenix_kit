defmodule PhoenixKitWeb.Users.Session do
  @moduledoc """
  Controller for handling user session management.

  This controller manages user login and logout operations, including:
  - Creating new sessions via email/password authentication
  - Handling post-registration and password update flows
  - Session termination (logout)
  - GET-based logout for direct URL access

  ## Security Features

  - Prevents user enumeration by not disclosing whether an email is registered
  - Supports remember me functionality via UserAuth module
  - Session renewal on login/logout to prevent fixation attacks
  """
  use PhoenixKitWeb, :controller

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Utils.IpAddress
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Users.Auth, as: UserAuth
  alias PhoenixKitWeb.Users.MultiSession

  def create(conn, %{"_action" => "registered"} = params) do
    create(conn, params, "Account created successfully!", :registered)
  end

  def create(conn, %{"_action" => "password_updated"} = params) do
    create(
      conn,
      carry_remember_me(conn, params),
      "Password updated successfully!",
      :password_updated
    )
  end

  def create(conn, params) do
    create(conn, params, "Welcome back!", :login)
  end

  # The destination is stashed only once the credentials check out. Doing it up
  # front leaked it into the failure branches, so a rejected registration
  # handoff left `after_registration_path` in the session and the user's NEXT
  # ordinary login landed on the registration page.
  defp stash_destination(conn, :registered), do: maybe_store_after_registration_path(conn)

  defp stash_destination(conn, :password_updated),
    do: put_session(conn, :user_return_to, Routes.path("/dashboard/settings"))

  defp stash_destination(conn, _), do: conn

  defp create(conn, %{"user" => user_params}, info, action) do
    %{"password" => password} = user_params
    # Support both old "email" field and new "email_or_username" field for backwards compatibility
    email_or_username = user_params["email_or_username"] || user_params["email"]
    ip_address = IpAddress.extract_from_conn(conn)

    case Auth.get_user_by_email_or_username_and_password(email_or_username, password, ip_address) do
      {:ok, %Auth.User{is_active: false}} ->
        # Valid credentials but account is inactive
        conn
        |> put_flash(
          :error,
          "Your account is currently inactive. Please contact the team if you believe this is an error."
        )
        |> put_flash(:email_or_username, String.slice(email_or_username, 0, 160))
        |> redirect(to: Routes.path("/users/log-in"))

      {:ok, user} ->
        # Valid credentials and active account
        conn
        |> stash_destination(action)
        |> maybe_store_return_to_from_params(user_params)
        |> put_flash(:info, info)
        |> UserAuth.log_in_user(user, user_params)

      {:error, :rate_limit_exceeded} ->
        # Rate limit exceeded - show specific error message
        conn
        |> put_flash(:error, "Too many login attempts. Please try again later.")
        |> put_flash(:email_or_username, String.slice(email_or_username, 0, 160))
        |> redirect(to: Routes.path("/users/log-in"))

      {:error, :invalid_credentials} ->
        # Invalid credentials (wrong email/username or password)
        # In order to prevent user enumeration attacks, don't disclose whether the email/username is registered.
        conn
        |> put_flash(:error, "Invalid email/username or password")
        |> put_flash(:email_or_username, String.slice(email_or_username, 0, 160))
        |> redirect(to: Routes.path("/users/log-in"))
    end
  end

  # Logout: "all" drains the whole stack; otherwise log out the active account only
  # (falling back to root) unless root is active, in which case full logout runs.
  def delete(conn, %{"all" => _} = _params) do
    # log_out_user/1 drains the whole multi-session stack, so this is now just a
    # relabelled full logout (kept distinct for the clearer flash message).
    conn
    |> put_flash(:info, "Logged out of all accounts.")
    |> UserAuth.log_out_user()
  end

  def delete(conn, _params) do
    case MultiSession.log_out_active(conn) do
      {:switched, conn, user} ->
        conn
        |> put_flash(:info, gettext("Logged out. Now signed in as %{email}.", email: user.email))
        |> redirect(to: Routes.path("/"))

      {:full, conn} ->
        # Root account is active → full logout. log_out_user/1 drains the whole
        # stack (after resolving the user for the disconnect broadcast).
        conn
        |> put_flash(:info, "Logged out successfully.")
        |> UserAuth.log_out_user()
    end
  end

  # --- multi-session helpers ---

  defp with_gate(conn, _params, fun) do
    if MultiSession.gate_allowed?(get_session(conn)) do
      fun.(conn)
    else
      # Feature is off (or no valid root) — send the user home with a flash. A bare
      # redirect (302) lets the flash render; a 403 would swallow it (the browser
      # never follows the Location header on a non-3xx response).
      conn
      |> put_flash(:error, "Multi-account switching is not available.")
      |> redirect(to: Routes.path("/"))
    end
  end

  defp redirect_back(conn, params) do
    if Routes.local_path?(params["return_to"]) do
      redirect(conn, to: params["return_to"])
    else
      redirect(conn, to: Routes.path("/"))
    end
  end

  # Changing a password deletes every token for the user, the one inside the
  # live remember-me cookie included, and the dashboard form that re-logs them
  # in carries no checkbox. Without this the user keeps a cookie pointing at a
  # deleted token: fine until the browser drops its session cookie, then a
  # silent sign-out — the exact failure this module's remember-me work exists
  # to prevent. Re-authenticating as themselves, so carrying their existing
  # choice forward is right; an absent cookie stays absent.
  defp carry_remember_me(conn, %{"user" => user_params} = params) do
    if UserAuth.remembered?(conn) do
      %{params | "user" => Map.put(user_params, "remember_me", "true")}
    else
      params
    end
  end

  defp carry_remember_me(_conn, params), do: params

  # Configured landing page for freshly registered accounts
  # (`after_registration_path` setting; empty = fall through to the
  # after-login default). An explicit destination always wins over the
  # setting: a return_to already stashed in the session (by an auth gate) is
  # left alone, and a return_to carried by the form overwrites the session
  # key afterwards (maybe_store_return_to_from_params/2 runs later in the
  # shared create/3).
  #
  # Re-guarded on read exactly like `Routes.post_auth_path/1` does for
  # `after_login_path`: trimmed (the changeset trims the CHANGE, but settings
  # are persisted from `changeset.params`, so a stored value can still carry
  # surrounding whitespace), rejected if not local, and rejected if it points
  # at a sign-in page — a hand-edited DB row must not become an open redirect
  # or a login loop.
  defp maybe_store_after_registration_path(conn) do
    path =
      "after_registration_path"
      |> PhoenixKit.Settings.get_setting("")
      |> to_string()
      |> String.trim()

    if path != "" and Routes.local_path?(path) and not Routes.auth_page?(path) and
         is_nil(get_session(conn, :user_return_to)) do
      put_session(conn, :user_return_to, path)
    else
      conn
    end
  end

  # Store return_to from form params (e.g., guest checkout → login → back to checkout)
  defp maybe_store_return_to_from_params(conn, %{"return_to" => return_to})
       when is_binary(return_to) and return_to != "" do
    if Routes.local_path?(return_to) do
      put_session(conn, :user_return_to, return_to)
    else
      conn
    end
  end

  defp maybe_store_return_to_from_params(conn, _params), do: conn

  # Support GET logout for direct URL access. log_out_user/1 drains the whole
  # multi-session stack, so secondary tokens are invalidated here too.
  def get_logout(conn, _params) do
    conn
    |> put_flash(:info, "Logged out successfully.")
    |> UserAuth.log_out_user()
  end

  def add_account(conn, %{"user" => %{"password" => password} = user_params} = params) do
    email_or_username = user_params["email_or_username"] || user_params["email"]

    with_gate(conn, params, fn conn ->
      case MultiSession.add_account(conn, email_or_username, password) do
        {:ok, conn} ->
          conn |> put_flash(:info, "Account added.") |> redirect_back(params)

        {:error, :stack_full} ->
          conn
          |> put_flash(:error, "Maximum number of accounts reached.")
          |> redirect_back(params)

        {:error, :already_in_stack} ->
          conn
          |> put_flash(:error, "That account is already in your session.")
          |> redirect_back(params)

        {:error, _reason} ->
          conn
          |> put_flash(:error, "Invalid email/username or password.")
          |> redirect_back(params)
      end
    end)
  end

  def set_active_account(conn, %{"ref" => ref} = params) do
    with_gate(conn, params, fn conn ->
      case MultiSession.switch_to(conn, ref) do
        {:ok, conn, user} ->
          conn
          |> put_flash(:info, gettext("Switched to %{email}.", email: user.email))
          |> redirect_back(params)

        {:error, _reason} ->
          conn |> put_flash(:error, "Could not switch account.") |> redirect_back(params)
      end
    end)
  end

  @doc """
  Adds a user to the session stack on an administrator's authority — the
  "log in as this user" button in the admin area.

  The authority checks live in `MultiSession.impersonate/2`; this action only
  translates their outcome into a flash. Each refusal says which rule stopped it,
  because "could not do that" on a support tool is how an operator ends up
  guessing at permissions.

  The precise refusals are for operators, so the actor's authority is settled
  BEFORE the uuid is resolved. The other order hands every signed-in user — the
  gate admits all of them, it only asks that the root session be real — a
  distinct "User not found." for an unused uuid and a different message for a
  used one, which is an account-existence oracle wearing a support tool's copy.
  """
  def impersonate(conn, %{"user_uuid" => user_uuid} = params) do
    with_gate(conn, params, fn conn ->
      if MultiSession.may_impersonate?(get_session(conn)) do
        lookup_and_impersonate(conn, user_uuid, params)
      else
        MultiSession.log_impersonation_refusal(conn, user_uuid)

        conn
        |> put_flash(:error, impersonation_error(:not_allowed))
        |> redirect_back(params)
      end
    end)
  end

  defp lookup_and_impersonate(conn, user_uuid, params) do
    case Auth.get_user(user_uuid) do
      nil ->
        conn |> put_flash(:error, gettext("User not found.")) |> redirect_back(params)

      user ->
        do_impersonate(conn, user, params)
    end
  end

  defp do_impersonate(conn, user, params) do
    case MultiSession.impersonate(conn, user) do
      {:ok, conn} ->
        conn
        |> put_flash(:info, gettext("You are now signed in as %{email}.", email: user.email))
        |> redirect_back(params)

      {:error, reason} ->
        conn |> put_flash(:error, impersonation_error(reason)) |> redirect_back(params)
    end
  end

  defp impersonation_error(:not_allowed),
    do: gettext("You do not have permission to sign in as another user.")

  defp impersonation_error(:target_is_owner), do: gettext("An owner account cannot be used.")

  defp impersonation_error(:target_is_staff),
    do: gettext("Only an owner can sign in as another administrator.")

  defp impersonation_error(:self), do: gettext("That is already your account.")
  defp impersonation_error(:inactive), do: gettext("That account is deactivated.")

  defp impersonation_error(:stack_full),
    do: gettext("Maximum number of accounts reached — remove one first.")

  defp impersonation_error(:already_in_stack),
    do: gettext("That account is already in your session — switch to it instead.")

  # No catch-all: `MultiSession.impersonate/2`'s spec enumerates the reasons, so
  # Dialyzer proves one unreachable (`pattern_match_cov`) and fails the gate. A
  # new reason has to be given copy here, which is the point — the refusals are
  # for operators, and a generic fallback is how one ends up guessing.

  def remove_account(conn, %{"ref" => ref} = params) do
    with_gate(conn, params, fn conn ->
      case MultiSession.remove_account(conn, ref) do
        {:ok, conn} ->
          conn |> put_flash(:info, "Account removed.") |> redirect_back(params)

        {:error, :cannot_remove_root} ->
          conn
          |> put_flash(:error, "Cannot remove your primary account.")
          |> redirect_back(params)

        {:error, _reason} ->
          conn |> put_flash(:error, "Could not remove account.") |> redirect_back(params)
      end
    end)
  end
end
