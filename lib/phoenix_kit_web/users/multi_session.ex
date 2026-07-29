defmodule PhoenixKitWeb.Users.MultiSession do
  @moduledoc """
  Multi-account session switching.

  The Plug session holds an ordered stack of raw session tokens under
  `:pk_session_accounts`. `hd/1` of the stack is the ROOT account (the original
  login). The currently active token stays in `:user_token`, so all existing auth
  resolution (`fetch_phoenix_kit_current_*`, `on_mount`) is untouched.

  Read helpers (`gate_allowed?/1`, `list_accounts/1`) take the string-keyed session
  map (works from both the plug and the LiveView on_mount). Conn-mutating ops
  (`add_account/3`, `add_authenticated_user/2`, `switch_to/2`, `remove_account/2`,
  logout helpers) take and return a `Plug.Conn`.
  """

  import Plug.Conn

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Role

  @stack_key :pk_session_accounts
  @max_accounts 5

  @doc "Maximum number of accounts allowed in one stack."
  def max_accounts, do: @max_accounts

  @doc """
  The list of raw session tokens in the stack. Falls back to the single active
  token when no explicit stack is stored, and `[]` when there is no active token.
  """
  def stack_tokens(session) when is_map(session) do
    case session["pk_session_accounts"] do
      [_ | _] = stack -> stack
      _ -> session["user_token"] |> List.wrap()
    end
  end

  @doc """
  True when the root session belongs to ANY authenticated user AND the
  `multi_session_enabled` setting is on. Evaluated against the root so the
  switcher stays visible even when a secondary account is active.

  Anonymous (no root token / no valid user) always returns false.
  """
  def gate_allowed?(session) when is_map(session) do
    Settings.get_boolean_setting("multi_session_enabled", false) and root_authenticated?(session)
  end

  defp root_authenticated?(session) do
    with [root_token | _] <- stack_tokens(session),
         %Auth.User{} <- Auth.get_user_by_session_token(root_token) do
      true
    else
      _ -> false
    end
  end

  @doc """
  Resolves each stack token to a render struct:
  `%{ref, user, email, role, active?, root?}`. Tokens that no longer resolve to a
  user (expired/deleted) are dropped.
  """
  def list_accounts(session) when is_map(session) do
    active = session["user_token"]
    tokens = stack_tokens(session)

    tokens
    |> Enum.with_index()
    |> Enum.flat_map(fn {token, index} ->
      case {Auth.get_user_by_session_token(token), Auth.get_session_token_record(token)} do
        {%Auth.User{} = user, %{uuid: ref}} ->
          [
            %{
              ref: ref,
              user: user,
              email: user.email,
              role: role_label(user),
              active?: token == active,
              root?: index == 0
            }
          ]

        _ ->
          []
      end
    end)
  end

  @doc """
  Resolves the two transient Scope fields `{multi_session_allowed?, multi_session_accounts}`
  for a session in one call.

  Crucially, the (DB-heavy) account stack is resolved ONLY when the setting is on.
  When `multi_session_enabled` is off — the default — this short-circuits to
  `{false, []}` without touching the DB, so the hot auth path (plug + every
  LiveView mount) pays nothing for a feature that is disabled.

  When it IS on, `allowed?` is derived from the resolved stack (a surviving root
  account) rather than a separate `gate_allowed?/1` call, which would re-resolve
  the root token in its own query on top of the `list_accounts/1` walk.
  """
  def scope_fields(session) when is_map(session) do
    if Settings.get_boolean_setting("multi_session_enabled", false) do
      accounts = list_accounts(session)
      {Enum.any?(accounts, & &1.root?), accounts}
    else
      {false, []}
    end
  end

  # Returns the user's most descriptive display role name.
  # Priority: Owner > Admin > first custom (non-"User") role > "User".
  # This correctly labels custom roles (e.g. "Manager") instead of
  # bucketing all permission-holders as "Admin".
  #
  # Reads role names straight from `User.get_roles/1` rather than building a full
  # `Scope` — the scope carries an opaque `MapSet` of permissions we don't need
  # here (and constructing it tripped a Dialyzer opaqueness warning).
  defp role_label(user) do
    roles = Auth.User.get_roles(user)
    system = Role.system_roles()

    cond do
      system.owner in roles ->
        system.owner

      system.admin in roles ->
        system.admin

      true ->
        # Pick the first role that isn't the plain "User" baseline.
        # Falls back to "User" (or the system.user name) when no custom role exists.
        Enum.find(roles, system.user, fn r -> r != system.user end)
    end
  end

  @doc """
  Validates credentials and appends a real session for that user to the stack,
  making it the active account. The new account may be any role; the gate is
  enforced by the caller (controller) against the root account.

  Returns `{:error, :already_in_stack}` if the user is already present.
  """
  def add_account(conn, email_or_username, password) do
    session = get_session(conn)
    stack = stack_tokens(session)

    if length(stack) >= @max_accounts do
      {:error, :stack_full}
    else
      case Auth.get_user_by_email_or_username_and_password(email_or_username, password) do
        {:ok, %Auth.User{is_active: true} = user} ->
          if already_in_stack?(stack, user) do
            {:error, :already_in_stack}
          else
            token = Auth.generate_user_session_token(user)

            conn =
              conn
              |> put_session(@stack_key, stack ++ [token])
              |> renew_and_put_active_token(token)

            log_event("session.account_added", root_user(session), user)
            {:ok, conn}
          end

        {:ok, %Auth.User{}} ->
          {:error, :inactive}

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @doc """
  Appends an already-authenticated (active) user to the session stack and makes
  them the active account. Shares all invariants with `add_account/3`:

  - Stack-limit check (`:stack_full`)
  - Dedup check — returns `{:error, :already_in_stack}` if the user is already present
  - Session-fixation protection via `renew_and_put_active_token/2`

  Used by the OAuth add-account callback so the same logic applies whether the
  user was authenticated via password or via OAuth.
  """
  def add_authenticated_user(conn, %Auth.User{is_active: true} = user) do
    session = get_session(conn)
    stack = stack_tokens(session)

    cond do
      length(stack) >= @max_accounts ->
        {:error, :stack_full}

      already_in_stack?(stack, user) ->
        {:error, :already_in_stack}

      true ->
        token = Auth.generate_user_session_token(user)

        conn =
          conn
          |> put_session(@stack_key, stack ++ [token])
          |> renew_and_put_active_token(token)

        log_event("session.account_added", root_user(session), user)
        {:ok, conn}
    end
  end

  def add_authenticated_user(_conn, %Auth.User{}), do: {:error, :inactive}

  @doc """
  Adds `target` to the session stack on an administrator's authority, without
  their password — "log in as this user".

  Shares every invariant of `add_authenticated_user/2` and adds the authority
  checks that separate support access from account takeover:

  - the **root** account decides, never the active one. Otherwise an
    administrator could impersonate a user and, from inside that session,
    impersonate someone the user could never reach;
  - the root must hold the Owner or Admin **role**. Deliberately not
    `can_access_admin_area?/1`: that is true for *any* permission holder, so a
    customer granted one self-service permission would qualify — and could then
    borrow another customer's account;
  - an Owner is never a target. The one account that can undo anything must not
    be reachable by borrowing it;
  - an Admin root cannot take another Admin either — support access is for the
    people being supported, not sideways between staff. An Owner root may,
    because there is nothing above it to escalate to.

  Logged as `session.impersonated` on the activity feed, always, before the
  session changes — an impersonation nobody can see afterwards is the thing that
  makes this feature dangerous.
  """
  @spec impersonate(Plug.Conn.t(), Auth.User.t()) ::
          {:ok, Plug.Conn.t()}
          | {:error,
             :not_allowed
             | :target_is_owner
             | :target_is_staff
             | :stack_full
             | :already_in_stack
             | :inactive
             | :self}
  def impersonate(conn, %Auth.User{} = target) do
    session = get_session(conn)
    actor = root_user(session)

    with :ok <- authorize_impersonation(actor, target) do
      case add_authenticated_user(conn, target) do
        {:ok, conn} ->
          log_event("session.impersonated", actor, target)
          {:ok, conn}

        {:error, _reason} = error ->
          error
      end
    end
  end

  defp authorize_impersonation(nil, _target), do: {:error, :not_allowed}

  defp authorize_impersonation(%Auth.User{} = actor, %Auth.User{} = target) do
    system = Role.system_roles()
    actor_roles = Auth.User.get_roles(actor)
    target_roles = Auth.User.get_roles(target)

    cond do
      actor.uuid == target.uuid ->
        {:error, :self}

      not (system.owner in actor_roles or system.admin in actor_roles) ->
        {:error, :not_allowed}

      system.owner in target_roles ->
        {:error, :target_is_owner}

      system.owner in actor_roles ->
        :ok

      system.admin in target_roles ->
        {:error, :target_is_staff}

      true ->
        :ok
    end
  end

  @doc "Activates a token already present in the stack, identified by `ref`."
  def switch_to(conn, ref) do
    session = get_session(conn)
    stack = stack_tokens(session)

    case find_token_by_ref(stack, ref) do
      nil ->
        {:error, :not_in_stack}

      token ->
        case Auth.ensure_active_user(Auth.get_user_by_session_token(token)) do
          nil ->
            {:error, :inactive}

          user ->
            conn = renew_and_put_active_token(conn, token)
            log_event("session.switched", root_user(session), user)
            {:ok, conn, user}
        end
    end
  end

  @doc "Removes a non-root token from the stack and deletes it from the DB."
  def remove_account(conn, ref) do
    session = get_session(conn)
    stack = stack_tokens(session)
    [root_token | _] = stack

    case find_token_by_ref(stack, ref) do
      nil ->
        {:error, :not_in_stack}

      ^root_token ->
        {:error, :cannot_remove_root}

      token ->
        Auth.delete_user_session_token(token)
        new_stack = List.delete(stack, token)
        conn = put_session(conn, @stack_key, new_stack)

        conn =
          if session["user_token"] == token,
            do: put_active_token(conn, root_token),
            else: conn

        {:ok, conn}
    end
  end

  @doc """
  Logs out the active account. When a non-root account is active, deletes it and
  switches back to root (`{:switched, conn, root_user}`). When the root account is
  active, signals a full logout (`{:full, conn}`) for the caller to run.
  """
  def log_out_active(conn) do
    session = get_session(conn)
    stack = stack_tokens(session)
    [root_token | _] = stack
    active = session["user_token"]

    if active == root_token or length(stack) <= 1 do
      {:full, conn}
    else
      if live_socket_id = session["live_socket_id"] do
        PhoenixKitWeb.Users.Auth.broadcast_disconnect_for_socket(live_socket_id)
      end

      Auth.delete_user_session_token(active)
      new_stack = List.delete(stack, active)
      root_user = Auth.get_user_by_session_token(root_token)

      conn =
        conn
        |> put_session(@stack_key, new_stack)
        |> put_active_token(root_token)

      {:switched, conn, root_user}
    end
  end

  @doc "Deletes every stack token from the DB (used by 'Log out all')."
  def delete_all_stack_tokens(conn) do
    conn |> get_session() |> stack_tokens() |> Enum.each(&Auth.delete_user_session_token/1)
    conn
  end

  # --- internal ---

  # Used for account-switching operations (add/switch): rotates the session ID
  # and drops the CSRF token to prevent session fixation attacks, while
  # preserving all existing session data (configure_session(renew: true) only
  # rotates the id — it does not clear conn.private[:plug_session]).
  defp renew_and_put_active_token(conn, token) do
    Plug.CSRFProtection.delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> put_active_token(token)
  end

  defp put_active_token(conn, token) do
    conn
    |> put_session(:user_token, token)
    |> put_session(:live_socket_id, "phoenix_kit_sessions:#{Base.url_encode64(token)}")
  end

  defp already_in_stack?(stack, %Auth.User{} = user) do
    Enum.any?(stack, fn token ->
      case Auth.get_user_by_session_token(token) do
        %Auth.User{uuid: uuid} -> uuid == user.uuid
        _ -> false
      end
    end)
  end

  defp find_token_by_ref(stack, ref) do
    Enum.find(stack, fn token ->
      match?(%{uuid: ^ref}, Auth.get_session_token_record(token))
    end)
  end

  defp root_user(session) do
    case stack_tokens(session) do
      [root_token | _] -> Auth.get_user_by_session_token(root_token)
      _ -> nil
    end
  end

  defp log_event(action, %Auth.User{} = actor, %Auth.User{} = target) do
    PhoenixKit.Activity.log(%{
      action: action,
      module: "users",
      mode: "auto",
      actor_uuid: actor.uuid,
      resource_type: "user",
      resource_uuid: target.uuid,
      target_uuid: target.uuid,
      metadata: %{"email" => target.email, "actor_role" => "admin"}
    })
  rescue
    _ -> :ok
  end

  defp log_event(_action, _actor, _target), do: :ok
end
