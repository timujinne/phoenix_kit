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
         %Auth.User{} <- root_user_from_token(root_token) do
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

  @doc """
  Returns the user's most descriptive display role name.

  Priority: Owner > Admin > first custom (non-"User") role > "User". This
  correctly labels custom roles (e.g. "Manager", "Client") instead of
  bucketing all permission-holders as "Admin".

  Use this for any "what is this account?" label. In particular do **not**
  derive one from `Scope.can_access_admin_area?/1`: that gate is true for
  Owner, Admin *or any single permission holder*, so a Client — who holds
  `client_portal` — reads back as "Admin".

  Reads role names straight from `User.get_roles/1` rather than building a full
  `Scope` — the scope carries an opaque `MapSet` of permissions we don't need
  here (and constructing it tripped a Dialyzer opaqueness warning).
  """
  def role_label(user), do: user |> Auth.User.get_roles() |> role_label_from_roles()

  @doc """
  `role_label/1` for callers that already hold the role names.

  `Auth.User.get_roles/1` queries, so a render path with the names in hand —
  `Scope`'s `cached_roles`, loaded once at `Scope.for_user/1` — should pass them
  here instead of handing over the user and paying for the lookup again.
  """
  @spec role_label_from_roles([String.t()]) :: String.t()
  def role_label_from_roles(roles) when is_list(roles) do
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

  `event` names the activity-feed action written on success. It exists so
  `impersonate/2` can record what actually happened instead of a second row
  saying `session.account_added` — in the feed those two are the same sentence,
  and one of them is a user adding an account of their own.
  """
  def add_authenticated_user(conn, user, event \\ "session.account_added")

  def add_authenticated_user(conn, %Auth.User{is_active: true} = user, event) do
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

        log_event(event, root_user(session), user)
        {:ok, conn}
    end
  end

  def add_authenticated_user(_conn, %Auth.User{}, _event), do: {:error, :inactive}

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

  A success is logged as `session.impersonated` — one row, written in place of
  the `session.account_added` the stack append would otherwise have written. A
  refusal is logged as `session.impersonation_refused` with the deciding rule in
  `metadata["reason"]`: an impersonation nobody can see afterwards is the thing
  that makes this feature dangerous, and a *rejected* attempt to borrow the
  owner's account is the entry whoever watches the feed most wants to find.

  Refusal rows carry no `target_uuid` on purpose. `Activity.log/1` fans a row
  with one out to that user's notification inbox, and a refused attempt is a
  signal for the feed, not a message to the person it named.
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

    case authorize_impersonation(actor, target) do
      :ok ->
        case add_authenticated_user(conn, target, "session.impersonated") do
          {:ok, conn} ->
            {:ok, conn}

          {:error, reason} = error ->
            log_impersonation_refused(actor, target, reason)
            error
        end

      {:error, reason} = error ->
        log_impersonation_refused(actor, target, reason)
        error
    end
  end

  @doc """
  True when the session's ROOT account holds the authority `impersonate/2`
  requires before it will look at a target at all.

  Exposed so the controller can refuse an unauthorized actor *before* it resolves
  the uuid: resolving first answers "does this account exist?" with a distinct
  message, and this endpoint is reachable by every signed-in user, not only by
  staff. Shares `staff?/1` with `authorize_impersonation/2` so the two rules
  cannot drift apart.
  """
  @spec may_impersonate?(map()) :: boolean()
  def may_impersonate?(session) when is_map(session) do
    case root_user(session) do
      %Auth.User{} = actor -> staff?(actor)
      _ -> false
    end
  end

  @doc """
  The account an impersonation would be judged against — the session's ROOT,
  never the account currently active.

  Returns `nil` when `gate_allowed?/1` is false, which makes `impersonable?/2`
  answer false for every target and takes the offer off the menu. That check
  belongs here rather than at the call sites: the controller opens with the
  same gate (`with_gate`), so without it a menu could offer impersonation while
  `multi_session_enabled` is off and the POST would bounce to the home page
  with "Multi-account switching is not available." The authority rules in
  `authorize_impersonation/2` never see the setting, so asking them alone is
  not enough to predict the outcome.

  Pair with `impersonable?/2` to offer the action only where it would succeed.
  A LiveView can hold the result across a mount safely: it is a `User` struct,
  so nothing keeps a session token in the socket.
  """
  @spec impersonation_actor(map()) :: Auth.User.t() | nil
  def impersonation_actor(session) when is_map(session) do
    if gate_allowed?(session), do: root_user(session)
  end

  @doc """
  True when `actor` may borrow `target`'s account.

  Answers with the same rules `impersonate/2` enforces — it calls the very same
  private predicate — so a menu built on this cannot offer an action the
  request would then refuse, and cannot hide one it would have allowed.

  A deactivated target answers false. That refusal (`:inactive`) is raised by
  `add_authenticated_user/2` rather than by the authority rules, so asking the
  rules alone would put the offer on every deactivated row in the admin list —
  where the status is displayed next to it — and every click would come back
  "That account is deactivated."

  The remaining reasons `impersonate/2` may still decline (the stack being
  full, or the target already sitting in it) depend on session state at request
  time, are recoverable, and report themselves through the controller's flash
  rather than by silently removing the option.

  Target roles come from the `:roles` preload when the caller has one — the
  user detail page loads its user through `get_user_with_roles/1` — and from a
  lookup otherwise.
  """
  @spec impersonable?(Auth.User.t() | nil, Auth.User.t()) :: boolean()
  def impersonable?(actor, target)

  def impersonable?(nil, %Auth.User{}), do: false

  def impersonable?(%Auth.User{} = actor, %Auth.User{is_active: true} = target) do
    decide_impersonation(
      actor.uuid,
      Auth.User.get_roles(actor),
      target.uuid,
      role_names(target)
    ) == :ok
  end

  def impersonable?(%Auth.User{}, %Auth.User{}), do: false

  @doc """
  The subset of `users` the actor may sign in as, as a `MapSet` of uuids.

  `impersonable?/2` reads roles from the database — three lookups per call, once
  the `staff?/1` check is counted — which is fine for one user but is an N+1 per
  row in a list. This reads the actor's roles once and each target's from the
  `:roles` preload the caller already has, falling back to a lookup only for a
  row that arrives without one. Decisions come from the same private predicate
  `impersonate/2` uses, so the two cannot diverge.

  Deactivated rows are left out for the reason given on `impersonable?/2`.

      assign(socket, :impersonable_uuids, MultiSession.impersonable_uuids(actor, users))

  and in the template `:if={user.uuid in @impersonable_uuids}`.
  """
  @spec impersonable_uuids(Auth.User.t() | nil, [Auth.User.t()]) :: MapSet.t()
  def impersonable_uuids(actor, users)

  def impersonable_uuids(nil, _users), do: MapSet.new()

  def impersonable_uuids(%Auth.User{} = actor, users) when is_list(users) do
    actor_roles = Auth.User.get_roles(actor)

    for %Auth.User{is_active: true} = user <- users,
        decide_impersonation(actor.uuid, actor_roles, user.uuid, role_names(user)) == :ok,
        into: MapSet.new(),
        do: user.uuid
  end

  defp role_names(%Auth.User{roles: roles}) when is_list(roles), do: Enum.map(roles, & &1.name)
  defp role_names(%Auth.User{} = user), do: Auth.User.get_roles(user)

  @doc """
  Records an impersonation attempt refused before a target was resolved, so the
  controller's authority-first ordering does not cost the feed an entry.
  """
  @spec log_impersonation_refusal(Plug.Conn.t(), String.t()) :: :ok
  def log_impersonation_refusal(conn, target_uuid) do
    conn
    |> get_session()
    |> root_user()
    |> log_impersonation_refused(target_uuid, :not_allowed)
  end

  defp authorize_impersonation(nil, _target), do: {:error, :not_allowed}

  defp authorize_impersonation(%Auth.User{} = actor, %Auth.User{} = target) do
    decide_impersonation(
      actor.uuid,
      Auth.User.get_roles(actor),
      target.uuid,
      Auth.User.get_roles(target)
    )
  end

  # The rule itself, over role names already in hand. Separated from the lookups
  # so a list render can decide many targets against one actor read; every
  # caller — the request path and the menus — funnels through here.
  defp decide_impersonation(actor_uuid, actor_roles, target_uuid, target_roles) do
    system = Role.system_roles()

    cond do
      actor_uuid == target_uuid ->
        {:error, :self}

      not staff_roles?(actor_roles) ->
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

  # Owner or Admin by ROLE. Deliberately not `can_access_admin_area?/1` — see
  # `impersonate/2`'s docstring for why a permission check opens the door to
  # any customer holding one self-service permission.
  defp staff?(%Auth.User{} = user), do: user |> Auth.User.get_roles() |> staff_roles?()

  defp staff_roles?(roles) when is_list(roles) do
    system = Role.system_roles()
    system.owner in roles or system.admin in roles
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
      [root_token | _] -> root_user_from_token(root_token)
      _ -> nil
    end
  end

  # The root account decides both whether the switcher is offered and who may
  # impersonate, so it must be resolved through the SAME active-user filter the
  # plugs and `switch_to/2` apply. Resolving it with a bare token lookup left
  # a deactivated Owner/Admin — a principal the system has explicitly cut off —
  # holding a still-valid cookie that these two entry points accepted, letting
  # them mint a fresh session as another live user.
  defp root_user_from_token(root_token) do
    root_token
    |> Auth.get_user_by_session_token()
    |> Auth.ensure_active_user()
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

  # A refused impersonation. `target` is a `%User{}` when one was resolved and a
  # bare uuid when the actor was turned away before the lookup; either way the
  # row names what was reached for. No `target_uuid` — see `impersonate/2`.
  defp log_impersonation_refused(%Auth.User{} = actor, target, reason) do
    {target_uuid, target_email} = refusal_target(target)

    PhoenixKit.Activity.log(%{
      action: "session.impersonation_refused",
      module: "users",
      mode: "auto",
      actor_uuid: actor.uuid,
      resource_type: "user",
      resource_uuid: target_uuid,
      target_uuid: nil,
      metadata:
        %{"reason" => to_string(reason), "email" => target_email}
        |> Enum.reject(fn {_k, v} -> is_nil(v) end)
        |> Map.new()
    })
  rescue
    _ -> :ok
  end

  defp log_impersonation_refused(_actor, _target, _reason), do: :ok

  defp refusal_target(%Auth.User{uuid: uuid, email: email}), do: {uuid, email}
  defp refusal_target(uuid) when is_binary(uuid), do: {uuid, nil}
  defp refusal_target(_target), do: {nil, nil}
end
