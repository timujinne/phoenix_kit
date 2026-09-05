defmodule PhoenixKit.Users.Sessions do
  @moduledoc """
  Context for managing user sessions in PhoenixKit.

  This module provides functions for listing, viewing, and managing active user sessions.
  It's primarily used by the admin interface to monitor and control user sessions.

  ## Functions

  - `list_active_sessions/0` - Get all currently active sessions
  - `list_user_sessions/1` - Get all active sessions for a specific user
  - `get_session_info/1` - Get detailed information about a specific session
  - `revoke_session/1` - Revoke a specific session token
  - `revoke_user_sessions/1` - Revoke all sessions for a specific user
  - `count_active_sessions/0` - Get total count of active sessions

  ## Session Information

  Each session includes:
  - User information (id, email, status)
  - Session creation time
  - Session token (first 8 chars for identification)
  - Session age and validity status
  """

  import Ecto.Query, warn: false
  require Logger
  alias PhoenixKit.Admin.Events
  alias PhoenixKit.RepoHelper, as: Repo
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.{KnownDevice, User, UserToken}
  alias PhoenixKit.Utils.Date, as: UtilsDate
  alias PhoenixKit.Utils.TimeZone

  @session_validity_in_days 60

  @doc """
  Lists all currently active sessions with user information.

  Returns a list of maps containing session and user details.

  ## Examples

      iex> list_active_sessions()
      [
        %{
          token_uuid: "019b5704-3680-7b95-...",
          token_preview: "abc12345",
          user: %User{uuid: "019b5704-...", email: "user@example.com"},
          created_at: ~N[2024-01-01 12:00:00],
          expires_at: ~N[2024-03-02 12:00:00],
          is_current: false
        }
      ]

  """
  def list_active_sessions(scope \\ :active) do
    from(token in UserToken,
      where: token.context == "session",
      where: ^scope_condition(scope),
      join: user in User,
      on: token.user_uuid == user.uuid,
      select: %{
        token_uuid: token.uuid,
        token_preview: fragment("encode(substring(?, 1, 4), 'hex')", token.token),
        user_uuid: user.uuid,
        user_email: user.email,
        user_is_active: user.is_active,
        user_confirmed_at: user.confirmed_at,
        browser: token.browser,
        os: token.os,
        created_at: token.inserted_at,
        expires_at: fragment("? + interval '60 days'", token.inserted_at)
      },
      order_by: [desc: token.inserted_at]
    )
    |> Repo.all()
    |> Enum.map(&format_session_info/1)
  end

  @doc """
  Lists all active sessions for a specific user.

  ## Examples

      iex> list_user_sessions(%User{uuid: "019b5704-..."})
      [%{token_uuid: "019b5704-...", user: %User{}, created_at: ~N[...], ...}]

  """
  def list_user_sessions(%User{uuid: user_uuid}) do
    from(token in UserToken,
      where: token.context == "session",
      where: token.user_uuid == ^user_uuid,
      where: token.inserted_at > ago(@session_validity_in_days, "day"),
      join: user in User,
      on: token.user_uuid == user.uuid,
      select: %{
        token_uuid: token.uuid,
        token_preview: fragment("encode(substring(?, 1, 4), 'hex')", token.token),
        user_uuid: user.uuid,
        user_email: user.email,
        user_is_active: user.is_active,
        user_confirmed_at: user.confirmed_at,
        browser: token.browser,
        os: token.os,
        created_at: token.inserted_at,
        expires_at: fragment("? + interval '60 days'", token.inserted_at)
      },
      order_by: [desc: token.inserted_at]
    )
    |> Repo.all()
    |> Enum.map(&format_session_info/1)
  end

  @doc """
  Lists a user's active sessions enriched with device info, for the
  self-service "Active Sessions" UI.

  Each session's `(ip_address, user_agent_hash)` is matched against the
  user's `KnownDevice` history to recover browser/OS/location/last-active
  (session tokens store only the hashed UA, never the raw string). Sessions
  predating fingerprinting — or from a device never recorded as "known" —
  degrade gracefully to an "Unknown device" with nil fields.

  `current_token` is the raw session token of the browser making the
  request (from the session's `"user_token"`); the matching row is flagged
  `is_current: true` so the UI can mark it and omit its "Sign out" button.
  """
  def list_user_device_sessions(%User{uuid: user_uuid}, current_token) do
    known = known_devices_by_fingerprint(user_uuid)
    current_uuid = current_session_uuid(user_uuid, current_token)

    from(token in UserToken,
      where: token.context == "session",
      where: token.user_uuid == ^user_uuid,
      where: token.inserted_at > ago(@session_validity_in_days, "day"),
      select: %{
        token_uuid: token.uuid,
        ip_address: token.ip_address,
        user_agent_hash: token.user_agent_hash,
        browser: token.browser,
        os: token.os,
        created_at: token.inserted_at
      },
      order_by: [desc: token.inserted_at]
    )
    |> Repo.all()
    |> Enum.map(fn s ->
      device = Map.get(known, {s.ip_address, s.user_agent_hash})

      %{
        token_uuid: s.token_uuid,
        ip_address: s.ip_address,
        # Device name comes from the token (V148), populated at login for every
        # session; fall back to a known-device row for pre-V148 sessions.
        browser: s.browser || (device && device.browser),
        os: s.os || (device && device.os),
        # Location stays known-device-only (recorded when new-login alerts run).
        location: device && device.location,
        last_active: (device && device.last_seen_at) || s.created_at,
        created_at: s.created_at,
        is_current: s.token_uuid == current_uuid
      }
    end)
  end

  @doc """
  Revokes one of a user's *own* sessions by token uuid.

  Scoped to `user` so a user can never revoke another user's session by
  guessing a token uuid. Returns `:ok` or `{:error, :not_found}`.
  """
  def revoke_user_session(%User{uuid: user_uuid}, token_uuid) when is_binary(token_uuid) do
    case Repo.delete_all(
           from(t in UserToken,
             where: t.uuid == ^token_uuid and t.user_uuid == ^user_uuid and t.context == "session"
           )
         ) do
      {1, _} ->
        Events.broadcast_session_revoked(token_uuid)
        :ok

      {0, _} ->
        {:error, :not_found}
    end
  end

  @doc """
  Revokes all of a user's sessions except the one identified by
  `current_token` (kept so the acting browser stays signed in). Returns the
  number revoked. With a nil token, revokes every session for the user.
  """
  def revoke_other_user_sessions(%User{} = user, nil), do: revoke_user_sessions(user)

  def revoke_other_user_sessions(%User{uuid: user_uuid}, current_token)
      when is_binary(current_token) do
    {count, _} =
      Repo.delete_all(
        from(t in UserToken,
          where:
            t.user_uuid == ^user_uuid and t.context == "session" and t.token != ^current_token
        )
      )

    if count > 0, do: Events.broadcast_user_sessions_revoked(user_uuid, count)
    count
  end

  @doc """
  Gets detailed information about a specific session by token ID.

  ## Examples

      iex> get_session_info("019b5704-3680-7b95-...")
      %{token_uuid: "019b5704-...", user: %User{}, created_at: ~N[...], ...}

      iex> get_session_info("019b5704-0000-0000-...")
      nil

  """
  def get_session_info(token_uuid) when is_binary(token_uuid) do
    from(token in UserToken,
      where: token.uuid == ^token_uuid,
      where: token.context == "session",
      where: token.inserted_at > ago(@session_validity_in_days, "day"),
      join: user in User,
      on: token.user_uuid == user.uuid,
      select: %{
        token_uuid: token.uuid,
        token_preview: fragment("encode(substring(?, 1, 4), 'hex')", token.token),
        user_uuid: user.uuid,
        user_email: user.email,
        user_is_active: user.is_active,
        user_confirmed_at: user.confirmed_at,
        created_at: token.inserted_at,
        expires_at: fragment("? + interval '60 days'", token.inserted_at)
      }
    )
    |> Repo.one()
    |> case do
      nil -> nil
      session_data -> format_session_info(session_data)
    end
  end

  @doc """
  Revokes a specific session by token ID.

  Returns :ok if successful, {:error, :not_found} if session doesn't exist.

  ## Examples

      iex> revoke_session("019b5704-3680-7b95-...")
      :ok

      iex> revoke_session("019b5704-0000-0000-...")
      {:error, :not_found}

  """
  def revoke_session(token_uuid) when is_binary(token_uuid) do
    case Repo.delete_all(
           from(token in UserToken,
             where: token.uuid == ^token_uuid and token.context == "session"
           )
         ) do
      {1, _} ->
        # Broadcast session revocation event
        Events.broadcast_session_revoked(token_uuid)
        :ok

      {0, _} ->
        {:error, :not_found}
    end
  end

  @doc """
  Revokes all sessions for a specific user.

  Returns the number of sessions revoked.

  ## Examples

      iex> revoke_user_sessions(%User{uuid: "019b5704-..."})
      3

  """
  def revoke_user_sessions(%User{uuid: user_uuid}) do
    {count, _} =
      Repo.delete_all(
        from(token in UserToken,
          where: token.user_uuid == ^user_uuid and token.context == "session"
        )
      )

    # Broadcast user sessions revocation event
    if count > 0 do
      Events.broadcast_user_sessions_revoked(user_uuid, count)
    end

    count
  end

  @doc """
  Counts the total number of active sessions.

  ## Examples

      iex> count_active_sessions()
      15

  """
  def count_active_sessions do
    from(token in UserToken,
      where: token.context == "session",
      where: token.inserted_at > ago(@session_validity_in_days, "day"),
      select: count(token.uuid)
    )
    |> Repo.one()
  end

  # The three scopes the admin dashboard counts, so each card can link to the
  # list behind its own number. `:active` is the historical behaviour and the
  # default, and the predicates are the same expressions `get_session_stats/0`
  # counts with — a report that disagreed with the card above it would be worse
  # than no link.
  defp scope_condition(:active),
    do: dynamic([token], token.inserted_at > ago(@session_validity_in_days, "day"))

  defp scope_condition(:expired),
    do: dynamic([token], token.inserted_at <= ago(@session_validity_in_days, "day"))

  defp scope_condition(:today) do
    today_start = today_start()
    dynamic([token], token.inserted_at >= ^today_start)
  end

  defp scope_condition(_other), do: scope_condition(:active)

  # "Today" is the OPERATOR's day, not UTC's. Counting from UTC midnight is
  # invisible for most of the day and then wrong every evening: on
  # Europe/Tallinn (UTC+3) every sign-in between 21:00 and midnight local falls
  # into "yesterday", so a dashboard read at night shows 0 while someone is
  # signed in — which is exactly how this was found.
  defp today_start do
    "time_zone"
    |> Settings.get_setting_cached("0")
    |> TimeZone.day_start()
  end

  @doc """
  Gets session statistics including total, unique users, expired sessions etc.

  ## Examples

      iex> get_session_stats()
      %{
        total_active: 15,
        unique_users: 8,
        expired_sessions: 5,
        sessions_today: 3
      }

  """
  def get_session_stats do
    today_start = today_start()

    # Active sessions
    active_query =
      from(token in UserToken,
        where: token.context == "session",
        where: token.inserted_at > ago(@session_validity_in_days, "day")
      )

    total_active = Repo.aggregate(active_query, :count, :uuid)

    # NOT `Repo.aggregate(active_query, :count, :user_uuid, distinct: true)`.
    # `aggregate/4`'s last argument is REPO options (`:prefix`, `:timeout`, …),
    # never query modifiers — `Ecto.Repo.Queryable.query_for_aggregate/3` builds
    # the select from the field alone and never sees them. So `distinct: true`
    # was accepted and silently ignored, and this counted ROWS: every panel
    # reported "unique users" exactly equal to "active sessions". Reported from
    # a live install showing 29 unique users against 2 registered accounts.
    unique_users =
      active_query
      |> select([token], count(token.user_uuid, :distinct))
      |> Repo.one()

    # Sessions created today
    sessions_today =
      from(token in UserToken,
        where: token.context == "session",
        where: token.inserted_at >= ^today_start,
        select: count(token.uuid)
      )
      |> Repo.one()

    # Expired sessions (for cleanup reference)
    expired_sessions =
      from(token in UserToken,
        where: token.context == "session",
        where: token.inserted_at <= ago(@session_validity_in_days, "day"),
        select: count(token.uuid)
      )
      |> Repo.one()

    %{
      total_active: total_active,
      unique_users: unique_users,
      expired_sessions: expired_sessions,
      sessions_today: sessions_today,
      by_os: active_breakdown(active_query, :os),
      by_browser: active_breakdown(active_query, :browser)
    }
  end

  # `[{name, count}, ...]` for active sessions grouped by a token field
  # (`:os` / `:browser`), most common first. Nil names (pre-V148 sessions
  # or missing UA) collapse into "Unknown".
  defp active_breakdown(active_query, field) do
    from(t in active_query,
      group_by: field(t, ^field),
      select: {field(t, ^field), count(t.uuid)},
      order_by: [desc: count(t.uuid)]
    )
    |> Repo.all()
    |> Enum.map(fn {name, count} -> {name || "Unknown", count} end)
  end

  # Loads the user's known devices keyed by {ip_address, user_agent_hash}
  # for O(1) enrichment of each session row.
  #
  # Degrades to no enrichment (empty map) if the known-devices table isn't
  # present yet — a parent app can deploy code carrying this feature before
  # running the V143/V147 migrations, and the sessions list (built from the
  # tokens table) must still render rather than crash the settings page.
  defp known_devices_by_fingerprint(user_uuid) do
    from(d in KnownDevice, where: d.user_uuid == ^user_uuid)
    |> Repo.all()
    |> Map.new(fn d -> {{d.ip_address, d.user_agent_hash}, d} end)
  rescue
    error in [Postgrex.Error, DBConnection.ConnectionError] ->
      Logger.warning(
        "[PhoenixKit.Sessions] known-device enrichment skipped " <>
          "(run PhoenixKit migrations to V147?): #{inspect(error)}"
      )

      %{}
  end

  # Resolves the token uuid of the acting session (session tokens are stored
  # raw, so a direct byte match is correct). Nil token / no match → nil.
  defp current_session_uuid(_user_uuid, nil), do: nil

  defp current_session_uuid(user_uuid, token) when is_binary(token) do
    from(t in UserToken,
      where: t.context == "session" and t.user_uuid == ^user_uuid and t.token == ^token,
      select: t.uuid
    )
    |> Repo.one()
  end

  # Private helper to format session information
  defp format_session_info(session_data) do
    %{
      token_uuid: session_data.token_uuid,
      token_preview: session_data.token_preview,
      user_uuid: session_data.user_uuid,
      user_email: session_data.user_email,
      user_is_active: session_data.user_is_active,
      user_confirmed_at: session_data.user_confirmed_at,
      browser: Map.get(session_data, :browser),
      os: Map.get(session_data, :os),
      created_at: session_data.created_at,
      expires_at: session_data.expires_at,
      age_in_days: calculate_age_in_days(session_data.created_at),
      is_expired: session_expired?(session_data.created_at)
    }
  end

  defp calculate_age_in_days(created_at) do
    DateTime.diff(UtilsDate.utc_now(), created_at, :day)
  end

  defp session_expired?(created_at) do
    DateTime.diff(UtilsDate.utc_now(), created_at, :day) >= @session_validity_in_days
  end
end
