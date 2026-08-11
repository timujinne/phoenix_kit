defmodule PhoenixKit.Integrations.Events do
  @moduledoc """
  PubSub helpers for broadcasting integration changes in real-time.

  Lets the settings pages update live without a refresh. There are two topic
  scopes:

    * the global system topic `"phoenix_kit:integrations"` — system-wide
      connection changes (the website-wide page + consumers subscribe here);
    * a per-user topic `"phoenix_kit:integrations:<user_uuid>"` — a user's own
      personal connection changes (the personal page subscribes here).

  Each broadcaster routes by the connection's owner, so a personal change only
  reaches that user's page and a system change only reaches the system page.

  ## Events

  - `{:integration_setup_saved, provider_key, data}` — setup credentials saved
  - `{:integration_connected, provider_key, data}` — OAuth flow completed
  - `{:integration_disconnected, provider_key}` — disconnected
  - `{:integration_validated, provider_key, :ok | {:error, reason}}` — health check
  - `{:integration_connection_added | _removed, provider_key, name}`
  - `{:integration_connection_renamed, provider_key, old, new}`

  The `data` payload on setup_saved/connected is REDACTED — secret fields are
  stripped before broadcast so credentials never travel over PubSub (consumers
  reload from the owner-scoped context anyway).
  """

  alias PhoenixKit.PubSub.Manager

  @topic "phoenix_kit:integrations"
  @user_topic_prefix "phoenix_kit:integrations:"

  @typedoc "Owner scope for routing a broadcast (mirrors `t:PhoenixKit.Integrations.owner/0`)."
  @type owner :: :system | {atom(), String.t()}

  # Mirror of PhoenixKit.Integrations.Encryption's sensitive fields — stripped
  # from any broadcast payload so decrypted credentials never leave the context.
  # `oauth_state` is the CSRF nonce for an in-flight OAuth handshake — not a
  # stored credential, but still must never ride a broadcast.
  @sensitive_fields ~w(access_token refresh_token client_secret api_key bot_token secret_key password oauth_state)

  @doc "The per-user personal-integrations topic."
  @spec topic_for_user(String.t()) :: String.t()
  def topic_for_user(user_uuid) when is_binary(user_uuid), do: @user_topic_prefix <> user_uuid

  @doc "Subscribe to system-wide integration change events (the global topic)."
  @spec subscribe() :: :ok | {:error, term()}
  def subscribe, do: Manager.subscribe(@topic)

  @doc "Subscribe to a user's personal integration change events."
  @spec subscribe(String.t()) :: :ok | {:error, term()}
  def subscribe(user_uuid) when is_binary(user_uuid),
    do: Manager.subscribe(topic_for_user(user_uuid))

  @doc "Broadcast that an integration's setup credentials were saved. Routes + redacts by `data`'s owner."
  @spec broadcast_setup_saved(String.t(), map()) :: :ok
  def broadcast_setup_saved(provider_key, data) do
    broadcast(owner_of(data), {:integration_setup_saved, provider_key, redact(data)})
  end

  @doc "Broadcast that an OAuth integration was connected. Routes + redacts by `data`'s owner."
  @spec broadcast_connected(String.t(), map()) :: :ok
  def broadcast_connected(provider_key, data) do
    broadcast(owner_of(data), {:integration_connected, provider_key, redact(data)})
  end

  @doc "Broadcast that an integration was disconnected."
  @spec broadcast_disconnected(String.t(), owner()) :: :ok
  def broadcast_disconnected(provider_key, owner \\ :system) do
    broadcast(owner, {:integration_disconnected, provider_key})
  end

  @doc "Broadcast that an integration's health check completed."
  @spec broadcast_validated(String.t(), :ok | {:error, term()}, owner()) ::
          :ok
  def broadcast_validated(provider_key, status, owner \\ :system) do
    broadcast(owner, {:integration_validated, provider_key, status})
  end

  @doc "Broadcast that a new named connection was added for a provider."
  @spec broadcast_connection_added(String.t(), String.t(), owner()) :: :ok
  def broadcast_connection_added(provider_key, name, owner \\ :system) do
    broadcast(owner, {:integration_connection_added, provider_key, name})
  end

  @doc "Broadcast that a named connection was removed from a provider."
  @spec broadcast_connection_removed(String.t(), String.t(), owner()) :: :ok
  def broadcast_connection_removed(provider_key, name, owner \\ :system) do
    broadcast(owner, {:integration_connection_removed, provider_key, name})
  end

  @doc "Broadcast that a named connection was renamed."
  @spec broadcast_connection_renamed(
          String.t(),
          String.t(),
          String.t(),
          owner()
        ) :: :ok
  def broadcast_connection_renamed(provider_key, old_name, new_name, owner \\ :system) do
    broadcast(owner, {:integration_connection_renamed, provider_key, old_name, new_name})
  end

  # ── Internals ──────────────────────────────────────────────────────────

  # A row's owner from its (decrypted) JSONB: a valid-looking uuid ⇒ a typed
  # owner (`owner_type`, defaulting to `:user` for pre-typed rows), else system.
  # Kept local so Events has no dependency back into the context.
  defp owner_of(data) when is_map(data) do
    case Map.get(data, "owner_uuid") do
      uuid when is_binary(uuid) and uuid != "" -> {owner_type_atom(data), uuid}
      _ -> :system
    end
  end

  defp owner_of(_), do: :system

  defp owner_type_atom(data) do
    case Map.get(data, "owner_type") do
      type when is_binary(type) and type != "" ->
        try do
          String.to_existing_atom(type)
        rescue
          ArgumentError -> :__unknown_owner__
        end

      _ ->
        :user
    end
  end

  defp redact(data) when is_map(data), do: Map.drop(data, @sensitive_fields)
  defp redact(other), do: other

  # Route by owner. `:system` → global topic; a typed owner → its own topic
  # (`:user` keeps the bare `<prefix><uuid>` topic the personal page subscribes
  # to; other types get `<prefix><type>:<id>`). A malformed owner never crashes
  # a broadcast — it no-ops.
  defp broadcast(:system, message), do: do_broadcast(@topic, message)

  defp broadcast({type, id}, message) when is_atom(type) and is_binary(id),
    do: do_broadcast(topic_for_owner(type, id), message)

  defp broadcast(_owner, _message), do: :ok

  defp topic_for_owner(:user, id), do: topic_for_user(id)
  defp topic_for_owner(type, id), do: @user_topic_prefix <> Atom.to_string(type) <> ":" <> id

  defp do_broadcast(topic, message) do
    Manager.broadcast(topic, message)
  rescue
    _ -> :ok
  end
end
