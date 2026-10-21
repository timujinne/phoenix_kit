defmodule PhoenixKit.API.Confirm do
  @moduledoc """
  Confirmation codes of dangerous API operations, and the helpers the approval queue
  shares.

  A dangerous call without a code changes nothing and returns a preview plus a code
  (`issue_token/6`). Repeating the call with the same arguments and the code runs it.
  The code is valid only when all of these hold:

    * its row is `unused` and has not expired;
    * it was issued to the same actor (an API key, or a client-token hash for a public
      tool);
    * it was issued for the same tool and the same arguments (`input_hash`, a hash of
      the arguments without the control fields);
    * the `fingerprint` (a hash of the *current values* the operation touches) is
      still the one in the row.

  `lookup_token/5` checks the cheap parts and changes nothing. `claim_token/3` is the
  atomic part: one `UPDATE` that sets `used` only if the row is still `unused`, not
  expired, and its fingerprint equals the fresh one the caller computed by running the
  handler as a dry run. Exactly one caller can win, so two simultaneous confirmations
  run the operation once; the loser sees `{:error, :used}`. A batch that then fails
  part-way keeps its code spent.

  `live_actor/1` rebuilds an actor from a key row without a token, for the approval
  queue. `expire_due/1`, `sweep_stuck/2` and `prune/1` are the maintenance functions
  the cron workers call.
  """

  import Ecto.Query, warn: false

  alias PhoenixKit.Activity
  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Approvals
  alias PhoenixKit.API.Confirm.Confirmation
  alias PhoenixKit.API.Confirm.Token
  alias PhoenixKit.API.FlowConfig
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Keys.Key
  alias PhoenixKit.RepoHelper

  @doc """
  Issues a code for `actor`, `tool_name` and `input_hash`, holding `preview` and
  `fingerprint`. The row lives `api_confirm_ttl_seconds`.

  A key that repeats the very same call (same tool, arguments and current values) while
  its earlier code is still unused and unexpired gets **that** code again, with the time
  it has left: an agent that polls a dangerous call does not pile up rows. A public actor
  is bound to a client token it chose itself, so nothing is shared between two of its calls;
  what keeps that table small is the early prune of never-used codes (`prune/1`) and the
  rate limit of the public API.
  """
  @spec issue_token(Actor.t(), String.t(), String.t(), map(), String.t(), DateTime.t()) ::
          {:ok,
           %{token: String.t(), row: Confirmation.t(), expires_in_seconds: non_neg_integer()}}
          | {:error, :no_secret | :no_binding | Ecto.Changeset.t()}
  def issue_token(
        %Actor{} = actor,
        tool_name,
        input_hash,
        preview,
        fingerprint,
        now \\ DateTime.utc_now()
      ) do
    now = second(now)

    with {:ok, owner} <- bind_to(actor) do
      case live_code(owner, tool_name, input_hash, fingerprint, now) do
        %Confirmation{} = row -> hand_out_again(row, now)
        nil -> insert_code(owner, tool_name, input_hash, preview, fingerprint, now)
      end
    end
  end

  defp insert_code(owner, tool_name, input_hash, preview, fingerprint, now) do
    uuid = UUIDv7.generate()
    ttl = FlowConfig.confirm_ttl_seconds()

    with {:ok, token} <- Token.sign(uuid),
         {:ok, row} <-
           %Confirmation{uuid: uuid}
           |> Confirmation.changeset(
             Map.merge(owner, %{
               kind: "token",
               tool: tool_name,
               input_hash: input_hash,
               fingerprint: fingerprint,
               preview: preview,
               status: "unused",
               expires_at: DateTime.add(now, ttl, :second)
             })
           )
           |> repo().insert() do
      {:ok, %{token: token, row: row, expires_in_seconds: ttl}}
    end
  end

  # The unused, unexpired code this key already holds for the same call and values. Only a
  # key is looked up (index `actor_key_uuid, status`); the client-token binding of a public
  # actor has no index, and the actor is self-chosen anyway.
  defp live_code(%{actor_key_uuid: key_uuid}, tool_name, input_hash, fingerprint, now) do
    repo().one(
      from(c in Confirmation,
        where:
          c.actor_key_uuid == ^key_uuid and c.status == "unused" and c.kind == "token" and
            c.tool == ^tool_name and
            c.input_hash == ^input_hash and c.fingerprint == ^fingerprint and c.expires_at > ^now,
        order_by: [desc: c.expires_at],
        limit: 1
      )
    )
  end

  defp live_code(_client_token_binding, _tool_name, _input_hash, _fingerprint, _now), do: nil

  defp hand_out_again(%Confirmation{} = row, now) do
    with {:ok, token} <- Token.sign(row.uuid) do
      {:ok,
       %{token: token, row: row, expires_in_seconds: max(DateTime.diff(row.expires_at, now), 0)}}
    end
  end

  defp bind_to(%Actor{kind: :key, key_uuid: uuid}) when is_binary(uuid),
    do: {:ok, %{actor_key_uuid: uuid}}

  defp bind_to(%Actor{client_token_hash: hash}) when is_binary(hash),
    do: {:ok, %{client_token_hash: hash}}

  defp bind_to(_actor), do: {:error, :no_binding}

  @doc """
  The cheap checks of a presented code. Changes nothing. `{:ok, row}` or the first
  reason it is refused.
  """
  @spec lookup_token(String.t(), Actor.t(), String.t(), String.t(), DateTime.t()) ::
          {:ok, Confirmation.t()}
          | {:error, :malformed | :unknown | :wrong_binding | :wrong_input | :used | :expired}
  def lookup_token(token, %Actor{} = actor, tool_name, input_hash, now \\ DateTime.utc_now()) do
    now = second(now)

    with {:ok, uuid} <- verify(token),
         {:ok, row} <- fetch_code(uuid),
         :ok <- bound_to(row, actor),
         :ok <- same_call(row, tool_name, input_hash),
         :ok <- usable(row, now) do
      {:ok, row}
    end
  end

  defp verify(token) do
    case Token.verify(token) do
      {:ok, uuid} -> {:ok, uuid}
      :error -> {:error, :malformed}
    end
  end

  defp fetch_code(uuid) do
    case repo().get(Confirmation, uuid) do
      %Confirmation{kind: "token"} = row -> {:ok, row}
      _none_or_approval -> {:error, :unknown}
    end
  end

  defp bound_to(%Confirmation{actor_key_uuid: key}, %Actor{kind: :key, key_uuid: key})
       when is_binary(key),
       do: :ok

  defp bound_to(%Confirmation{client_token_hash: hash}, %Actor{client_token_hash: hash})
       when is_binary(hash),
       do: :ok

  defp bound_to(_row, _actor), do: {:error, :wrong_binding}

  defp same_call(%Confirmation{tool: tool, input_hash: hash}, tool, hash), do: :ok
  defp same_call(_row, _tool_name, _input_hash), do: {:error, :wrong_input}

  defp usable(%Confirmation{status: "used"}, _now), do: {:error, :used}
  defp usable(%Confirmation{status: status}, _now) when status != "unused", do: {:error, :expired}

  defp usable(%Confirmation{expires_at: expires_at}, now) do
    if DateTime.compare(expires_at, now) == :gt, do: :ok, else: {:error, :expired}
  end

  @doc """
  Spends a code, atomically. `fresh_fingerprint` is the fingerprint of the values the
  operation touches *now*. `:ok` for exactly one caller; `{:error, :used}`,
  `{:error, :expired}` or `{:error, :changed}` for the others.
  """
  @spec claim_token(Confirmation.t(), String.t(), DateTime.t()) ::
          :ok | {:error, :used | :expired | :changed}
  def claim_token(%Confirmation{uuid: uuid}, fresh_fingerprint, now \\ DateTime.utc_now()) do
    now = second(now)

    query =
      from(c in Confirmation,
        where:
          c.uuid == ^uuid and c.kind == "token" and c.status == "unused" and c.expires_at > ^now and
            c.fingerprint == ^fresh_fingerprint
      )

    case repo().update_all(query, set: [status: "used", used_at: now, updated_at: now]) do
      {1, _} -> :ok
      {0, _} -> {:error, why_not_claimed(uuid, now)}
    end
  end

  defp why_not_claimed(uuid, now) do
    case repo().get(Confirmation, uuid) do
      %Confirmation{status: "used"} ->
        :used

      %Confirmation{status: "unused", expires_at: expires_at} ->
        if DateTime.compare(expires_at, now) == :gt, do: :changed, else: :expired

      _expired_or_gone ->
        :expired
    end
  end

  @doc """
  The actor of an API key as it stands **now**, without a token: the key is read from
  the database (not the cache), must not be revoked or expired (`Keys.dead_reason/1`), and
  its owner must be active; `scopes` are the key's scopes filtered by the owner's live
  permissions. This is the request-path check of the executor, for code that has no
  request.
  """
  @spec live_actor(String.t()) ::
          {:ok, Actor.t()} | {:error, :not_found | :revoked | :expired | :owner_inactive}
  def live_actor(key_uuid) do
    with %Key{} = key <- Keys.get_key(key_uuid) || {:error, :not_found},
         :ok <- alive(key),
         {:ok, owner} <- Keys.active_owner(key) do
      {:ok, Keys.actor(key, owner, nil)}
    end
  end

  defp alive(%Key{} = key) do
    case Keys.dead_reason(key) do
      nil -> :ok
      reason -> {:error, reason}
    end
  end

  # --- maintenance (the cron workers) ---------------------------------------------------

  @stuck_after_seconds 900
  @retention_days 30
  @unused_code_retention_seconds 3_600
  @interrupted "The process that was running this operation stopped before it finished. Part of it may have been applied: check the data."

  @doc """
  Marks the pending approvals and the unused codes whose `expires_at` has passed as
  `expired` (an approval's input is cleared). Returns how many of each.
  """
  @spec expire_due(DateTime.t()) :: %{approvals: non_neg_integer(), tokens: non_neg_integer()}
  def expire_due(now \\ DateTime.utc_now()) do
    now = second(now)

    {approvals, _} =
      repo().update_all(
        from(c in Confirmation,
          where: c.kind == "approval" and c.status == "pending" and c.expires_at <= ^now
        ),
        set: [status: "expired", input: nil, updated_at: now]
      )

    {tokens, _} =
      repo().update_all(
        from(c in Confirmation,
          where: c.kind == "token" and c.status == "unused" and c.expires_at <= ^now
        ),
        set: [status: "expired", updated_at: now]
      )

    if approvals > 0, do: Approvals.broadcast(:expired)
    %{approvals: approvals, tokens: tokens}
  end

  @doc """
  Fails every approval that is still `approved` or `executing` although nothing has
  touched it for `stale_after_seconds` (default 15 minutes): the process that was running
  it died. The error `interrupted` is added to whatever partial results it had reported,
  its input is cleared, and the outcome is logged and announced. Returns how many.
  """
  @spec sweep_stuck(DateTime.t(), pos_integer()) :: non_neg_integer()
  def sweep_stuck(now \\ DateTime.utc_now(), stale_after_seconds \\ @stuck_after_seconds) do
    now = second(now)
    cutoff = DateTime.add(now, -stale_after_seconds, :second)
    error = %{"code" => "interrupted", "detail" => @interrupted, "context" => %{}}

    stuck =
      repo().all(
        from(c in Confirmation,
          where:
            c.kind == "approval" and c.status in ["approved", "executing"] and
              c.updated_at < ^cutoff
        )
      )

    # Row by row: a row that moved on since it was read (its updated_at changed) is skipped.
    swept =
      Enum.filter(stuck, fn row ->
        query =
          from(c in Confirmation,
            where:
              c.uuid == ^row.uuid and c.status in ["approved", "executing"] and
                c.updated_at < ^cutoff
          )

        changes = [
          status: "failed",
          input: nil,
          result: Map.put(row.result || %{}, "error", error),
          updated_at: now
        ]

        match?({1, _}, repo().update_all(query, set: changes))
      end)

    Enum.each(swept, &announce_swept/1)
    length(swept)
  end

  defp announce_swept(%Confirmation{} = row) do
    Activity.log("api", "api.approval_finished",
      mode: "auto",
      resource_type: "api_approval",
      resource_uuid: row.uuid,
      metadata: %{"status" => "failed", "tool" => row.tool, "error_code" => "interrupted"}
    )

    Approvals.broadcast(row.uuid)
  end

  @doc """
  Deletes the rows nobody needs any more. Returns how many rows went.

    * a code that was **never used** (still `unused`, or marked `expired`) one hour after it
      ran out: every dangerous call without a code inserts one, and a public client can ask
      for many, so these must not stay for a month;
    * a code that **was used** 30 days after it ran out (it is the trace of what was confirmed);
    * an approval 30 days after its last change, once decided, executed, failed, found stale
      or expired. A pending, approved or executing approval is never deleted.
  """
  @spec prune(DateTime.t()) :: non_neg_integer()
  def prune(now \\ DateTime.utc_now()) do
    cutoff = now |> second() |> DateTime.add(-@retention_days * 86_400, :second)
    live = ["pending", "approved", "executing"]

    unused_cutoff = now |> second() |> DateTime.add(-@unused_code_retention_seconds, :second)

    {unused, _} =
      repo().delete_all(
        from(c in Confirmation,
          where:
            c.kind == "token" and c.status in ["unused", "expired"] and
              c.expires_at < ^unused_cutoff
        )
      )

    {used, _} =
      repo().delete_all(
        from(c in Confirmation, where: c.kind == "token" and c.expires_at < ^cutoff)
      )

    {approvals, _} =
      repo().delete_all(
        from(c in Confirmation,
          where: c.kind == "approval" and c.status not in ^live and c.updated_at < ^cutoff
        )
      )

    unused + used + approvals
  end

  defp second(%DateTime{} = time), do: DateTime.truncate(time, :second)

  defp repo, do: RepoHelper.repo()
end
