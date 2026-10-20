defmodule PhoenixKit.API.Idempotency do
  @moduledoc """
  Idempotent writes for the machine API: a client that retries a request with
  the same `Idempotency-Key` gets the first answer back, and never a second write.

  `claim/4` is called before the handler runs. Its answers:

    * `{:claimed, claim}` - this request runs. Afterwards call `store/2` with the JSON
      body of the answer, but only when `storable?/1` says it may be kept; otherwise
      call `release/1`.
    * `{:replay, body}` - the same request already finished; send `body` again.
    * `{:error, :in_progress}` - the same request is running (its lease is alive).
    * `{:error, :reused}` - the key was used for a different request.

  A claim is a row of `phoenix_kit_api_idempotency` keyed by `(scope_ref, key)`;
  `scope_ref` is the API key's uuid for admin calls and the client-token hash for public
  calls whose tool declares a client token. The insert is `ON CONFLICT DO NOTHING`, so two
  first requests cannot both win. A request that crashed or timed out leaves an `in_progress` row; once its lease
  (`api_idempotency_lease_seconds`) has run out a retry of the same request takes the row
  over. A request that committed and died before `store/2` runs again after a takeover,
  so module authors should also give their writes a natural key of their own (an
  `external_ref`, say) where a repeated write would do harm.

  A claim is the pair `{uuid, locked_at}`. Every later write compares `locked_at`, so a
  run that lost its claim to a takeover can neither store nor delete anything.

  ## What is stored

  Only a `200` body that is at most 1 MB and carries no credential (`storable?/1`).
  Previews, confirmation prompts, pending approvals and errors are not stored: the caller
  releases the claim, so the confirming or the corrected call may reuse the key. A body
  is credential-bearing when any object key, at any depth, names a credential
  (`PhoenixKit.API.Auth.credential_name?/1`: `token`, `secret`, `api_key`, `authorization`,
  `bearer`, or any name ending in `_token`, compared without regard to case), or is one of
  the output fields the tool declares (`PhoenixKit.API.Tool.credential_keys/1`: its
  `credentials` and its `client_token`), or any string value starts with `pk_`.
  `PhoenixKit.API.Legacy` adds the keys `claim_url` and `checkout_url` and the value
  marker `/checkout/claim/` for modules that predate `Tool.credentials`.
  Module authors: name a field that carries a secret `*_token`, or list it in the tool's
  `credentials`, or the answer is not safe to replay. The check is deliberately broad, so
  it has false positives: an echoed SKU or title that starts with `pk_`, or a field named
  `token` or `secret`, makes the answer unstorable, and the retry of that write then runs
  the handler again. Keep such values out of write answers. `token_count` or `tokens_issued`
  are not credentials; `session-token` (a hyphen) is not either.
  """

  import Ecto.Query

  alias PhoenixKit.API.Auth
  alias PhoenixKit.API.FlowConfig
  alias PhoenixKit.API.Idempotency.Record
  alias PhoenixKit.API.Legacy
  alias PhoenixKit.RepoHelper

  @max_body_bytes 1_048_576
  @max_attempts 3

  @type claim :: %{uuid: String.t(), locked_at: DateTime.t()}

  @doc """
  Claims `key` for the request `request_hash` in `scope_ref`. `now` is a parameter so
  tests move the clock; any precision is accepted.
  """
  @spec claim(String.t(), String.t(), String.t(), DateTime.t()) ::
          {:claimed, claim()} | {:replay, String.t()} | {:error, :in_progress | :reused}
  def claim(scope_ref, key, request_hash, now \\ DateTime.utc_now())
      when is_binary(scope_ref) and is_binary(key) and is_binary(request_hash) do
    # locked_at is utc_datetime_usec: a clock with another precision cannot be dumped.
    do_claim(scope_ref, key, request_hash, DateTime.add(now, 0, :microsecond), 1)
  end

  defp do_claim(scope_ref, key, request_hash, now, attempt) do
    uuid = UUIDv7.generate()

    row = %{
      uuid: uuid,
      scope_ref: scope_ref,
      key: key,
      request_hash: request_hash,
      state: "in_progress",
      locked_at: now,
      expires_at: expires_at(now),
      inserted_at: DateTime.truncate(now, :second)
    }

    case repo().insert_all(Record, [row],
           on_conflict: :nothing,
           conflict_target: [:scope_ref, :key]
         ) do
      {1, _} -> {:claimed, %{uuid: uuid, locked_at: now}}
      {0, _} -> resolve(scope_ref, key, request_hash, now, attempt)
    end
  end

  # The row exists. (It can also have been pruned between the conflict and this read:
  # try the insert again, a few times. If it is still missing after the last try the
  # answer is in_progress: the caller retries later, and nothing is run twice.)
  defp resolve(scope_ref, key, request_hash, now, attempt) do
    case repo().get_by(Record, scope_ref: scope_ref, key: key) do
      nil when attempt < @max_attempts -> do_claim(scope_ref, key, request_hash, now, attempt + 1)
      nil -> {:error, :in_progress}
      %Record{} = record -> decide(record, request_hash, now)
    end
  end

  defp decide(%Record{} = record, request_hash, now) do
    cond do
      DateTime.compare(record.expires_at, now) != :gt -> take_over(record, request_hash, now)
      record.request_hash != request_hash -> {:error, :reused}
      record.state == "done" -> {:replay, record.response}
      lease_alive?(record, now) -> {:error, :in_progress}
      true -> take_over(record, request_hash, now)
    end
  end

  defp lease_alive?(%Record{locked_at: locked_at}, now) do
    locked_at
    |> DateTime.add(FlowConfig.idempotency_lease_seconds(), :second)
    |> DateTime.compare(now) == :gt
  end

  # One compare-and-set: only the process that still sees the row as it read it wins.
  defp take_over(%Record{} = record, request_hash, now) do
    query =
      from(r in Record,
        where:
          r.uuid == ^record.uuid and r.locked_at == ^record.locked_at and r.state == ^record.state
      )

    changes = [
      request_hash: request_hash,
      state: "in_progress",
      locked_at: now,
      response: nil,
      expires_at: expires_at(now)
    ]

    case repo().update_all(query, set: changes) do
      {1, _} -> {:claimed, %{uuid: record.uuid, locked_at: now}}
      {0, _} -> {:error, :in_progress}
    end
  end

  @doc """
  Stores the answer of a finished request. `:lost` when the claim was taken over (or
  deleted) meanwhile: the newer run owns the row.

  The body is written as given. The caller must check `storable?/1` first and call
  `release/1` instead when it is false: a client token or a claim URL stored here would
  sit in the table in plain text.
  """
  @spec store(claim(), String.t()) :: :ok | :lost
  def store(%{uuid: uuid, locked_at: locked_at}, body) when is_binary(body) do
    query =
      from(r in Record,
        where: r.uuid == ^uuid and r.locked_at == ^locked_at and r.state == "in_progress"
      )

    case repo().update_all(query, set: [state: "done", response: body]) do
      {1, _} -> :ok
      {0, _} -> :lost
    end
  end

  @doc "Gives a claim up: deletes the row if it is still this claim and still running."
  @spec release(claim()) :: :ok
  def release(%{uuid: uuid, locked_at: locked_at}) do
    repo().delete_all(
      from(r in Record,
        where: r.uuid == ^uuid and r.locked_at == ^locked_at and r.state == "in_progress"
      )
    )

    :ok
  end

  @doc """
  Whether an answer may be stored: at most 1 MB, valid JSON, no credential. `keys` are the
  tool's own credential fields (`PhoenixKit.API.Tool.credential_keys/1`).
  """
  @spec storable?(String.t(), [String.t()]) :: boolean()
  def storable?(body, keys \\ []) when is_binary(body) do
    byte_size(body) <= @max_body_bytes and not credential_bearing?(body, keys)
  end

  @doc """
  Whether a JSON body carries a credential (see the moduledoc); `keys` are the tool's own
  credential fields. A body that is not JSON counts as carrying one: it is not stored.
  """
  @spec credential_bearing?(String.t(), [String.t()]) :: boolean()
  def credential_bearing?(body, keys \\ []) when is_binary(body) do
    case JSON.decode(body) do
      {:ok, decoded} -> walk(decoded, key_set(keys))
      {:error, _reason} -> true
    end
  end

  @doc """
  Redacts credentials in JSON-compatible data using the same rules as replay storage;
  `keys` are the tool's own credential fields.
  Approval results and progress must pass through this before they are persisted.
  """
  @spec redact_credentials(term(), [String.t()]) :: term()
  def redact_credentials(data, keys \\ []), do: redact(data, key_set(keys))

  defp redact(map, keys) when is_map(map) do
    Map.new(map, fn {key, value} ->
      {key, if(credential_key?(key, keys), do: "[REDACTED]", else: redact(value, keys))}
    end)
  end

  defp redact(list, keys) when is_list(list), do: Enum.map(list, &redact(&1, keys))

  defp redact(value, keys) when is_binary(value),
    do: if(walk(value, keys), do: "[REDACTED]", else: value)

  defp redact(value, _keys), do: value

  defp walk(map, keys) when is_map(map) do
    Enum.any?(map, fn {key, value} -> credential_key?(key, keys) or walk(value, keys) end)
  end

  defp walk(list, keys) when is_list(list), do: Enum.any?(list, &walk(&1, keys))

  defp walk(value, _keys) when is_binary(value) do
    lowered = String.downcase(value)

    String.starts_with?(value, "pk_") or
      Enum.any?(Legacy.credential_markers(), &String.contains?(lowered, &1))
  end

  defp walk(_other, _keys), do: false

  defp credential_key?(key, keys) when is_binary(key),
    do: Auth.credential_name?(key) or String.downcase(key) in keys

  defp credential_key?(_key, _keys), do: false

  # The names that are credentials besides core's rule: the tool's own and the legacy ones.
  defp key_set(keys), do: Legacy.credential_keys() ++ Enum.map(keys, &String.downcase/1)

  @doc "Deletes the rows that have expired. Returns how many."
  @spec prune(DateTime.t()) :: non_neg_integer()
  def prune(now \\ DateTime.utc_now()) do
    now = DateTime.truncate(now, :second)
    {count, _} = repo().delete_all(from(r in Record, where: r.expires_at <= ^now))
    count
  end

  defp expires_at(now) do
    now
    |> DateTime.add(FlowConfig.idempotency_ttl_hours() * 3600, :second)
    |> DateTime.truncate(:second)
  end

  defp repo, do: RepoHelper.repo()
end
