defmodule PhoenixKit.Modules.Storage.Locations do
  @moduledoc """
  Where a stored object is: its `phoenix_kit_file_locations` rows (V204).

  An object is named by its key (`FileInstance.file_name`). Several
  instances may share one key (a cross-user copy, a tile written twice), and
  each instance has one location row per bucket that holds the object
  (`phoenix_kit_file_locations_instance_bucket_index`).

  `PhoenixKit.Modules.Storage.Manager` reads, serves and checks objects
  through this: the buckets the rows name come first, then the other
  enabled buckets, and when one of those turns out to hold the object, a row
  is recorded for it (`record/2`). That fallback is what keeps files stored
  before every writer recorded its locations working while
  `Storage.Workers.LocationBackfillJob` has not reached them yet.
  """

  import Ecto.Query

  require Logger

  alias PhoenixKit.Modules.Storage.File, as: StorageFile

  alias PhoenixKit.Modules.Storage.{
    FileInstance,
    FileLocation,
    Library,
    LocationCheck,
    ProfileBucket,
    Profiles
  }

  @doc "The uuids of the buckets the active location rows of `key` name."
  @spec bucket_uuids(String.t()) :: [String.t()]
  def bucket_uuids(key) when is_binary(key) do
    from(l in FileLocation,
      where: l.path == ^key and l.status == "active",
      distinct: true,
      select: l.bucket_uuid
    )
    |> repo().all()
    |> Enum.map(&to_string/1)
  rescue
    # A lookup must never stop a read: without it the manager tries every
    # bucket, as it did before V204.
    error ->
      Logger.warning("Storage: location lookup for #{key} failed: #{Exception.message(error)}")
      []
  end

  def bucket_uuids(_key), do: []

  # How a copy is ranked for serving (V205): primaries, then replicas, then
  # a copy on a bucket its profile no longer lists (the reconciler has not
  # moved it yet), then backups, which are never served.
  @role_rank %{"primary" => 0, "replica" => 1, nil => 2, "backup" => 3}

  @doc """
  The buckets the active location rows of `key` name, each with the role
  and serve order its file's storage profile gives it (V205), best first:
  primaries, then replicas, then buckets the profile no longer lists, then
  backups; each group by `serve_order`. `role` is nil for a bucket not in
  the profile. Never raises: a failed lookup is `[]`, as for `bucket_uuids/1`.
  """
  # With `file_uuid`, only that file's locations and its own profile count:
  # a key shared with a cross-user copy in another library must not have a
  # bucket that library marks `backup` served because the other one calls
  # it `primary`. Without it (a key read for processing), every file sharing
  # the key counts, each bucket at its best rank.
  @spec ranked(String.t(), term()) :: [%{bucket_uuid: String.t(), role: String.t() | nil}]
  def ranked(key, file_uuid \\ nil)

  def ranked(key, file_uuid) when is_binary(key) do
    default = Profiles.default_uuid()

    from(l in FileLocation,
      join: i in FileInstance,
      on: i.uuid == l.file_instance_uuid,
      join: f in StorageFile,
      on: f.uuid == i.file_uuid,
      left_join: lib in Library,
      on: lib.uuid == f.library_uuid,
      left_join: pb in ProfileBucket,
      on:
        pb.bucket_uuid == l.bucket_uuid and
          pb.profile_uuid == coalesce(lib.storage_profile_uuid, type(^default, UUIDv7)),
      where: l.path == ^key and l.status == "active",
      select: {l.bucket_uuid, pb.role, pb.serve_order}
    )
    |> only_file(file_uuid)
    |> repo().all()
    |> rank()
  rescue
    error ->
      Logger.warning("Storage: location lookup for #{key} failed: #{Exception.message(error)}")
      []
  end

  def ranked(_key, _file_uuid), do: []

  @doc """
  `ranked/2` for many objects in one query, each with its file: `pairs` are
  `{key, file_uuid}`, and the result maps each pair that has an active
  location row to its ranked buckets. Never raises: a failed lookup is `%{}`.
  """
  @spec ranked_all([{String.t(), String.t()}]) :: %{
          {String.t(), String.t()} => [%{bucket_uuid: String.t(), role: String.t() | nil}]
        }
  def ranked_all([]), do: %{}

  def ranked_all(pairs) when is_list(pairs) do
    default = Profiles.default_uuid()
    wanted = MapSet.new(pairs, fn {key, file_uuid} -> {key, to_string(file_uuid)} end)
    keys = wanted |> Enum.map(&elem(&1, 0)) |> Enum.uniq()
    file_uuids = wanted |> Enum.map(&elem(&1, 1)) |> Enum.uniq()

    from(l in FileLocation,
      join: i in FileInstance,
      on: i.uuid == l.file_instance_uuid,
      join: f in StorageFile,
      on: f.uuid == i.file_uuid,
      left_join: lib in Library,
      on: lib.uuid == f.library_uuid,
      left_join: pb in ProfileBucket,
      on:
        pb.bucket_uuid == l.bucket_uuid and
          pb.profile_uuid == coalesce(lib.storage_profile_uuid, type(^default, UUIDv7)),
      where: l.path in ^keys and i.file_uuid in ^file_uuids and l.status == "active",
      select: {l.path, i.file_uuid, l.bucket_uuid, pb.role, pb.serve_order}
    )
    |> repo().all()
    |> Enum.group_by(
      fn {key, file_uuid, _bucket, _role, _order} -> {key, to_string(file_uuid)} end,
      fn {_key, _file_uuid, bucket, role, order} -> {bucket, role, order} end
    )
    |> Enum.filter(fn {pair, _rows} -> MapSet.member?(wanted, pair) end)
    |> Map.new(fn {pair, rows} -> {pair, rank(rows)} end)
  rescue
    error ->
      Logger.warning("Storage: location lookup failed: #{Exception.message(error)}")
      %{}
  end

  def ranked_all(_pairs), do: %{}

  defp rank(rows) do
    rows
    |> Enum.map(fn {bucket_uuid, role, serve_order} ->
      {to_string(bucket_uuid), role, {Map.fetch!(@role_rank, role), serve_order || 0}}
    end)
    # Instances sharing a key (a cross-user copy) name the same buckets;
    # each bucket once, at its best rank.
    |> Enum.group_by(&elem(&1, 0))
    |> Enum.map(fn {_bucket, rows} -> Enum.min_by(rows, &elem(&1, 2)) end)
    |> Enum.sort_by(&elem(&1, 2))
    |> Enum.map(fn {bucket_uuid, role, _rank} -> %{bucket_uuid: bucket_uuid, role: role} end)
  end

  defp only_file(query, nil), do: query
  defp only_file(query, file_uuid), do: where(query, [_l, i], i.file_uuid == ^file_uuid)

  @doc """
  The buckets the profile of `file_uuid`'s library marks `backup`: never
  served for that file, not even probed when its location rows name no
  bucket that has the object. Never raises.
  """
  @spec backup_buckets(term()) :: [String.t()]
  def backup_buckets(file_uuid) do
    default = Profiles.default_uuid()

    from(f in StorageFile,
      left_join: lib in Library,
      on: lib.uuid == f.library_uuid,
      join: pb in ProfileBucket,
      on: pb.profile_uuid == coalesce(lib.storage_profile_uuid, type(^default, UUIDv7)),
      where: f.uuid == ^file_uuid and pb.role == "backup",
      select: pb.bucket_uuid
    )
    |> repo().all()
    |> Enum.map(&to_string/1)
  rescue
    _ -> []
  end

  @doc """
  Records that `bucket_uuid` holds the object at `key`: an active location
  row for every instance stored under that key that has none on that
  bucket. Returns how many rows were added. Never raises.
  """
  @spec record(String.t(), term()) :: non_neg_integer()
  def record(key, bucket_uuid) when is_binary(key) and not is_nil(bucket_uuid) do
    now = DateTime.truncate(DateTime.utc_now(), :second)

    rows =
      from(i in FileInstance,
        left_join: l in FileLocation,
        on: l.file_instance_uuid == i.uuid and l.bucket_uuid == ^bucket_uuid,
        where: i.file_name == ^key and is_nil(l.uuid),
        select: i.uuid
      )
      |> repo().all()
      |> Enum.map(fn instance_uuid ->
        %{
          uuid: UUIDv7.generate(),
          path: key,
          status: "active",
          priority: 0,
          last_verified_at: now,
          file_instance_uuid: instance_uuid,
          bucket_uuid: bucket_uuid,
          inserted_at: now,
          updated_at: now
        }
      end)

    if rows == [] do
      0
    else
      {count, _} =
        repo().insert_all(FileLocation, rows,
          on_conflict: :nothing,
          conflict_target: [:file_instance_uuid, :bucket_uuid]
        )

      count
    end
  rescue
    error ->
      Logger.warning(
        "Storage: recording #{key} on #{bucket_uuid} failed: #{Exception.message(error)}"
      )

      0
  end

  def record(_key, _bucket_uuid), do: 0

  @doc """
  Records every bucket in `bucket_uuids` for `key` (`record/2` each) and
  marks the key's instances checked: what a writer calls once its instance
  row exists, with the buckets the manager stored the object in (a writer
  knows every bucket it wrote).
  """
  @spec record_all(String.t(), [term()]) :: non_neg_integer()
  def record_all(key, bucket_uuids) when is_list(bucket_uuids) do
    count = bucket_uuids |> Enum.map(&record(key, &1)) |> Enum.sum()
    key |> instance_uuids() |> mark_checked(length(Enum.uniq(bucket_uuids)))
    count
  end

  @doc """
  Marks instances checked against every bucket, found in `found_in` of
  them. Never raises.
  """
  @spec mark_checked([term()], non_neg_integer()) :: :ok
  def mark_checked([], _found_in), do: :ok

  def mark_checked(instance_uuids, found_in) when is_list(instance_uuids) do
    now = NaiveDateTime.truncate(NaiveDateTime.utc_now(), :second)

    rows =
      instance_uuids
      |> Enum.uniq()
      |> Enum.map(&%{file_instance_uuid: &1, checked_at: now, found_in: found_in})

    repo().insert_all(LocationCheck, rows,
      on_conflict: {:replace, [:checked_at, :found_in]},
      conflict_target: [:file_instance_uuid]
    )

    :ok
  rescue
    error ->
      Logger.warning("Storage: marking instances checked failed: #{Exception.message(error)}")
      :ok
  end

  @doc """
  Whether `key` is known to be in no bucket: every instance stored under it
  was checked and found nowhere, and nothing has recorded it since. A read
  then answers "not found" without asking every bucket again.
  """
  @spec known_missing?(String.t()) :: boolean()
  def known_missing?(key) when is_binary(key) do
    instances =
      from(i in FileInstance,
        left_join: c in LocationCheck,
        on: c.file_instance_uuid == i.uuid,
        where: i.file_name == ^key,
        select: c.found_in
      )
      |> repo().all()

    instances != [] and Enum.all?(instances, &(&1 == 0))
  rescue
    _ -> false
  end

  def known_missing?(_key), do: false

  defp instance_uuids(key) do
    from(i in FileInstance, where: i.file_name == ^key, select: i.uuid) |> repo().all()
  rescue
    _ -> []
  end

  @doc "How many instances have not been checked against every bucket yet."
  @spec missing_count() :: non_neg_integer()
  def missing_count do
    from(i in unchecked_query(), select: count(i.uuid)) |> repo().one()
  end

  @doc """
  The instances not checked against every bucket yet: what
  `LocationBackfillJob` walks. Not "has no location row": a read that finds
  a key records one bucket, and a missing object never gets a row.
  """
  @spec unchecked_query() :: Ecto.Query.t()
  def unchecked_query do
    from(i in FileInstance,
      as: :instance,
      where:
        not exists(
          from(c in LocationCheck,
            where: c.file_instance_uuid == parent_as(:instance).uuid,
            select: 1
          )
        )
    )
  end

  defp repo, do: PhoenixKit.RepoHelper.repo()
end
