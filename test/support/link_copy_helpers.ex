defmodule PhoenixKit.TestSupport.LinkCopyHelpers do
  @moduledoc """
  Fixtures for the tests of `Storage.link_copy/3`, `Storage.relink_file/3` and
  the variant keys burned thumbnails are written under: a real local bucket,
  real ImageMagick images, and files that went through `ProcessFileJob`, so
  they carry the variants of their library's set.
  """

  import Ecto.Query

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Bucket, Libraries, Manager, ProcessFileJob, VariantGenerator}
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  @buckets_cache :phoenix_kit_buckets_cache

  def imagemagick? do
    System.find_executable("convert") != nil and System.find_executable("identify") != nil
  end

  @doc "Only a bucket of this test takes uploads; Oban is started in manual mode."
  def setup_storage(tmp) do
    :persistent_term.erase(@buckets_cache)
    n = System.unique_integer([:positive])
    Repo.update_all(Bucket, set: [enabled: false])

    root = Path.join(tmp, "bucket")

    {:ok, bucket} =
      Storage.create_bucket(%{
        name: "link-copy-#{n}",
        provider: "local",
        endpoint: root,
        enabled: true,
        priority: 0
      })

    ExUnit.Callbacks.start_supervised!(
      {Oban, name: Oban, repo: PhoenixKit.Test.Repo, testing: :manual, queues: [], plugins: []}
    )

    ExUnit.Callbacks.on_exit(fn -> :persistent_term.erase(@buckets_cache) end)

    # The first registered user may become Owner; the ones below must not.
    _first = user!("first", n)
    %{n: n, tmp: tmp, bucket: bucket, root: root}
  end

  def user!(name, n) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "#{name}-linkcopy-#{n}@example.com",
        "password" => "ValidPassword123!"
      })

    user
  end

  def library!(n, name \\ "Target") do
    {:ok, library} =
      Storage.Libraries.create_system_library(
        %{name: "#{name} #{n}", slug: "#{String.downcase(name)}-#{n}"},
        hidden: true
      )

    library
  end

  @doc "A 1200x800 JPEG; `color` makes its bytes differ from another call's."
  def image!(dir, name, color \\ "red") do
    path = Path.join(dir, name)

    {_, 0} =
      System.cmd("convert", ["-size", "1200x800", "xc:#{color}", "-noise", "3", path],
        stderr_to_stdout: true
      )

    path
  end

  @doc "A 1200x800 PNG with a half-transparent alpha channel: its sizes are PNG, and not byte-stable."
  def alpha_png!(dir, name) do
    path = Path.join(dir, name)

    {_, 0} =
      System.cmd(
        "convert",
        [
          "-size",
          "1200x800",
          "plasma:",
          "-alpha",
          "set",
          "-channel",
          "A",
          "-evaluate",
          "set",
          "50%",
          path
        ],
        stderr_to_stdout: true
      )

    path
  end

  @doc "Stores `path` as `user` (into `library_uuid`, Media by default) and runs its variant job."
  def upload!(user, path, opts \\ []) do
    sha = :sha256 |> :crypto.hash(File.read!(path)) |> Base.encode16(case: :lower)
    name = Path.basename(path)
    ext = name |> Path.extname() |> String.trim_leading(".")
    store_opts = Keyword.take(opts, [:library_uuid, :dedup])

    file =
      case Storage.store_file_in_buckets(path, "image", user.uuid, sha, ext, name, store_opts) do
        {:ok, file} -> file
        {:ok, file, _} -> file
      end

    run_job!(file, name)
  end

  def run_job!(file, name \\ "photo.jpg") do
    :ok = ProcessFileJob.perform(%Oban.Job{args: %{"file_uuid" => file.uuid, "filename" => name}})
    reload(file)
  end

  def reload(file), do: Storage.get_file(file.uuid)

  def instances(file), do: Storage.list_file_instances(file.uuid)

  def keys(file), do: Map.new(instances(file), &{&1.variant_name, &1.file_name})

  def instance(file, variant), do: Storage.get_file_instance_by_name(file.uuid, variant)

  def exists?(key), do: Manager.file_exists?(key)

  def all_keys_exist?(keys), do: Enum.all?(keys, &exists?/1)

  def object_sha256(key) do
    tmp = Path.join(System.tmp_dir!(), "pk_linkcopy_sha_#{System.unique_integer([:positive])}")
    {:ok, _} = Manager.retrieve_file(key, destination_path: tmp)
    sha = :sha256 |> :crypto.hash(File.read!(tmp)) |> Base.encode16(case: :lower)
    File.rm(tmp)
    sha
  end

  @doc "How many objects the bucket holds."
  def object_count(root),
    do: Path.join(root, "**/*") |> Path.wildcard() |> Enum.count(&File.regular?/1)

  @doc "Writes `color` over `file`'s `variant` slot the way a burn does (no spec hash)."
  def burn!(file, variant, tmp, color \\ "green") do
    prepared = image!(tmp, "burn-#{System.unique_integer([:positive])}.jpg", color)
    %{file_name: source} = instance(file, "original")

    {:ok, burned} =
      VariantGenerator.store_prepared_variant(file, variant, prepared, "jpg", "image/jpeg",
        source_key: source
      )

    burned
  end

  @doc "Queued `ProcessFileJob`s for `file`."
  def queued_jobs(file) do
    Repo.all(
      from(j in Oban.Job,
        where:
          j.worker == "PhoenixKit.Modules.Storage.ProcessFileJob" and
            fragment("?->>'file_uuid' = ?", j.args, ^file.uuid)
      )
    )
  end

  def media_uuid, do: Libraries.media_uuid()
end
