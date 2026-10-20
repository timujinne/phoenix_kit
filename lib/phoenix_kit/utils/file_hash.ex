defmodule PhoenixKit.Utils.FileHash do
  @moduledoc """
  Checksums of a file on disk, read in chunks.

  A video can be gigabytes. `File.read!/1` followed by `:crypto.hash/2` holds the
  whole file in memory (twice, while it is copied into a binary), once for every
  checksum taken: the original's SHA-256 and MD5 at upload, each rendition's, the
  dedup backfill. This reads the file a megabyte at a time, so what a hash costs in
  memory is the chunk, whatever the file's size.

      FileHash.sha256("/tmp/video.mov")
      #=> {:ok, "9f86d0…"}

      FileHash.hashes("/tmp/video.mov", [:sha256, :md5])
      #=> {:ok, %{sha256: "…", md5: "…"}}   # one pass over the file

  Digests are lowercase hexadecimal, as everywhere in storage. The `!` forms raise
  `File.Error` as `File.read!/1` did, for the callers that were written around it.
  """

  @chunk_size 1_048_576
  @algorithms [:sha256, :md5, :sha, :sha384, :sha512]

  @type algorithm :: :sha256 | :md5 | :sha | :sha384 | :sha512
  @type result :: {:ok, String.t()} | {:error, File.posix() | :badarg}

  @doc "The SHA-256 of the file at `path`."
  @spec sha256(Path.t(), keyword()) :: result()
  def sha256(path, opts \\ []), do: single(path, :sha256, opts)

  @doc "The MD5 of the file at `path`."
  @spec md5(Path.t(), keyword()) :: result()
  def md5(path, opts \\ []), do: single(path, :md5, opts)

  @doc "`sha256/2`, raising `File.Error` when the file cannot be read."
  @spec sha256!(Path.t(), keyword()) :: String.t()
  def sha256!(path, opts \\ []), do: unwrap!(sha256(path, opts), path)

  @doc "`md5/2`, raising `File.Error` when the file cannot be read."
  @spec md5!(Path.t(), keyword()) :: String.t()
  def md5!(path, opts \\ []), do: unwrap!(md5(path, opts), path)

  @doc """
  Several digests of the file in one pass over it.

  Returns `{:ok, %{algorithm => hex}}` for the algorithms asked for, or
  `{:error, :badarg}` when one is not an `t:algorithm/0`. `opts`: `:chunk_size` (bytes per read; default 1 MiB).
  """
  @spec hashes(Path.t(), [algorithm()], keyword()) ::
          {:ok, %{algorithm() => String.t()}} | {:error, File.posix() | :badarg}
  def hashes(path, algorithms, opts \\ []) when is_list(algorithms) and algorithms != [] do
    chunk = chunk_size(opts)

    with :ok <- check_algorithms(algorithms),
         {:ok, io} <- File.open(path, [:read, :raw, :binary]) do
      try do
        states = Map.new(algorithms, &{&1, :crypto.hash_init(&1)})

        case read_all(io, states, chunk) do
          {:ok, states} ->
            {:ok, Map.new(states, fn {algorithm, state} -> {algorithm, hex(state)} end)}

          {:error, _reason} = error ->
            error
        end
      after
        File.close(io)
      end
    end
  end

  defp check_algorithms(algorithms),
    do: if(Enum.all?(algorithms, &(&1 in @algorithms)), do: :ok, else: {:error, :badarg})

  defp single(path, algorithm, opts) do
    with {:ok, digests} <- hashes(path, [algorithm], opts),
         do: {:ok, Map.fetch!(digests, algorithm)}
  end

  defp read_all(io, states, chunk) do
    case :file.read(io, chunk) do
      {:ok, data} ->
        read_all(
          io,
          Map.new(states, fn {algorithm, state} ->
            {algorithm, :crypto.hash_update(state, data)}
          end),
          chunk
        )

      :eof ->
        {:ok, states}

      {:error, _reason} = error ->
        error
    end
  end

  defp hex(state), do: state |> :crypto.hash_final() |> Base.encode16(case: :lower)

  defp chunk_size(opts) do
    case Keyword.get(opts, :chunk_size, @chunk_size) do
      n when is_integer(n) and n > 0 -> n
      _ -> @chunk_size
    end
  end

  defp unwrap!({:ok, digest}, _path), do: digest

  defp unwrap!({:error, reason}, path),
    do: raise(File.Error, reason: reason, action: "read file", path: IO.chardata_to_string(path))
end
