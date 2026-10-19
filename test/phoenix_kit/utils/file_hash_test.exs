defmodule PhoenixKit.Utils.FileHashTest do
  @moduledoc """
  Checksums of a file read in chunks: the same digests as hashing the bytes in
  memory, whatever the chunk size and file size, errors as values, and a file far
  larger than the memory it is allowed to cost.
  """
  use ExUnit.Case, async: false

  alias PhoenixKit.Utils.FileHash

  @abc_sha256 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  @abc_md5 "900150983cd24fb0d6963f7d28e17f72"
  @empty_sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

  setup do
    dir = Path.join(System.tmp_dir!(), "pk_file_hash_#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf(dir) end)
    %{dir: dir}
  end

  defp write!(dir, name, bytes) do
    path = Path.join(dir, name)
    File.write!(path, bytes)
    path
  end

  defp hex(algorithm, bytes), do: algorithm |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  describe "digests" do
    test "known values", %{dir: dir} do
      path = write!(dir, "abc", "abc")

      assert {:ok, @abc_sha256} = FileHash.sha256(path)
      assert {:ok, @abc_md5} = FileHash.md5(path)
      assert FileHash.sha256!(path) == @abc_sha256
      assert FileHash.md5!(path) == @abc_md5
    end

    test "an empty file", %{dir: dir} do
      assert {:ok, @empty_sha256} = FileHash.sha256(write!(dir, "empty", ""))
    end

    test "the same as hashing the bytes in memory, whatever the chunk size", %{dir: dir} do
      bytes = :crypto.strong_rand_bytes(3 * 1_048_576 + 12_345)
      path = write!(dir, "random", bytes)

      for chunk <- [1, 7, 4096, 1_048_576, 10_000_000] do
        assert {:ok, hex(:sha256, bytes)} == FileHash.sha256(path, chunk_size: chunk)
      end

      assert {:ok, hex(:md5, bytes)} == FileHash.md5(path)
    end

    test "a chunk size that makes no sense falls back to the default", %{dir: dir} do
      path = write!(dir, "abc", "abc")

      for chunk <- [0, -1, nil, "big"] do
        assert {:ok, @abc_sha256} = FileHash.sha256(path, chunk_size: chunk)
      end
    end

    test "several digests in one pass", %{dir: dir} do
      path = write!(dir, "abc", "abc")

      assert {:ok, %{sha256: @abc_sha256, md5: @abc_md5}} =
               FileHash.hashes(path, [:sha256, :md5])
    end
  end

  describe "errors" do
    test "a missing file is an error value, and the bang raises as File.read! did", %{dir: dir} do
      path = Path.join(dir, "missing")

      assert {:error, :enoent} = FileHash.sha256(path)
      assert {:error, :enoent} = FileHash.hashes(path, [:sha256, :md5])
      assert_raise File.Error, fn -> FileHash.sha256!(path) end
      assert_raise File.Error, fn -> FileHash.md5!(path) end
    end

    test "an algorithm that is not offered is an error value, not a raise", %{dir: dir} do
      path = write!(dir, "abc", "abc")

      assert {:error, :badarg} = FileHash.hashes(path, [:sha256, :crc32])
    end

    test "a directory is an error", %{dir: dir} do
      assert {:error, _reason} = FileHash.sha256(dir)
    end
  end

  describe "memory" do
    @tag timeout: 120_000
    test "a file much larger than the memory it costs", %{dir: dir} do
      mib = 1_048_576
      block = :crypto.strong_rand_bytes(mib)
      path = Path.join(dir, "large")

      File.open!(path, [:write, :raw, :binary], fn io ->
        for _ <- 1..192, do: :ok = :file.write(io, block)
      end)

      assert File.stat!(path).size == 192 * mib

      :erlang.garbage_collect()
      baseline = :erlang.memory(:binary)
      sampler = start_sampler(baseline)

      {:ok, digest} = FileHash.sha256(path)

      peak = stop_sampler(sampler)
      assert digest == expected_sha256_of_repeated(block, 192)

      # Reading the file whole would put 192 MiB of binary on the heap at once;
      # a chunked read stays within a few chunks of where it started.
      assert peak - baseline < 48 * mib,
             "binary memory rose by #{div(peak - baseline, mib)} MiB hashing a 192 MiB file"
    end
  end

  defp expected_sha256_of_repeated(block, times) do
    1..times
    |> Enum.reduce(:crypto.hash_init(:sha256), fn _, state ->
      :crypto.hash_update(state, block)
    end)
    |> :crypto.hash_final()
    |> Base.encode16(case: :lower)
  end

  defp start_sampler(baseline) do
    parent = self()

    pid =
      spawn_link(fn ->
        sample_loop(baseline, parent)
      end)

    pid
  end

  defp sample_loop(peak, parent) do
    receive do
      :stop -> send(parent, {:peak, peak})
    after
      2 -> sample_loop(max(peak, :erlang.memory(:binary)), parent)
    end
  end

  defp stop_sampler(pid) do
    send(pid, :stop)

    receive do
      {:peak, peak} -> peak
    after
      5_000 -> flunk("the memory sampler did not answer")
    end
  end
end
