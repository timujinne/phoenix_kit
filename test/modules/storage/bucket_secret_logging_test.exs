defmodule PhoenixKit.Modules.Storage.BucketSecretLoggingTest do
  @moduledoc """
  `phoenix_kit_buckets` keeps a bucket's `access_key_id` and the `enc:v1:`
  ciphertext of its `secret_access_key` in plain columns, and Ecto's SQL debug
  logger prints every bound parameter of an `INSERT`/`UPDATE`. The bucket
  writes in `PhoenixKit.Modules.Storage` run with `log: false` so those values
  never reach a log that leaves the process.

  Each test asserts the debug log captured SQL at all (the suite's logger sits
  at `:warning`, and an empty capture would pass every `refute`) and then looks
  for the stored ciphertext and the access key id.
  """
  # async: false — stamps the global `:phoenix_kit, :secret_key_base` app env
  # and lowers the global logger level, same rationale as BucketPersistenceTest.
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.Bucket

  @access_key_id "AKIABUCKETLOGCANARY"

  setup do
    original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
    original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

    on_exit(fn ->
      restore_env(:integrations_encryption_key, original_dedicated)
      restore_env(:secret_key_base, original_flat)
    end)

    Application.delete_env(:phoenix_kit, :integrations_encryption_key)
    Application.put_env(:phoenix_kit, :secret_key_base, "secret-under-test-for-bucket-log")

    :ok
  end

  defp attrs(overrides \\ %{}) do
    Map.merge(
      %{
        name: "Log canary",
        provider: "r2",
        bucket_name: "media",
        region: "auto",
        endpoint: "https://acct.r2.cloudflarestorage.com",
        access_key_id: @access_key_id,
        secret_access_key: "bucket-secret-first"
      },
      overrides
    )
  end

  defp stored_secret(uuid), do: Repo.get!(Bucket, uuid).secret_access_key

  test "create_bucket/2 does not log the access key id or the stored ciphertext" do
    log =
      capture_debug_log(fn ->
        assert {:ok, %Bucket{uuid: uuid}} = Storage.create_bucket(attrs())
        send(self(), {:uuid, uuid})
      end)

    assert_received {:uuid, uuid}
    stored = stored_secret(uuid)
    assert String.starts_with?(stored, "enc:v1:")

    assert log =~ "phoenix_kit_buckets"
    refute log =~ stored
    refute log =~ "enc:v1:"
    refute log =~ @access_key_id
  end

  test "update_bucket/3 does not log the access key id or the new ciphertext" do
    {:ok, bucket} = Storage.create_bucket(attrs())
    first = stored_secret(bucket.uuid)

    log =
      capture_debug_log(fn ->
        assert {:ok, _} =
                 Storage.update_bucket(bucket, %{
                   access_key_id: @access_key_id <> "2",
                   secret_access_key: "bucket-secret-second"
                 })
      end)

    updated = stored_secret(bucket.uuid)
    assert String.starts_with?(updated, "enc:v1:")
    refute updated == first

    assert log =~ "phoenix_kit_buckets"
    refute log =~ updated
    refute log =~ "enc:v1:"
    refute log =~ @access_key_id
  end

  test "the bucket writes still land — log: false only silences logging" do
    assert {:ok, bucket} = Storage.create_bucket(attrs())
    assert {:ok, updated} = Storage.update_bucket(bucket, %{name: "Renamed"})
    assert Repo.get!(Bucket, updated.uuid).name == "Renamed"
  end

  defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)
end
