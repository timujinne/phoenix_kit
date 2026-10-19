defmodule PhoenixKit.Integration.KeyRotationBucketsTest do
  @moduledoc """
  `PhoenixKit.Integrations.KeyRotation` against `phoenix_kit_buckets` rows.

  A bucket's `secret_access_key` is encrypted by the same
  `PhoenixKit.Integrations.Encryption` key as the integration connections and
  the restricted settings, so a rotation that skipped it would leave every
  S3 key stranded under the old key the moment the app restarts onto the new
  one.
  """
  use PhoenixKit.DataCase, async: false

  alias Ecto.Adapters.SQL, as: EctoSQL
  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.Encryption
  alias PhoenixKit.Integrations.KeyRotation
  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries

  @new_secret "brand-new-secret-well-over-min-length"

  setup do
    original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
    original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

    on_exit(fn ->
      restore_env(:integrations_encryption_key, original_dedicated)
      restore_env(:secret_key_base, original_flat)
    end)

    Application.delete_env(:phoenix_kit, :integrations_encryption_key)
    Application.put_env(:phoenix_kit, :secret_key_base, "current-secret-under-test")

    :ok
  end

  defp create_bucket!(name, secret) do
    {:ok, bucket} =
      Storage.create_bucket(%{
        name: name,
        provider: "s3",
        bucket_name: "bucket-#{name}",
        access_key_id: "AKIA#{name}",
        secret_access_key: secret
      })

    bucket
  end

  defp raw_secret(bucket), do: Storage.get_bucket(bucket.uuid).secret_access_key

  # Writes a bucket's secret verbatim, bypassing the changeset's encryption
  # step (which would otherwise re-encrypt it under the active key).
  defp write_raw_secret!(bucket, value) do
    bucket.uuid
    |> Storage.get_bucket()
    |> Ecto.Changeset.change(secret_access_key: value)
    |> PhoenixKit.RepoHelper.repo().update!()
  end

  defp activate_new_secret do
    Application.put_env(:phoenix_kit, :integrations_encryption_key, @new_secret)
  end

  defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)

  describe "rotate/2 — storage buckets" do
    test "after switching to the new key, the bucket's secret_access_key is still readable" do
      bucket = create_bucket!("one", "s3-secret-one")

      assert {:ok, %{dry_run: false}} = KeyRotation.rotate(@new_secret)

      # What the app sees once the operator switches config to the new key
      # and restarts.
      activate_new_secret()
      assert Encryption.decrypt_value(raw_secret(bucket)) == {:ok, "s3-secret-one"}
    end

    test "re-encrypts the bucket's secret_access_key; the old key can no longer read it" do
      bucket = create_bucket!("two", "s3-secret-two")
      before_secret = raw_secret(bucket)
      assert String.starts_with?(before_secret, "enc:v1:")

      assert {:ok, %{rotated: 1, dry_run: false}} = KeyRotation.rotate(@new_secret)

      after_secret = raw_secret(bucket)
      assert String.starts_with?(after_secret, "enc:v1:")
      refute after_secret == before_secret
      assert {:error, _} = Encryption.decrypt_value(after_secret)
    end

    test "leaves every other bucket column alone" do
      bucket = create_bucket!("cols", "s3-secret-cols")

      assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)

      reloaded = Storage.get_bucket(bucket.uuid)
      assert reloaded.name == bucket.name
      assert reloaded.access_key_id == bucket.access_key_id
      assert reloaded.bucket_name == bucket.bucket_name
      assert reloaded.provider == bucket.provider
    end

    test "buckets without a secret are not counted or touched" do
      {:ok, local} = Storage.create_bucket(%{name: "local", provider: "local"})

      assert {:ok, %{rotated: 0, dry_run: false}} = KeyRotation.rotate(@new_secret)

      assert Storage.get_bucket(local.uuid).secret_access_key in [nil, ""]
    end

    test "a bucket secret still PLAINTEXT (predates encryption) gets encrypted, not skipped" do
      bucket = create_bucket!("legacy", "s3-secret-legacy")
      write_raw_secret!(bucket, "s3-secret-legacy")
      refute String.starts_with?(raw_secret(bucket), "enc:v1:")

      assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)

      after_secret = raw_secret(bucket)
      assert String.starts_with?(after_secret, "enc:v1:")

      activate_new_secret()
      assert Encryption.decrypt_value(after_secret) == {:ok, "s3-secret-legacy"}
    end

    test "aborts and writes NOTHING when a bucket secret fails to decrypt under the current key" do
      good = create_bucket!("good", "s3-secret-good")
      bad = create_bucket!("bad", "s3-secret-bad")

      corrupted = Encryption.encrypt_value_with_secret("s3-secret-bad", "some-other-secret")
      write_raw_secret!(bad, corrupted)

      good_before = raw_secret(good)
      bad_uuid = bad.uuid

      assert {:error, {:decrypt_failed, ^bad_uuid, :decrypt_failed_under_current_key}} =
               KeyRotation.rotate(@new_secret)

      assert raw_secret(good) == good_before
      assert raw_secret(bad) == corrupted
    end

    test "one undecryptable bucket aborts the whole rotation: connection, restricted setting and good bucket stay as they were" do
      {:ok, %{uuid: conn_uuid}} = Integrations.add_connection("openrouter", "conn")
      {:ok, _} = Integrations.save_setup(conn_uuid, %{"api_key" => "sk-conn"})
      [restricted_key | _] = Settings.restricted_setting_keys()
      {:ok, _} = Settings.update_setting(restricted_key, "restricted-secret")

      good = create_bucket!("atomic-good", "s3-secret-good")
      bad = create_bucket!("atomic-bad", "s3-secret-bad")

      write_raw_secret!(
        bad,
        Encryption.encrypt_value_with_secret("s3-secret-bad", "other-secret")
      )

      conn_before = Queries.get_setting_by_uuid(conn_uuid).value_json
      restricted_before = Queries.get_setting_by_key(restricted_key).value
      good_before = raw_secret(good)
      bad_before = raw_secret(bad)
      bad_uuid = bad.uuid

      assert {:error, {:decrypt_failed, ^bad_uuid, :decrypt_failed_under_current_key}} =
               KeyRotation.rotate(@new_secret)

      assert Queries.get_setting_by_uuid(conn_uuid).value_json == conn_before
      assert Queries.get_setting_by_key(restricted_key).value == restricted_before
      assert raw_secret(good) == good_before
      assert raw_secret(bad) == bad_before
    end

    test "dry run counts buckets and writes nothing" do
      bucket = create_bucket!("dry", "s3-secret-dry")
      before_secret = raw_secret(bucket)

      assert {:ok, %{rotated: 1, dry_run: true}} = KeyRotation.rotate("unused", dry_run: true)

      assert raw_secret(bucket) == before_secret
    end

    test "running again under the new key keeps the bucket readable (idempotent)" do
      bucket = create_bucket!("again", "s3-secret-again")

      assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)
      activate_new_secret()
      assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)

      assert Encryption.decrypt_value(raw_secret(bucket)) == {:ok, "s3-secret-again"}
    end

    test "running again BEFORE the restart refuses and leaves the rotated bucket untouched" do
      bucket = create_bucket!("early", "s3-secret-early")

      assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)
      rotated = raw_secret(bucket)

      bucket_uuid = bucket.uuid

      assert {:error, {:decrypt_failed, ^bucket_uuid, :decrypt_failed_under_current_key}} =
               KeyRotation.rotate(@new_secret)

      assert raw_secret(bucket) == rotated
    end

    test "the bucket row-fetch of a real rotation is FOR NO KEY UPDATE (uploads take FOR KEY SHARE on the bucket), the dry-run one is not" do
      repo = PhoenixKit.RepoHelper.repo()

      {locked_sql, _} = EctoSQL.to_sql(:all, repo, KeyRotation.locked_buckets_query())
      {plain_sql, _} = EctoSQL.to_sql(:all, repo, KeyRotation.rotate_buckets_query())

      assert locked_sql =~ "FOR NO KEY UPDATE"
      refute plain_sql =~ "FOR "
    end

    test "rotation does not print the new ciphertext into the Ecto debug log" do
      bucket = create_bucket!("log", "s3-secret-log")

      log =
        capture_debug_log(fn ->
          assert {:ok, %{rotated: 1}} = KeyRotation.rotate(@new_secret)
        end)

      assert log =~ "SELECT"
      refute log =~ ~r/^UPDATE /m
      refute log =~ String.slice(raw_secret(bucket), 0, 40)
    end
  end
end
