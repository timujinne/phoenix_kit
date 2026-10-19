defmodule PhoenixKit.Integration.SettingsSecretSqlLoggingTest do
  @moduledoc """
  The two write paths into `phoenix_kit_settings` that bypass
  `PhoenixKit.Settings.Queries` (and so its `log: false`) must not print a
  secret row's stored value through Ecto's SQL debug logger:

    * `PhoenixKit.Integrations.KeyRotation.rotate/2` — rewrites every
      integration connection and every restricted setting under the new
      secret; its `UPDATE`s used to log the fresh ciphertext of every one
      of them (found on a live rotation).
    * `PhoenixKit.Settings.update_settings_batch/2` — its `Ecto.Multi`
      insert/update steps logged the stored value, restricted keys
      included (its own doc example writes `aws_access_key_id`).

  Ciphertext is not the secret, but a debug log that leaves the process
  carries every secret row out with it, and paired with a leaked key it is
  the secrets themselves.

  The assertions look for the value AS STORED (read back from the row after
  the write), not for the plaintext: with encryption on, the plaintext never
  reaches the SQL at all, so a plaintext-only check passes whether or not
  the leak is there. Each test also asserts the debug log captured SQL at
  all — `config/test.exs` sets the logger to `:warning`, and a capture that
  saw nothing would make every `refute` here pass vacuously (see
  `PhoenixKit.DataCase.capture_debug_log/1`).
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integrations
  alias PhoenixKit.Integrations.KeyRotation
  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries

  @new_secret "rotated-secret-well-over-the-minimum-length"

  setup do
    original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
    original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

    on_exit(fn ->
      restore_env(:integrations_encryption_key, original_dedicated)
      restore_env(:secret_key_base, original_flat)
    end)

    # Encryption on (legacy secret_key_base tier) — the state a rotation runs in.
    Application.delete_env(:phoenix_kit, :integrations_encryption_key)
    Application.put_env(:phoenix_kit, :secret_key_base, "current-secret-under-test")

    :ok
  end

  defp stored_value(key), do: Queries.get_setting_by_key(key).value
  defp stored_value_json(uuid), do: Queries.get_setting_by_uuid(uuid).value_json

  describe "KeyRotation.rotate/2" do
    test "does not log the re-encrypted value of any rotated row" do
      {:ok, %{uuid: uuid}} = Integrations.add_connection("openrouter", "rotation-log")
      {:ok, _} = Integrations.save_setup(uuid, %{"api_key" => "sk-rotation-plaintext"})
      {:ok, _} = Settings.update_setting("oauth_google_client_secret", "gcs-rotation-plaintext")

      log =
        capture_debug_log(fn ->
          assert {:ok, %{rotated: 2, dry_run: false}} = KeyRotation.rotate(@new_secret)
        end)

      rotated_api_key = stored_value_json(uuid)["api_key"]
      rotated_client_secret = stored_value("oauth_google_client_secret")

      assert String.starts_with?(rotated_api_key, "enc:v1:")
      assert String.starts_with?(rotated_client_secret, "enc:v1:")

      # The capture really saw rotation's SQL: the locked read stays logged
      # (its parameters are key names, its result rows are never logged).
      assert log =~ "FOR UPDATE"

      refute log =~ rotated_api_key
      refute log =~ rotated_client_secret
      refute log =~ "enc:v1:"
      refute log =~ @new_secret
    end
  end

  describe "Settings.update_settings_batch/2" do
    test "does not log a restricted key's stored value, on insert or on update" do
      inserted_log =
        capture_debug_log(fn ->
          assert {:ok, _} =
                   Settings.update_settings_batch(%{"aws_secret_access_key" => "aws-batch-first"})
        end)

      inserted = stored_value("aws_secret_access_key")
      assert String.starts_with?(inserted, "enc:v1:")

      updated_log =
        capture_debug_log(fn ->
          assert {:ok, _} =
                   Settings.update_settings_batch(%{
                     "aws_secret_access_key" => "aws-batch-second"
                   })
        end)

      updated = stored_value("aws_secret_access_key")
      assert String.starts_with?(updated, "enc:v1:")
      refute updated == inserted

      # Both captures really saw the batch's SQL (its existing-rows read,
      # whose parameters are key names).
      assert inserted_log =~ "phoenix_kit_settings"
      assert updated_log =~ "phoenix_kit_settings"

      refute inserted_log =~ inserted
      refute updated_log =~ updated
      refute inserted_log =~ "enc:v1:"
      refute updated_log =~ "enc:v1:"
    end

    test "the batch write still lands — log: false only silences logging" do
      assert {:ok, _} = Settings.update_settings_batch(%{"aws_secret_access_key" => "aws-batch"})
      assert Settings.get_setting("aws_secret_access_key") == "aws-batch"
    end
  end

  defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)
end
