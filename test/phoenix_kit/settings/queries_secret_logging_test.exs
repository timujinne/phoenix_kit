defmodule PhoenixKit.Settings.QueriesSecretLoggingTest do
  @moduledoc """
  `phoenix_kit_settings` stores every setting's value in the same
  two generic columns — secrets included (`oauth_google_client_secret`,
  `aws_secret_access_key`, ...). Ecto's own SQL debug logger has no notion
  of the schema (no `redact:` field option reaches it) and would otherwise
  print the literal bound value on every insert/update, e.g.
  `UPDATE ... SET value = $1 ... [<secret>, ...]` — found doing exactly
  that on a live install.

  Destructive proof, not a confirming one: write a fake secret through the
  real `PhoenixKit.Settings.update_setting/2` path and confirm that neither
  it nor its stored ciphertext shows up in the log, at `:debug` — the level
  Ecto logs queries at by default, and the level a leak would actually
  surface at. With encryption on, the bound value is the `enc:v1:` ciphertext,
  not the plaintext, so that is what is looked for; and each test asserts the
  capture saw the SQL at all, because the suite's logger sits at `:warning`
  and an empty capture would pass every `refute` (see
  `PhoenixKit.DataCase.capture_debug_log/1`).
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.Queries

  @canary "leak-canary-secret-#{System.unique_integer([:positive])}"

  setup do
    original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
    original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

    on_exit(fn ->
      restore_env(:integrations_encryption_key, original_dedicated)
      restore_env(:secret_key_base, original_flat)
    end)

    Application.delete_env(:phoenix_kit, :integrations_encryption_key)
    Application.put_env(:phoenix_kit, :secret_key_base, "secret-under-test-for-settings-log")

    :ok
  end

  test "inserting a brand-new setting never leaks its value into the SQL debug log" do
    log =
      capture_debug_log(fn ->
        {:ok, _} = Settings.update_setting("oauth_google_client_secret", @canary)
      end)

    stored = Queries.get_setting_by_key("oauth_google_client_secret").value
    assert String.starts_with?(stored, "enc:v1:")

    assert log =~ "phoenix_kit_settings"
    refute log =~ stored
    refute log =~ "enc:v1:"
    refute log =~ @canary
  end

  test "updating an existing setting never leaks the new value into the SQL debug log" do
    {:ok, _} = Settings.update_setting("oauth_google_client_secret", "seed-value")

    log =
      capture_debug_log(fn ->
        {:ok, _} = Settings.update_setting("oauth_google_client_secret", @canary)
      end)

    stored = Queries.get_setting_by_key("oauth_google_client_secret").value
    assert String.starts_with?(stored, "enc:v1:")

    assert log =~ "phoenix_kit_settings"
    refute log =~ stored
    refute log =~ "enc:v1:"
    refute log =~ @canary
  end

  test "the write still actually happens — log: false only silences logging" do
    {:ok, _} = Settings.update_setting("oauth_google_client_secret", @canary)

    assert Settings.get_setting("oauth_google_client_secret") == @canary
  end

  defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)
end
