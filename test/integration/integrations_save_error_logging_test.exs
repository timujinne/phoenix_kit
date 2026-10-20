defmodule PhoenixKit.Integration.IntegrationsSaveErrorLoggingTest do
  @moduledoc """
  When saving an integration fails, the error log must not carry the row's
  stored value: `inspect(changeset)` printed `value_json` (the `enc:v1:`
  ciphertext, or the plaintext with encryption off) and the row's `value`.
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query
  import ExUnit.CaptureLog

  alias PhoenixKit.Integrations
  alias PhoenixKit.Settings.Setting

  @legacy_value "legacy-value-canary"

  setup do
    original_dedicated = Application.get_env(:phoenix_kit, :integrations_encryption_key)
    original_flat = Application.get_env(:phoenix_kit, :secret_key_base)

    on_exit(fn ->
      restore_env(:integrations_encryption_key, original_dedicated)
      restore_env(:secret_key_base, original_flat)
    end)

    Application.delete_env(:phoenix_kit, :integrations_encryption_key)
    Application.put_env(:phoenix_kit, :secret_key_base, "secret-under-test-for-save-error")

    :ok
  end

  test "a failed save logs the errors, not the changeset's values" do
    {:ok, %{uuid: uuid}} = Integrations.add_connection("openrouter", "save-error-log")

    # A row holding both value and value_json fails Setting's exclusivity
    # validation, which sends save_integration/3 down its error branch.
    Repo.update_all(from(s in Setting, where: s.uuid == ^uuid), set: [value: @legacy_value])

    log =
      capture_log(fn ->
        assert {:error, %Ecto.Changeset{}} =
                 Integrations.save_setup(uuid, %{"api_key" => "sk-save-error-plaintext"})
      end)

    assert log =~ "Failed to save integration #{uuid}"
    assert log =~ "cannot set both value and value_json"
    refute log =~ "enc:v1:"
    refute log =~ @legacy_value
    refute log =~ "sk-save-error-plaintext"
  end

  test "inspecting a Setting or its changeset hides value and value_json" do
    setting = %Setting{key: "k", value: "plain-canary", value_json: %{"a" => "json-canary"}}
    changeset = Setting.update_changeset(setting, %{value: "changed-canary"})

    for term <- [setting, changeset] do
      out = inspect(term)
      refute out =~ "plain-canary"
      refute out =~ "json-canary"
      refute out =~ "changed-canary"
    end
  end

  defp restore_env(key, nil), do: Application.delete_env(:phoenix_kit, key)
  defp restore_env(key, value), do: Application.put_env(:phoenix_kit, key, value)
end
