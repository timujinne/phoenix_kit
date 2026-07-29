defmodule PhoenixKit.Integration.Languages.RequestDefaultLanguageTest do
  @moduledoc """
  Pins the request-scoped default-language override used by multi-domain
  host apps: `put_request_default_language/1` + its precedence over the
  site-wide `is_default` flag inside `get_default_language/0`.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Modules.Languages
  alias PhoenixKit.Settings

  setup do
    config = %{
      "languages" => [
        %{"code" => "en-US", "name" => "English", "is_default" => true, "is_enabled" => true},
        %{"code" => "fr-FR", "name" => "French", "is_default" => false, "is_enabled" => true},
        %{"code" => "de", "name" => "German", "is_default" => false, "is_enabled" => false}
      ]
    }

    Settings.update_setting("languages_enabled", "true")
    Settings.update_json_setting("languages_config", config)

    on_exit(fn ->
      Languages.put_request_default_language(nil)
      Settings.update_setting("languages_enabled", "false")
    end)

    :ok
  end

  test "without an override the is_default language wins" do
    assert %{code: "en-US"} = Languages.get_default_language()
  end

  test "an enabled override (exact code) wins over is_default" do
    Languages.put_request_default_language("fr-FR")
    assert %{code: "fr-FR"} = Languages.get_default_language()
  end

  test "an enabled override matches on base code, both directions" do
    Languages.put_request_default_language("fr")
    assert %{code: "fr-FR"} = Languages.get_default_language()
  end

  test "a disabled override falls back to is_default" do
    Languages.put_request_default_language("de")
    assert %{code: "en-US"} = Languages.get_default_language()
  end

  test "an unknown override falls back to is_default" do
    Languages.put_request_default_language("xx")
    assert %{code: "en-US"} = Languages.get_default_language()
  end

  test "nil clears the override" do
    Languages.put_request_default_language("fr-FR")
    Languages.put_request_default_language(nil)
    assert Languages.request_default_language() == nil
    assert %{code: "en-US"} = Languages.get_default_language()
  end

  test "the override is process-scoped" do
    Languages.put_request_default_language("fr-FR")

    other =
      Task.async(fn -> Languages.request_default_language() end)
      |> Task.await()

    assert other == nil
  end

  test "override has no effect while the Languages module is disabled" do
    Settings.update_setting("languages_enabled", "false")
    Languages.put_request_default_language("fr-FR")
    assert Languages.get_default_language() == nil
  end
end
