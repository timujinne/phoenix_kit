defmodule PhoenixKit.Settings.ModifySettingTest do
  @moduledoc """
  `PhoenixKit.Settings.modify_setting_with_module/4`: a change that depends on the value the
  setting has now, taken from the database under a row lock and never from the cache.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Settings
  alias PhoenixKit.Settings.History
  alias PhoenixKit.Settings.Setting
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.Auth

  setup do
    start_supervised!(PhoenixKit.Cache.Registry)
    start_supervised!({PhoenixKit.Cache, name: :settings})
    %{key: "modify_test_#{System.unique_integer([:positive])}"}
  end

  defp append(suffix), do: fn stored -> (stored || "") <> suffix end

  test "the function gets the stored value, not a stale cached one", %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")
    PhoenixKit.Cache.put(:settings, key, "stale")

    assert {:ok, %Setting{value: "ab", module: "mod"}} =
             Settings.modify_setting_with_module(key, "mod", append("b"))

    assert Settings.get_setting(key) == "ab"
    assert Settings.fetch_setting_cached(key) == {:ok, "ab"}
  end

  test "a key that does not exist yet is created from nil", %{key: key} do
    assert {:ok, %Setting{value: "new", module: "mod"}} =
             Settings.modify_setting_with_module(key, "mod", fn nil -> "new" end)

    assert Settings.get_setting(key) == "new"
  end

  test "the history records the old and the new value with the actor", %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")

    {:ok, _} =
      Settings.modify_setting_with_module(key, "mod", append("b"),
        actor_uuid: Auth.get_user_by_email("seed-owner@phoenixkit.test").uuid,
        source: "settings"
      )

    assert [newest | _] = History.list(key)
    assert newest.metadata["from"] == "a"
    assert newest.metadata["to"] == "ab"
    assert newest.metadata["source"] == "settings"
  end

  test ":unchanged writes nothing, records nothing and creates no row", %{key: key} do
    assert {:ok, :unchanged} =
             Settings.modify_setting_with_module(key, "mod", fn nil -> :unchanged end)

    assert Repo.get_by(Setting, key: key) == nil

    {:ok, _} = Settings.update_setting(key, "a")
    before = length(History.list(key))

    assert {:ok, :unchanged} =
             Settings.modify_setting_with_module(key, "mod", fn "a" -> :unchanged end)

    assert length(History.list(key)) == before
  end

  test "a value equal to the stored one records no history entry", %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")
    before = length(History.list(key))

    assert {:ok, %Setting{value: "a"}} =
             Settings.modify_setting_with_module(key, "mod", fn stored -> stored end)

    assert length(History.list(key)) == before
  end

  test "a value the setting refuses is an error and the old value stays", %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")

    assert {:error, %Ecto.Changeset{valid?: false}} =
             Settings.modify_setting_with_module(key, "mod", fn _ ->
               String.duplicate("x", 1001)
             end)

    assert Settings.get_setting(key) == "a"
  end

  test "a history entry that cannot be written is an error on the setting's changeset",
       %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")

    assert {:error, %Ecto.Changeset{data: %Setting{}, errors: errors}} =
             Settings.modify_setting_with_module(key, "mod", append("b"),
               actor_uuid: "not-a-uuid"
             )

    assert {message, _} = errors[:base]
    assert message =~ "the change could not be recorded"
    assert Settings.get_setting(key) == "a"
  end

  test "a function that returns neither a binary nor :unchanged raises and writes nothing",
       %{key: key} do
    {:ok, _} = Settings.update_setting(key, "a")

    assert_raise ArgumentError, ~r/must return a binary or :unchanged, got: nil/, fn ->
      Settings.modify_setting_with_module(key, "mod", fn _ -> nil end)
    end

    assert Settings.get_setting(key) == "a"
  end
end
