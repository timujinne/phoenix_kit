defmodule PhoenixKit.Settings.ModifySettingConcurrencyTest do
  @moduledoc """
  `PhoenixKit.Settings.modify_setting_with_module/4` under real concurrency: separate
  database sessions and real commits, no sandbox (the sandbox runs everything on one
  connection, where a row lock cannot show). Same shape as
  `PhoenixKit.API.ApprovalsConcurrencyTest`.

  What the lock buys: N writers that each append a token all keep their token. Without the
  `FOR UPDATE` (a plain read of the row) only one of them survives.
  """
  use ExUnit.Case, async: false

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.Repo

  @moduletag :integration

  @writers 12

  setup do
    Sandbox.mode(Repo, :auto)
    key = "modify_race_#{System.unique_integer([:positive])}"

    on_exit(fn ->
      Sandbox.mode(Repo, :auto)

      Repo.query!(
        "DELETE FROM phoenix_kit_activities " <>
          "WHERE action = 'setting.changed' AND metadata->>'key' = $1",
        [key]
      )

      Repo.query!("DELETE FROM phoenix_kit_settings WHERE key = $1", [key])
      Sandbox.mode(Repo, :manual)
    end)

    %{key: key}
  end

  defp concurrently(count, fun) do
    1..count
    |> Enum.map(fn n -> Task.async(fn -> fun.(n) end) end)
    |> Task.await_many(30_000)
  end

  defp append(token),
    do: fn stored -> Enum.join(Enum.reject([stored, token], &is_nil/1), "\n") end

  test "writers racing on an existing row each keep their change", %{key: key} do
    {:ok, _} = Settings.update_setting(key, "seed")

    results =
      concurrently(@writers, fn n ->
        Settings.modify_setting_with_module(key, "api", append("w#{n}"))
      end)

    assert Enum.all?(results, &match?({:ok, %Settings.Setting{}}, &1))

    tokens = key |> Settings.get_setting() |> String.split("\n")
    assert hd(tokens) == "seed"
    assert Enum.sort(tl(tokens)) == Enum.sort(for n <- 1..@writers, do: "w#{n}")
  end

  test "writers racing to create the key: the losers get an error, none raises, no change is lost",
       %{key: key} do
    results =
      concurrently(@writers, fn n ->
        try do
          {n, Settings.modify_setting_with_module(key, "api", append("w#{n}"))}
        rescue
          exception -> {n, {:raised, exception}}
        end
      end)

    {won, lost} = Enum.split_with(results, &match?({_, {:ok, %Settings.Setting{}}}, &1))

    # `FOR UPDATE` cannot lock a row that does not exist, so the first writers collide on
    # the unique key and get a changeset back; a writer that starts after the first commit
    # finds the row and appends like any other.
    assert won != []
    assert Enum.all?(lost, &match?({_, {:error, %Ecto.Changeset{}}}, &1))

    tokens = key |> Settings.get_setting() |> String.split("\n")
    assert Enum.sort(tokens) == Enum.sort(for {n, _} <- won, do: "w#{n}")
  end
end
