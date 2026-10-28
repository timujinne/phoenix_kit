defmodule PhoenixKit.Integration.ModuleFixtureTablesTest do
  @moduledoc """
  The fixtures work on a fresh database and on one upgraded from 2.x, where the
  real module table is already there (the sandbox rolls the swap back).
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Test.ModuleFixtureTables
  alias PhoenixKit.Test.Repo

  test "an existing table is replaced for the test, then created again without error" do
    Repo.query!(
      "CREATE TABLE IF NOT EXISTS phoenix_kit_post_media (uuid uuid, extra text NOT NULL)"
    )

    assert :ok = ModuleFixtureTables.create!([:post_media])
    assert :ok = ModuleFixtureTables.create!([:post_media])

    assert %{rows: [["uuid"], ["file_uuid"]]} =
             Repo.query!(
               "SELECT column_name FROM information_schema.columns " <>
                 "WHERE table_name = 'phoenix_kit_post_media' ORDER BY ordinal_position"
             )
  end
end
