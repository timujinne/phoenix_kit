defmodule PhoenixKit.Migrations.Postgres.V184Test do
  @moduledoc """
  V184's `shop_currency` deletion, run against a seeded settings row.

  `V184.up/1` can't be invoked outside an `Ecto.Migrator` runner (same
  constraint as V182Test and friends), and by the time any test runs the
  chain has already deleted the row — from an install that had no
  `shop_currency` problem to prove in the first place. So the migration
  exposes its statements via `up_statements/1`/`down_statements/1` (`up/1`
  and `down/1` execute exactly those lists), and this suite seeds the row
  back first, then runs the REAL SQL against it.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.Postgres.V184
  alias PhoenixKit.Test.Repo

  @table "phoenix_kit"

  defp seed_shop_currency! do
    Repo.query!("""
    INSERT INTO phoenix_kit_settings ("key", "module", "value", "value_json")
    VALUES ('shop_currency', 'shop', 'USD', NULL)
    ON CONFLICT ("key") DO NOTHING
    """)
  end

  defp run_up, do: Enum.each(V184.up_statements("public."), &Repo.query!/1)
  defp run_down, do: Enum.each(V184.down_statements("public."), &Repo.query!/1)

  defp shop_currency_count do
    %{rows: [[count]]} =
      Repo.query!("SELECT count(*) FROM phoenix_kit_settings WHERE \"key\" = 'shop_currency'")

    count
  end

  defp shop_currency_value do
    case Repo.query!("SELECT value FROM phoenix_kit_settings WHERE \"key\" = 'shop_currency'") do
      %{rows: [[value]]} -> value
      %{rows: []} -> nil
    end
  end

  defp table_marker do
    %{rows: [[marker]]} = Repo.query!("SELECT obj_description('#{@table}'::regclass)")
    marker
  end

  test "up deletes the dead shop_currency setting and stamps the version marker" do
    seed_shop_currency!()
    assert shop_currency_count() == 1

    run_up()

    assert shop_currency_count() == 0
    assert table_marker() == "184"
  end

  test "down restores the row exactly as V135 seeded it, and stamps the prior marker" do
    seed_shop_currency!()
    run_up()
    assert shop_currency_count() == 0

    run_down()

    assert shop_currency_count() == 1
    assert shop_currency_value() == "USD"
    assert table_marker() == "183"
  end

  test "down never clobbers a value an operator re-created by hand" do
    seed_shop_currency!()
    run_up()
    assert shop_currency_count() == 0

    # A host re-creates the setting by hand after the deletion, with a value
    # that is not the V135 default — e.g. it configured a real shop currency
    # under this key before ever seeing this migration.
    Repo.query!("""
    INSERT INTO phoenix_kit_settings ("key", "module", "value", "value_json")
    VALUES ('shop_currency', 'shop', 'EUR', NULL)
    """)

    run_down()

    # ON CONFLICT DO NOTHING: the hand-created row survives untouched.
    assert shop_currency_value() == "EUR"
    assert table_marker() == "183"
  end
end
