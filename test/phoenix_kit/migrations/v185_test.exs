defmodule PhoenixKit.Migrations.Postgres.V185Test do
  @moduledoc """
  V185's freeze columns and backfill, run against real cart/cart-item rows.

  `V185.up/1` can't be invoked outside an `Ecto.Migrator` runner (same
  constraint as V182Test/V184Test and friends), and by the time any test
  runs, the chain has already added these columns to an install with no
  rows to backfill in the first place. So the migration exposes its
  statements via `up_statements/1`/`down_statements/1` (`up/1`/`down/1`
  execute exactly those lists), and this suite runs the REAL SQL against
  currency and cart rows seeded to reproduce the three cases the backfill
  has to tell apart: a cart in the base currency, a cart in a currency the
  currency table still knows a rate for, and a cart in a currency the
  currency table has never heard of.
  """

  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.Postgres.V185
  alias PhoenixKit.Test.Repo

  @table "phoenix_kit"

  defp run_up, do: Enum.each(V185.up_statements("public."), &Repo.query!/1)

  defp table_marker do
    %{rows: [[marker]]} = Repo.query!("SELECT obj_description('#{@table}'::regclass)")
    marker
  end

  test "V185 backfills from the default-currency row, never from literals" do
    Repo.query!("DELETE FROM phoenix_kit_currencies")

    Repo.query!("""
    INSERT INTO phoenix_kit_currencies (uuid, code, name, symbol, is_default, enabled, exchange_rate, inserted_at, updated_at) VALUES
      (gen_random_uuid(),'USD','d','$',true,true,1.0,now(),now()),
      (gen_random_uuid(),'EUR','e','€',false,true,0.909091,now(),now())
    """)

    Repo.query!("""
    INSERT INTO phoenix_kit_shop_carts (uuid, session_id, status, currency, total, inserted_at, updated_at) VALUES
      ('018f0000-0000-7000-8000-000000000001','s1','active','USD',10.00,now(),now()),
      ('018f0000-0000-7000-8000-000000000002','s2','active','EUR',9.09,now(),now()),
      ('018f0000-0000-7000-8000-000000000003','s3','active','XXX',1.00,now(),now())
    """)

    Repo.query!("""
    INSERT INTO phoenix_kit_shop_cart_items (uuid, cart_uuid, product_title, unit_price, currency, quantity, line_total, inserted_at, updated_at) VALUES
      (gen_random_uuid(),'018f0000-0000-7000-8000-000000000001','t',10.00,'USD',1,10.00,now(),now()),
      (gen_random_uuid(),'018f0000-0000-7000-8000-000000000002','t',9.09,'EUR',1,9.09,now(),now())
    """)

    run_up()

    assert %{rows: [["USD", "1.000000"], ["USD", "0.909091"], ["USD", nil]]} =
             Repo.query!("""
             SELECT base_currency, exchange_rate::text FROM phoenix_kit_shop_carts
             ORDER BY session_id
             """)

    assert %{rows: [["10.00"], [nil]]} =
             Repo.query!("""
             SELECT ci.base_unit_price::text FROM phoenix_kit_shop_cart_items ci
             JOIN phoenix_kit_shop_carts c ON c.uuid = ci.cart_uuid
             ORDER BY c.session_id
             """)

    assert table_marker() == "185"
  end

  test "V185 refuses to run while two currencies claim is_default" do
    # The scratch database this suite runs against also carries billing's
    # own `phoenix_kit_currencies_default_uidx` (a partial unique index on
    # `is_default`, owned by phoenix_kit_billing, not core — plan §9.1). V185
    # cannot assume every host it reaches has that index, so it re-checks the
    # invariant itself (see the DO block in `up_statements/1`); this test
    # proves that guard fires on its own, without relying on the index. The
    # DROP happens inside this test's sandboxed transaction and is rolled
    # back with everything else at the end of the test.
    Repo.query!("DROP INDEX IF EXISTS phoenix_kit_currencies_default_uidx")
    Repo.query!("DELETE FROM phoenix_kit_currencies")

    Repo.query!("""
    INSERT INTO phoenix_kit_currencies (uuid, code, name, symbol, is_default, inserted_at, updated_at) VALUES
      (gen_random_uuid(),'USD','d','$',true,now(),now()),
      (gen_random_uuid(),'EUR','e','€',true,now(),now())
    """)

    assert_raise Postgrex.Error, ~r/exactly one default currency/, fn ->
      run_up()
    end
  end
end
