defmodule PhoenixKit.Migrations.Postgres.V162 do
  @moduledoc """
  V162: First-class payment-option linkage on billing orders.

  An order records HOW it is to be paid via `payment_method`, a small closed
  vocabulary (`bank`, `stripe`, `paypal`, …). What the customer actually
  chose at checkout is a `phoenix_kit_payment_options` row — an
  operator-configured method with its own name, instructions, provider and
  billing-profile requirement. The two are not the same thing: several
  options can share one `payment_method` ("Bank transfer (EU)" and "Bank
  transfer (UK)" are both `bank`), and an option can be renamed or
  deactivated after the order is placed.

  Without a link, the choice was simply lost at conversion: nothing on the
  order said which option the customer picked, so an operator processing a
  bank transfer could not tell which instructions the customer had been
  shown, and payment reconciliation had to guess.

  `ON DELETE SET NULL` rather than restrict: deactivating and deleting a
  payment option is an ordinary operator action, and it must not be blocked
  by — or destroy — historical orders. The order keeps `payment_method` and
  its metadata snapshot regardless, so a deleted option degrades to "we know
  it was a bank transfer" rather than to nothing.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)
    schema = schema_name(prefix)

    # A raw guarded block rather than `add_if_not_exists` + `references`:
    # Ecto emits the column and its constraint as separate statements and
    # only the column carries IF NOT EXISTS, so a re-run — or a prefixed run
    # whose constraint resolves through the search_path — fails on the
    # constraint. Every check here is anchored on `table_schema`, per the
    # chain's prefix-safety rules.
    execute("""
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = '#{schema}' AND table_name = 'phoenix_kit_orders'
      ) THEN
        RAISE NOTICE 'Orders table not found, skipping V162';
        RETURN;
      END IF;

      IF NOT EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_schema = '#{schema}'
          AND table_name = 'phoenix_kit_orders'
          AND column_name = 'payment_option_uuid'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_orders
          ADD COLUMN payment_option_uuid UUID;
      END IF;

      -- Any FK on the column, whatever it is called: an earlier build of
      -- this migration created one under Ecto's default name.
      IF NOT EXISTS (
        SELECT FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON kcu.constraint_name = tc.constraint_name
         AND kcu.constraint_schema = tc.constraint_schema
        WHERE tc.table_schema = '#{schema}'
          AND tc.table_name = 'phoenix_kit_orders'
          AND tc.constraint_type = 'FOREIGN KEY'
          AND kcu.column_name = 'payment_option_uuid'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_orders
          ADD CONSTRAINT fk_orders_payment_option
          FOREIGN KEY (payment_option_uuid)
          REFERENCES #{p}phoenix_kit_payment_options(uuid)
          ON DELETE SET NULL;
      END IF;
    END $$;
    """)

    # FK columns get an index: the payment-options admin needs "orders using
    # this option" and, without it, that is a sequential scan of every order.
    # Bare name on CREATE — an index always lands in its table's schema.
    execute("""
    DO $$
    BEGIN
      IF EXISTS (
        SELECT FROM information_schema.columns
        WHERE table_schema = '#{schema}'
          AND table_name = 'phoenix_kit_orders'
          AND column_name = 'payment_option_uuid'
      ) THEN
        CREATE INDEX IF NOT EXISTS phoenix_kit_orders_payment_option_uuid_index
          ON #{p}phoenix_kit_orders (payment_option_uuid);
      END IF;
    END $$;
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '162'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_orders_payment_option_uuid_index")

    execute("""
    ALTER TABLE #{p}phoenix_kit_orders
      DROP CONSTRAINT IF EXISTS fk_orders_payment_option
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_orders
      DROP CONSTRAINT IF EXISTS phoenix_kit_orders_payment_option_uuid_fkey
    """)

    execute("""
    ALTER TABLE #{p}phoenix_kit_orders
      DROP COLUMN IF EXISTS payment_option_uuid
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '161'")
  end

  defp schema_name("public"), do: "public"
  defp schema_name(prefix), do: prefix

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
