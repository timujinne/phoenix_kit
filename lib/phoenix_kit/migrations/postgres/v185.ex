defmodule PhoenixKit.Migrations.Postgres.V185 do
  @moduledoc """
  V185: freezes the base currency and exchange rate on carts, cart items,
  and orders.

  ## What it adds

    * `phoenix_kit_shop_carts.base_currency varchar(3)` and
      `.exchange_rate numeric(15,6)` — the base currency and the
      `base -> cart.currency` rate at the moment the cart was created,
      frozen there so a later change to the currency table (or to the
      shop's base currency) cannot silently reprice a cart the shopper
      is still looking at.
    * `phoenix_kit_shop_cart_items.base_unit_price numeric(15,2)` — the
      line's unit price expressed in the base currency, kept purely for
      *auditing new rows going forward*: without it a support agent
      looking at a mispriced line cannot tell whether the rate, an
      option modifier, or rounding is at fault.
    * `phoenix_kit_orders.base_currency varchar(3)`,
      `.exchange_rate numeric(15,6)`, `.base_total numeric(15,2)` — the
      same freeze at the moment an order is placed, so a rate change
      tomorrow can never retroactively change what an order is recorded
      as having cost, and so a multi-domain deployment can total orders
      placed in different currencies against one reporting currency.

  All six columns are added nullable, with no default — `ALTER TABLE ...
  ADD COLUMN` without a rewrite, safe at any table size. They stay
  nullable permanently, not just during the migration: a currency that
  is absent from `phoenix_kit_currencies` has no rate to report, and
  "unknown" has to be representable rather than replaced with a
  plausible-looking number.

  ## The `is_default` guard

  The backfill below derives every value from the *current* state of
  `phoenix_kit_currencies` rather than from a literal (see "Why the
  backfill is derived, not literal" below). That means the two
  `(SELECT code FROM phoenix_kit_currencies WHERE is_default)`-shaped
  subqueries silently pick an arbitrary row and produce a wrong-but-not
  crashing backfill if more than one currency claims `is_default = true`
  — the worst kind of bug, because it looks like it worked. A `DO`
  block runs first and raises before a single column is touched if the
  count is not exactly 1. Today the uniqueness of `is_default` is
  enforced only inside a transaction in
  `PhoenixKitBilling.set_default_currency/1`; the database has no
  constraint of its own (a partial unique index lands separately, owned
  by the billing package, since it owns that table's write path — see
  the plan's §9.1). This migration cannot assume that index exists on
  every host that reaches V185, so it re-checks the invariant itself
  rather than trusting a constraint it does not own.

  ## Why the backfill is derived, not literal

  An earlier draft backfilled with `base_currency = 'USD'`,
  `exchange_rate = 1.0` as constants. That is correct for a shop whose
  base currency happens to be USD, but this migration ships to every
  host running this package, including ones whose base is something
  else, or whose carts were created in a currency other than their own
  base. A literal would write a plausible-looking lie into a column
  that exists specifically to record the truth about the past.

  Instead every value is derived from the data in front of it: the base
  currency is read from the (now-verified-unique) `is_default` row, and
  the rate applied to a non-base row is the rate that row's currency
  actually carries in `phoenix_kit_currencies` today — `NULL` if that
  currency is not there at all. "This cart's rate is unknown" is a more
  honest answer than any number we could invent, and the fail-safe
  display path (spec §6.3) is required to survive exactly that `NULL`.

  ## Why `base_unit_price`/`base_total` are `NULL` for non-base rows

  For a cart or order already in the base currency, `base_unit_price`/
  `base_total` are filled in — they equal the row's own `unit_price`/
  `total`, no conversion needed. For a cart or order in a *different*
  currency, they are left `NULL` even when a rate was found, rather than
  computed as `unit_price / rate` or similar. Backfilling that
  multiplication would silently create the one thing this migration is
  built to avoid: a computed number nobody asked for and nobody can
  trace back to a real conversion event. These columns are meant to
  describe *new* rows created going forward under the real conversion
  path (`Currency.present/3`, cart snapshot, order freeze); a backfilled
  guess wearing the same column would be indistinguishable from the real
  thing to every later reader. `base_currency`/`exchange_rate` do not
  have this problem — they describe the row's own currency situation,
  not a converted amount, so deriving them from the currency table is
  reporting a fact, not fabricating one.

  On our stand this entire distinction is moot: the base currency is
  USD (an assumption, spec §3.1) and every existing cart, cart item, and
  order is already in USD, so the backfill is the identity — every
  `exchange_rate` becomes `1.000000` and every `base_*` equals its own
  source column. No price changes and no order is repriced. That
  identity is what makes USD-as-base a real argument rather than
  "that's how it's always been" (spec §9.3).

  ## Why the columns landed here and not with the tables' owning packages

  `phoenix_kit_shop_carts`, `phoenix_kit_shop_cart_items`, and
  `phoenix_kit_orders` are core tables consumed by the `ecommerce` and
  `billing` packages' own `Ecto.Schema`s. Ecto selects every field a
  schema declares, so a package that adds a field to its own schema
  without the column existing on the host fails every `Repo.all/1` with
  a `Postgrex.Error`. Core must create the column before either
  dependent package's schema can declare the field, which is why this
  migration exists in core and runs before the billing/ecommerce
  currency work pins onto a host (plan §0.3).

  ## `down/1`

  Drops all six columns. This is irreversible **in meaning**, not just
  mechanically: an order's frozen `exchange_rate` is the only record of
  what it was actually priced at, and dropping the column throws that
  fact away for good — a later `up/1` backfills a *fresh* guess from
  whatever the currency table says at that later moment, which is not
  the same information. `down/1` is provided because every migration in
  this chain needs one, not because rolling back is free.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    Enum.each(up_statements(p), &execute/1)
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    Enum.each(down_statements(p), &execute/1)
  end

  # Public (and idempotent) so the suite can run the REAL statements against
  # seeded cart/order rows — `up/1` itself can't be invoked outside an
  # `Ecto.Migrator` runner (same constraint as V182Test/V184Test and
  # friends), and by the time any test runs, the chain has already added
  # these columns to an install with no rows to backfill in the first
  # place. `p` is the rendered prefix including the trailing dot.
  @doc false
  def up_statements(p) do
    [
      """
      DO $$
      DECLARE
        n integer;
      BEGIN
        SELECT count(*) INTO n FROM #{p}phoenix_kit_currencies WHERE is_default;
        IF n <> 1 THEN
          RAISE EXCEPTION 'V185 needs exactly one default currency in #{p}phoenix_kit_currencies, found %', n;
        END IF;
      END $$
      """,
      "ALTER TABLE #{p}phoenix_kit_shop_carts ADD COLUMN IF NOT EXISTS base_currency character varying(3)",
      "ALTER TABLE #{p}phoenix_kit_shop_carts ADD COLUMN IF NOT EXISTS exchange_rate numeric(15,6)",
      "ALTER TABLE #{p}phoenix_kit_shop_cart_items ADD COLUMN IF NOT EXISTS base_unit_price numeric(15,2)",
      "ALTER TABLE #{p}phoenix_kit_orders ADD COLUMN IF NOT EXISTS base_currency character varying(3)",
      "ALTER TABLE #{p}phoenix_kit_orders ADD COLUMN IF NOT EXISTS exchange_rate numeric(15,6)",
      "ALTER TABLE #{p}phoenix_kit_orders ADD COLUMN IF NOT EXISTS base_total numeric(15,2)",
      """
      UPDATE #{p}phoenix_kit_shop_carts c
         SET base_currency = b.code,
             exchange_rate = CASE
               WHEN c.currency = b.code THEN 1.0
               ELSE (SELECT x.exchange_rate FROM #{p}phoenix_kit_currencies x WHERE x.code = c.currency)
             END
        FROM (SELECT code FROM #{p}phoenix_kit_currencies WHERE is_default) b
       WHERE c.base_currency IS NULL
      """,
      """
      UPDATE #{p}phoenix_kit_shop_cart_items ci
         SET base_unit_price = ci.unit_price
        FROM #{p}phoenix_kit_shop_carts c
       WHERE c.uuid = ci.cart_uuid
         AND ci.base_unit_price IS NULL
         AND c.currency = c.base_currency
      """,
      """
      UPDATE #{p}phoenix_kit_orders o
         SET base_currency = b.code,
             exchange_rate = CASE
               WHEN o.currency = b.code THEN 1.0
               ELSE (SELECT x.exchange_rate FROM #{p}phoenix_kit_currencies x WHERE x.code = o.currency)
             END,
             base_total = CASE WHEN o.currency = b.code THEN o.total ELSE NULL END
        FROM (SELECT code FROM #{p}phoenix_kit_currencies WHERE is_default) b
       WHERE o.base_currency IS NULL
      """,
      "COMMENT ON TABLE #{p}phoenix_kit IS '185'"
    ]
  end

  @doc false
  def down_statements(p) do
    [
      "ALTER TABLE #{p}phoenix_kit_shop_carts DROP COLUMN IF EXISTS base_currency",
      "ALTER TABLE #{p}phoenix_kit_shop_carts DROP COLUMN IF EXISTS exchange_rate",
      "ALTER TABLE #{p}phoenix_kit_shop_cart_items DROP COLUMN IF EXISTS base_unit_price",
      "ALTER TABLE #{p}phoenix_kit_orders DROP COLUMN IF EXISTS base_currency",
      "ALTER TABLE #{p}phoenix_kit_orders DROP COLUMN IF EXISTS exchange_rate",
      "ALTER TABLE #{p}phoenix_kit_orders DROP COLUMN IF EXISTS base_total",
      "COMMENT ON TABLE #{p}phoenix_kit IS '184'"
    ]
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
