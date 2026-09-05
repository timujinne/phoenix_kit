defmodule PhoenixKit.Migrations.Postgres.V184 do
  @moduledoc """
  V184: removes the `shop_currency` setting seeded by V135.

  Nothing reads it — confirmed by a full grep over `phoenix_kit`,
  `phoenix_kit_billing`, `phoenix_kit_ecommerce`, and a host application: the
  only occurrences of the key are the V135 seed itself and this package's
  `ExpectedSchema` manifest that audits V135's shape. The default currency a
  shop actually uses is the `is_default = true` row of
  `phoenix_kit_currencies`, resolved through
  `PhoenixKitBilling.get_default_currency/0` — and nothing else. A second,
  identically-named "shop currency" that does nothing is exactly the kind of
  trap the next reader falls into, assuming it is the thing that's read.

  ## Why V135 itself is not edited

  The seed is `INSERT ... ON CONFLICT ("key") DO NOTHING`. Every host that has
  already migrated already has the row — deleting the line from V135's text
  changes nothing for them, since a past migration's `execute/1` calls do not
  re-run. It would only change behavior for a brand-new install, which is
  exactly the population that has no problem to fix. Worse, `V135` is a
  released, hashed baseline: editing it changes `ExpectedSchema.chain_hash/0`
  and fails `mix phoenix_kit.release_check` for every host already on this
  version, for a change that helps nobody. The correct place for a removal is
  a new chain version, which is what this migration is.

  ## down/1

  Restores the row with the exact statement V135 seeded it with (copied
  verbatim, including the `ON CONFLICT ("key") DO NOTHING`), so a rollback
  never overwrites a value an operator may have re-created by hand after the
  key was deleted — it only recreates the row if one is not already there.
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

  # Public (and idempotent) so the suite can run the REAL statements against a
  # seeded settings row — `up/1` itself can't be invoked outside an
  # `Ecto.Migrator` runner (same constraint as V182Test and friends), and by
  # the time any test runs, the chain has already deleted the row from an
  # install that starts with no problem to prove. `p` is the rendered prefix
  # including the trailing dot.
  @doc false
  def up_statements(p) do
    [
      "DELETE FROM #{p}phoenix_kit_settings WHERE \"key\" = 'shop_currency'",
      "COMMENT ON TABLE #{p}phoenix_kit IS '184'"
    ]
  end

  @doc false
  def down_statements(p) do
    [
      """
      INSERT INTO #{p}phoenix_kit_settings ("key", "module", "value", "value_json")
      VALUES ('shop_currency', 'shop', 'USD', NULL)
      ON CONFLICT ("key") DO NOTHING
      """,
      "COMMENT ON TABLE #{p}phoenix_kit IS '183'"
    ]
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
