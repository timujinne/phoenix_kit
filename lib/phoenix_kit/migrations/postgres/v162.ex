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

  ## Core 3.0

  Everything this version did belonged to a module's tables and now lives in
  that module's own migration chain (`PhoenixKit.Migrations.ModuleOwnedTables`,
  plan `dev_docs/plans/2026-10-25-module-table-ownership.md`, step 8): core no
  longer creates or changes them. The version is kept so the chain stays
  numbered; it only moves the marker. Hosts below V225 cannot upgrade to this
  release (`BelowFloorError`), so nobody replays what the text above describes.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '162'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '161'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
