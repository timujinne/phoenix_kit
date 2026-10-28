defmodule PhoenixKit.Migrations.Postgres.V180 do
  @moduledoc """
  V180: the manufacturer↔supplier graph becomes federated, and an item can no
  longer list the same supplier twice.

  ## Block 1 — `phoenix_kit_cat_manufacturer_suppliers` federates

  V179 did this for an item's manufacturer; the M:N graph was the last place
  still forced to point at the catalogue's own directory. It carried hard
  foreign keys onto **both** `phoenix_kit_cat_manufacturers` and
  `phoenix_kit_cat_suppliers`, so a CRM party's uuid physically could not be
  stored — which meant that with suppliers and manufacturers living in CRM the
  graph simply stopped being built, and warehouse's manufacturer-based supplier
  resolution (`supplier_orders.ex`) had nothing to read.

  Same shape as V179 and V149 before it: a uuid plus a `*_source`
  discriminator. The accepted values match
  `phoenix_kit_cat_item_supplier_info.supplier_source` — `'local'`,
  `'crm_company'`, `'crm_contact'` — because a supplier CAN be a contact there
  and a narrower CHECK here would make such a supplier unlinkable. Existing
  rows are all `'local'`, which is what the default backfills.

  ## What replaces the two FKs

  Application-level cleanup, deliberately. The dropped constraints carried
  `ON DELETE CASCADE`, so deleting a local supplier or manufacturer used to
  clear its links for free; `Catalogue.delete_supplier/2` and
  `delete_manufacturer/2` now delete them explicitly. A cascade cannot span an
  optional-module boundary — the CRM tables need not exist — so this is the
  same trade V179 made, and the same one `item_supplier_info.supplier_uuid` has
  lived with since V149.

  ## Block 2 — one CURRENT supplier row per item/supplier pair

  Riding along rather than spending a version number of its own (workspace
  `AGENTS.md`). Nothing stopped two OPEN rows for the same pair, i.e. one item
  listing the same supplier twice with two live prices and no rule about which
  one warehouse should believe.

  The index is **partial on `valid_to IS NULL`**, never the bare pair: several
  rows per pair are legitimate and expected, because that is exactly what a
  price revision produces — the old row is closed and a successor appended.
  Only one may be open.

  Existing duplicates are **closed, not deleted** — they are real price records
  — keeping the primary row, or the oldest when neither is primary, and
  clearing `is_primary` on the ones being closed so the V151
  `..._primary_uniq` index still holds. A loser is closed at
  `GREATEST(valid_from, CURRENT_DATE)` so a future-dated row cannot end before
  it begins, which would leave it failing its own changeset validation
  forever. Without this the `CREATE UNIQUE INDEX`
  would fail outright on any install carrying a duplicate.

  The lock, the dedupe UPDATE, and the index build all live inside one
  `DO $$` block (fixed post-publish, same shape as V170's
  `phoenix_kit_notifications_dedupe_unseen_idx`). A bare top-level
  `LOCK TABLE`, as this originally shipped, gets `25P01
  no_active_sql_transaction` — wrappers carry `@disable_ddl_transaction
  true`, so every top-level `execute/1` auto-commits on its own and `LOCK
  TABLE` has nothing to hold — and even accepted, the lock would release at
  its own commit before the statements it exists to protect. Recovery for an
  install that hit the crash: block 1 already committed and the version
  comment still reads `'179'`, so a plain re-run of `up/1` (or `mix
  ecto.migrate`) completes it — every block-1 statement is
  `IF NOT EXISTS`-guarded.

  ## Rollback

  `down/1` restores both foreign keys and will FAIL if any link references a
  CRM party by then — that uuid has no matching local row, which is the whole
  point of the columns. Repoint or delete those links first. The dedupe is not
  reversed: which rows were closed by this migration is not recorded, and
  re-opening them would recreate the ambiguity on purpose.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '180'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '179'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
