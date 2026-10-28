defmodule PhoenixKit.Migrations.Postgres.V155 do
  @moduledoc """
  V155: `phoenix_kit_newsletters_deliveries` gains a CRM contact identifier
  and DB-level per-broadcast dedup.

  ## Section: `crm_contact_uuid`

  Adds a bare, nullable `crm_contact_uuid UUID` column — a soft reference
  the same way `phoenix_kit_newsletters_broadcasts.crm_list_uuid` (V152)
  already is: no FK, because newsletters must not hard-depend on the CRM
  module being installed. A plain (non-partial) index backs it, at the
  caller's request — every other soft-ref uuid column added so far in
  this chain (`crm_list_uuid`, `send_profile_uuid`) uses a partial index
  instead, but a plain index is a strict superset of what a partial one
  covers here and the column stays small, so there's no reason to special
  case this one.

  ## Section: recipient-check CHECK — widened, not XOR'd

  V152 added `phoenix_kit_newsletters_deliveries_recipient_check`, `CHECK
  (user_uuid IS NOT NULL OR recipient_email IS NOT NULL)` — "somebody is
  addressable." This section replaces it (same name, so nothing downstream
  needs to know it changed) with two conditions:

    1. The original addressability requirement, unchanged.
    2. `NOT (user_uuid IS NOT NULL AND crm_contact_uuid IS NOT NULL)` — a
       delivery is never claimed by both a core `User` and a CRM contact
       at once.

  **Deliberate deviation from the letter of the restructuring spec (§7):**
  the spec's shorthand describes this as a strict XOR between `user_uuid`
  and `crm_contact_uuid` (`CHECK ((user_uuid IS NULL) <> (crm_contact_uuid
  IS NULL))`) — i.e. every delivery row is required to have *exactly one*
  of the two owners. This migration does **not** enforce that: every
  CRM-sourced delivery in production today has both `user_uuid` and
  `crm_contact_uuid` NULL (it's addressed by `recipient_email` alone —
  `crm_contact_uuid` is new as of this migration and nothing backfills it
  onto existing rows), and a strict XOR would reject exactly the shape
  `Broadcaster`'s existing crm_list send path produces. Retrofitting a
  heuristic email-based backfill of `crm_contact_uuid` onto historical
  deliveries is not required by anything in scope here and is skipped —
  the two-condition CHECK above is the accurate constraint for what this
  migration actually guarantees: *addressable* (original clause) *and
  not double-claimed* (new clause), which is what "mutual exclusion"
  buys without requiring every row to positively identify a CRM contact.

  ## Section: per-broadcast dedup indexes

  Three partial unique indexes — the first DB-level, per-broadcast
  duplicate guard `phoenix_kit_newsletters_deliveries` has ever had.
  Before this, `insert_all` in `Broadcaster.process_batch/5` had no
  `ON CONFLICT` at all (see newsletters `broadcaster.ex`); the only
  existing dedup is Oban's `unique` on `delivery_uuid`
  (`delivery_worker.ex`), which guards the *job*, not the row a second
  enqueue of the same broadcast would insert:

    * `UNIQUE (broadcast_uuid, user_uuid) WHERE user_uuid IS NOT NULL`
    * `UNIQUE (broadcast_uuid, crm_contact_uuid) WHERE crm_contact_uuid
      IS NOT NULL`
    * `UNIQUE (broadcast_uuid, recipient_email) WHERE recipient_email IS
      NOT NULL` — the address-level index; the only one of the three that
      also stops the same broadcast reaching one mailbox twice through
      two different CRM contacts that happen to share it.

  All three partial (`WHERE ... IS NOT NULL`) — a delivery only ever
  populates the identifier matching its recipient source, so the other
  two columns are NULL on that row and must not participate in the
  uniqueness check (Postgres already excludes NULLs from a plain unique
  index, but partial makes the "only when populated" intent explicit and
  keeps the index smaller).

  Checked directly against the dev database before writing this migration
  (`phoenix_kit_newsletters_deliveries`, 14 rows / 4 broadcasts at the
  time): no existing `(broadcast_uuid, user_uuid)` or `(broadcast_uuid,
  recipient_email)` duplicates, so all three indexes create cleanly with
  no pre-migration cleanup needed.

  ## Section: `source_params` for the user_group recipient source

  Adds `source_params JSONB NOT NULL DEFAULT '{}'` to
  `phoenix_kit_newsletters_broadcasts`, for Stage 4's third recipient
  source (spec §1/§7): `source_type = "user_group"` targets core users
  by role rather than a CRM list or the newsletters list. Roles are a
  *set* (a broadcast can target more than one), unlike the scalar
  `crm_list_uuid`/`list_uuid` the other two sources already have — so
  this is a JSONB bag rather than another single soft-ref uuid column.
  Shape the newsletters-side resolver reads/writes:
  `%{"role_uuids" => [...], "role_names_snapshot" => [...]}`.

  **Uuids, not names, are what gets resolved** — a role's `name` is
  mutable (`Roles.update_role/2` doesn't protect it, not even for
  system roles), so storing names would let a rename silently re-target
  (or empty out) an already-saved broadcast with no signal anywhere.
  `role_names_snapshot` exists purely so the UI can still show what a
  broadcast targeted after a role is later renamed or deleted — same
  precedent as `recipient_email`/`supplier_name_snapshot` elsewhere in
  this chain. Same flexible-JSONB convention as `crm_lists.metadata`/
  `crm_list_members.metadata`: Ecto-validated, no DB CHECK on its
  contents (and none on the `role_uuids`/`role_names_snapshot` shape
  either — that contract lives entirely on the newsletters side, in
  `Broadcast.role_uuids/1`/`role_names_snapshot/1`).

  `source_type`'s own three-value enum (`newsletters_list`/`crm_list`/
  `user_group`) stays Ecto-only, unchanged from V152's convention for
  that column (v152.ex's "Section: broadcasts can source recipients
  from a CRM list").

  ## down/1

  Unwinds in reverse: drops the three unique indexes, restores the V152
  CHECK (single-clause, no `crm_contact_uuid` term), then drops the
  `crm_contact_uuid` index and column. Non-lossy **relative to the
  original V152 schema** — this migration adds no backfill, so nothing
  it creates is derived from data that predates it. That is not the same
  as "safe to run at any time": once the newsletters module (which
  writes `crm_contact_uuid` on every CRM-sourced delivery — see
  `phoenix_kit_newsletters`'s `Broadcaster`) has actually sent anything,
  the column holds real contact references, and `DROP COLUMN` destroys
  them same as any other rollback of a populated column. Because that
  writer lives in a separate package with its own release cycle, V155
  and the newsletters version that depends on it must be rolled back
  **together** — reverting V155 alone while that newsletters release is
  still deployed breaks it outright (its `insert_all` targets a column
  that no longer exists).

  `source_params` is lossy on rollback in the ordinary sense — a
  `user_group` broadcast's role selection is genuinely destroyed, not
  merely orphaned — but it's a UI selection, not delivery-identifying
  history, so this doesn't carry the same "outlives the column" risk
  `crm_contact_uuid` does.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '155'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '154'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
