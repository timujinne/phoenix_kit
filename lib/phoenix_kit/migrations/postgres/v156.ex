defmodule PhoenixKit.Migrations.Postgres.V156 do
  @moduledoc """
  V156: Migrates legacy newsletters lists into CRM contact lists (spec
  §4.5), then drops the newsletters-owned list tables entirely.

  > #### Requires a coordinated release with the newsletters module {: .warning}
  >
  > `phoenix_kit_newsletters_lists` / `..._list_members` and
  > `phoenix_kit_newsletters_broadcasts.list_uuid` are read directly by
  > the newsletters package's `List`/`ListMember` schemas and its
  > `"newsletters_list"` broadcast source path. This migration drops all
  > three. A host app running V156 with an OLDER newsletters release
  > (one that still reads them) breaks outright. The newsletters release
  > that removes that code path ships separately, after this migration —
  > do not deploy V156 alone.

  ## Why the data migration lives in this schema migration, not a
  ## separate mix task

  Every table involved — both newsletters' own and CRM's — is defined by
  CORE's migrations already (CRM's tables since V152/V138), regardless
  of whether the CRM module is actually installed in a given host app.
  So there is always somewhere for this data to go, and core moving its
  own data between its own tables, atomically with the DDL that
  retires the source tables, is the same shape V152's "send profiles
  move to core Email" section already used (copy rows by `uuid`, drop
  the source table, same migration). A separate required-but-easy-to-
  forget mix task, with the DDL raising mid-`phoenix_kit.update` if
  skipped, is a strictly worse failure mode for an upgrade path that is
  otherwise a single non-interactive command.

  ## Section 1+2: `phoenix_kit_newsletters_lists`/`..._list_members` →
  ## `phoenix_kit_crm_lists`/`..._crm_list_members`

  One pass, four steps, run only while the legacy tables still exist
  (see `table_exists?/3` — makes the whole data phase a no-op on a
  second `up/1` run after the first one already dropped them):

    1. **Lists** — one `phoenix_kit_crm_lists` row per legacy list,
       `name`/`slug`/`description` copied verbatim; `status` through a
       fail-closed CASE (`'active'` stays, anything else — including a
       stray out-of-vocabulary value the un-CHECKed legacy column could
       hold — becomes `'archived'`, since the CRM column's V152 CHECK
       would otherwise abort the whole INSERT), NOT
       copied by `uuid` (unlike the V152 send-profiles precedent) — a
       fresh CRM-side `uuid` avoids relying on cross-table PK reuse. Slug
       is the idempotency key: `WHERE NOT EXISTS (... WHERE cl.slug =
       l.slug)`, so a CRM list already using this slug (created
       independently, before this migration ever ran) is reused rather
       than duplicated. Created `subscribable = true` — every migrated
       list had real subscribers under the old system, so it stays
       visible/manageable via the CRM module's preference center rather
       than silently becoming inert bookkeeping.

    2. **Contacts** — a `phoenix_kit_crm_contacts` row per distinct user
       referenced by a legacy membership, skipped only when a same-email
       contact already exists that this user can end up attached to
       (unlinked, or linked to this very user). A same-email contact
       linked to a DIFFERENT user does not suppress creation — see the
       comment on `create_contacts_for_migrating_users/1` for why that
       carve-out is what keeps such a user's memberships from being
       silently dropped. `name` falls back through first+last name, then
       the email itself. **Guard, load-bearing:** user linking is a
       straight `UPDATE ... SET user_uuid = u.uuid ... WHERE
       c.user_uuid IS NULL` against `phoenix_kit_users` — reading an
       EXISTING user row, never creating one. `phoenix_kit_crm_contacts`
       has no `connect_user`-equivalent DDL path and never will; the
       "mint a placeholder user for an unrecognized email" behavior
       lives entirely in `PhoenixKitCRM.Contacts.connect_user/2`
       (application code, no SQL at all), so it is structurally
       unreachable from this migration regardless of intent. The link
       UPDATE also picks at most one unlinked same-email contact per
       user (`ORDER BY inserted_at, uuid LIMIT 1` via a correlated
       subquery, not a bare multi-row join) — `idx_crm_contacts_user_uuid`
       is a unique partial index (at most one contact per user), and a
       naive join could try to set the same `user_uuid` onto two
       pre-existing duplicate-email contacts at once and fail the whole
       statement on that constraint.

    3. **Memberships** — one `phoenix_kit_crm_list_members` row per
       legacy membership, joined lists→contacts by the same keys the
       two steps above just established (`slug`, then `user_uuid`).
       Status maps `'active'` → `'subscribed'`, `'unsubscribed'` →
       `'removed'` (the two schemas do NOT share membership-status
       vocabulary — CRM's is `subscribed`/`pending`/`removed`); an
       unrecognized legacy status (there is no DB CHECK backing
       `phoenix_kit_newsletters_list_members.status`, only an Ecto
       validation, so a stray value is possible in principle) maps to
       `'removed'` rather than `'subscribed'` — a migration defect
       should fail closed (nobody wrongly receives mail) not open.
       `subscribed_at`/`unsubscribed_at` copied verbatim — this is the
       one property spec §4.5 is explicit about preserving, and the
       reason this INSERT can't go through
       `PhoenixKitCRM.Lists.add_contact_to_list/3` even conceptually:
       that context function always stamps `subscribed_at: now()`, which
       would be actively wrong here. `source = 'import'`.
       `ON CONFLICT DO NOTHING` (no target list — covers both
       `idx_crm_list_members_list_contact` and
       `idx_crm_list_members_list_email`, either of which a
       pre-existing CRM list could already legitimately hold).

    4. **Recount** — `phoenix_kit_crm_lists.subscriber_count` is a
       maintained cache (see V152), not derived at query time; a bulk
       INSERT bypasses whatever incremental bump the ordinary
       membership-add path performs, so it's set here by a direct
       recount over what was actually inserted (mirrors
       `PhoenixKitCRM.Lists.recount_list/1`'s own repair-by-recount
       approach, just for every migrated list in one statement instead
       of one list at a time).

  ## Section 3: re-point broadcasts, then drop the FK + column

  Every broadcast still at `source_type = 'newsletters_list'` whose
  `list_uuid` matches a list migrated above is flipped to `source_type =
  'crm_list'` with `crm_list_uuid` set to the matching CRM list — the
  exact re-pointing the restructuring plan's `crm_list` source type
  (V152) exists to receive. Real column names confirmed against
  `phoenix_kit_newsletters_broadcasts` directly (not assumed): this
  chain added `source_type`/`crm_list_uuid` in V152, and dropped
  `list_uuid`'s `NOT NULL` in the same version — see that migration's
  "Section: broadcasts can source recipients from a CRM list".

  **Orphan guard.** `list_uuid` carries `fk_newsletters_broadcasts_list`
  — `ON DELETE RESTRICT` (V79) — so under normal operation every
  non-null `list_uuid` on a broadcast is guaranteed to match a row in
  `phoenix_kit_newsletters_lists`, which step 1 above migrates
  unconditionally; the re-point should therefore never fail to find a
  match. Defended anyway, cheaply: any broadcast still at
  `source_type = 'newsletters_list'` with a non-null `list_uuid` after
  the re-point UPDATE (should be none, but "should" isn't a database
  constraint) gets that `list_uuid` preserved into
  `source_params->>'legacy_list_uuid'` before the column carrying it is
  dropped a moment later — the alternative is losing the only clue to
  what a corrupted-even-before-this-migration broadcast used to target,
  for the cost of one extra guarded UPDATE.

  The FK, its supporting index (`idx_newsletters_broadcasts_list`, V79),
  and the `list_uuid` column itself are then dropped — this is the step
  that makes dropping `phoenix_kit_newsletters_lists` in section 4
  possible at all; `ON DELETE RESTRICT` means the table can't be
  dropped while anything still references it.

  ## Section 4: drop the legacy tables

  `phoenix_kit_newsletters_list_members` first (it holds the FK
  *to* `phoenix_kit_newsletters_lists`), then
  `phoenix_kit_newsletters_lists`. `CASCADE` on both, matching this
  chain's existing drop-table precedent (V145, V152) — belt-and-braces
  against any dependent object this migration didn't anticipate; by this
  point section 3 has already removed the one FK from outside these two
  tables that referenced them (`fk_newsletters_broadcasts_list`), so
  `CASCADE` isn't expected to drop anything beyond the two tables'
  own indexes.

  ## down/1

  Restores STRUCTURE only, in reverse order (recreate the two tables
  first — the FK restored next needs somewhere to point), never DATA —
  consistent with V152/V155's own down/1 precedent for a destructive
  section (see V155's moduledoc on `crm_contact_uuid`): the migrated
  rows already live in `phoenix_kit_crm_lists`/`..._crm_list_members`
  and are not copied back, the newly-empty
  `phoenix_kit_newsletters_lists`/`..._list_members` tables come back
  empty, and any broadcast this version re-pointed to `crm_list` stays
  re-pointed (source_type/crm_list_uuid are untouched by down/1). This
  chain's rollback story has never guaranteed data survives a down/up
  cycle across a version that intentionally discards or relocates rows
  (V145's send-profile predecessor didn't either); it guarantees the
  SCHEMA is usable again, which is what every downstream migration in
  the chain actually depends on.

  `list_uuid` is restored nullable (matching the state V152 already put
  it in — this section does not attempt to reconstruct which broadcasts
  used to be NOT NULL-eligible) with its FK and index; the two legacy
  tables are recreated exactly as V79 defined them (confirmed unchanged
  in the live schema through V155 — no migration between V79 and V155
  touches either table's columns).

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '156'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '155'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
