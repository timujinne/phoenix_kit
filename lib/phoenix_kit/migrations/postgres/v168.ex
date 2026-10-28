defmodule PhoenixKit.Migrations.Postgres.V168 do
  @moduledoc """
  V168: the two remaining slug `unique_constraint/3` declarations get an index.

  ## The gap

  V167 did this for `phoenix_kit_posts`. An audit of every schema that declares a
  slug `unique_constraint/3` found exactly two more where the constraint has nothing
  to translate, and six where it is already backed correctly
  (`phoenix_kit_doc_templates_slug_index`, `phoenix_kit_ai_prompts_slug_uidx`,
  `phoenix_kit_bookings_services_slug_index`,
  `phoenix_kit_shop_shipping_methods_slug_unique`, `idx_publishing_groups_slug`,
  `phoenix_kit_post_tags_slug_index`). This migration is the whole remainder, not a
  sample of it.

    * **`phoenix_kit_tickets`** carries a plain btree from V135
      (`v135.ex:2842`), while `PhoenixKitCustomerSupport.Ticket` declares
      `unique_constraint(:slug)` (`ticket.ex:173`) and `get_ticket_by_slug/2`
      fetches with `repo().one()` — which raises `Ecto.MultipleResultsError`, not a
      changeset error, the moment two tickets share a slug.

    * **`phoenix_kit_post_groups`** has no slug index of any kind. Its schema
      declares a COMPOSITE `unique_constraint([:user_uuid, :slug], name:
      :phoenix_kit_post_groups_user_uuid_slug_index)` (`post_group.ex:141`) naming an
      index that exists nowhere, so a user can hold two groups on one slug and
      `unique_constraint` never fires.

  ## Scoped, not global

  Post-group slugs are unique **per user**, so the index is on `(user_uuid, slug)`
  and the dedup partitions by the pair. A global unique here would reject one user
  taking a slug another user already has, which is not what the schema asks for and
  would break existing data.

  ## Why the dedup runs first

  `CREATE UNIQUE INDEX` fails outright on existing duplicates, so the rows are
  repaired before the index is built. Tickets are unlikely to have duplicates in
  practice — `ticket.ex:250` appends a millisecond-derived timestamp to every
  generated slug — but "unlikely" is not a thing to bet a migration on, and that same
  timestamp is being deleted by the changeset work this migration accompanies.

  ## Why tickets rename silently where V167 refused

  V167 raises when two *live* posts share a slug; this migration suffixes duplicate
  ticket slugs without asking. That is deliberate, not drift. A duplicated slug means
  `get_ticket_by_slug/2` raises `Ecto.MultipleResultsError` on **every** request for
  it — both tickets' URLs are already broken — so renaming the newer one strictly
  improves things: the older URL starts working again and the newer ticket gets a
  slug that resolves. Refusing would block the whole upgrade to ask an operator about
  a URL that is already dead. Posts earned the refusal because *which* post keeps a
  slug is an editorial and SEO identity question; between two support tickets,
  oldest-wins has no second defensible answer.

  ## Why not CONCURRENTLY

  It is *available* — the wrappers this chain runs under are generated with
  `@disable_ddl_transaction true` (see `PhoenixKit.Migrations.Postgres`, the note
  above the advisory lock), so there is no enclosing transaction to forbid it. It is
  still the wrong choice here:

    * A failed `CREATE UNIQUE INDEX CONCURRENTLY` leaves an **INVALID** index behind
      rather than nothing. `IF NOT EXISTS` then matches it **by name**, so the next
      run is a silent no-op that stamps the bug as fixed while uniqueness is still
      unenforced — the exact trap V167's moduledoc documents for the non-concurrent
      case, made worse by leaving a plausible-looking index in `\\di`.
    * It cannot run inside the `DO $$` block the dedup needs, so the two halves could
      not be kept adjacent.

  A bounded `lock_timeout` is the V163/V167 answer to the lock this takes: fail loudly
  and quickly rather than hang unattended behind a long read.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '168'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '167'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
