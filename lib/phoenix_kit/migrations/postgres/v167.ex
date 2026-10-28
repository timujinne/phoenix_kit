defmodule PhoenixKit.Migrations.Postgres.V167 do
  @moduledoc """
  V167: post slugs are unique, and the index finally says so.

  ## The gap

  `phoenix_kit_posts.slug` has carried a plain btree since V135, while its
  sibling `phoenix_kit_post_tags.slug` has been unique the whole time. Two
  things downstream assume the uniqueness that was never enforced:
  `PhoenixKitPosts.Post` declares `unique_constraint(:slug)`, which had no
  index to translate and so could never fire, and `get_post_by_slug/2` fetches
  with `repo().one()` — which raises `Ecto.MultipleResultsError` the moment two
  rows share a slug. A duplicate therefore did not degrade that URL, it broke
  it, and the error surfaced far from the save that caused it.

  Nothing was stopping duplicates either: two posts titled the same slugified
  identically and both were written. That generation gap is fixed in
  `phoenix_kit_posts` (it now calls `PhoenixKit.Utils.Slug.ensure_unique/2`),
  but that check is advisory — it probes, then writes, and it falls back to the
  unsuffixed slug if the repo is unreachable. Only this index closes it.

  ## Renaming rows, and the line this will not cross

  Existing installs may already hold duplicates, and a unique index cannot be
  created over them. Extras are suffixed `-2`, `-3` … until free, which is the
  same rule `Slug.ensure_unique/2` applies at runtime — so the repair produces
  exactly what the application would have, and is auditable against it.

  Renaming a slug moves a URL, so the keeper is chosen to make that as
  survivable as possible: a publicly reachable post outranks a draft, then the
  oldest wins, then uuid breaks the tie. `timestamps(type: :utc_datetime)`
  stores whole seconds with no DB default, so ties are ordinary rather than
  theoretical, and without the uuid the choice would be arbitrary per run.

  **Two live posts sharing a slug raises instead.** One of them has to lose a
  working public URL, and which one is an editorial decision that belongs to
  whoever runs the site — not to an upgrade running unattended. V161 sets the
  precedent: refuse, and name the value. Drafts are suffixed silently because
  a draft has no URL anyone can have linked.

  ## Why `IF NOT EXISTS` is not enough on its own

  `CREATE UNIQUE INDEX IF NOT EXISTS` matches on the index NAME only. Against
  the existing non-unique `phoenix_kit_posts_slug_index` it emits "relation
  already exists, skipping" and leaves it non-unique — duplicates keep
  inserting, and the migration reports success. Verified against PostgreSQL 17.
  The explicit `DROP` below is load-bearing, not tidiness.

  The name is kept deliberately. `Post` declares a bare
  `unique_constraint(:slug)`, so Ecto infers `phoenix_kit_posts_slug_index`;
  renaming the index would silently stop that constraint translating and turn
  a friendly validation error back into a raw `Postgrex.Error`.

  No `CONCURRENTLY`. It is *available* — the wrappers this chain runs under are
  generated with `@disable_ddl_transaction true` (see
  `PhoenixKit.Migrations.Postgres`, the note above the advisory lock), so there
  is no enclosing transaction to forbid it — but a failed build leaves an
  **INVALID** index that the `IF NOT EXISTS` above then matches by name, turning
  the next run into a silent no-op over an unenforced constraint. V168's
  "Why not CONCURRENTLY" carries the full reasoning;
  `v163_uuid_integrity_test.exs` asserts the chain never emits it.

  `phoenix_kit_post_groups` is deliberately untouched — its schema declares a
  composite `[:user_uuid, :slug]` constraint, so a global unique would be
  wrong there, and it is a separate missing index.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '167'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '166'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
