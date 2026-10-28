defmodule PhoenixKit.Migrations.Postgres.V171 do
  @moduledoc """
  V171: shop slugs become unique per (base language, value).

  ## The gap

  Product and category slugs are jsonb maps of language → slug, and the only
  uniqueness the database enforced since V52 was an expression index on
  `extract_primary_slug(slug)` — the alphabetically-first key's value. That
  bucket is wrong in both directions:

    * **under-enforced**: only the primary language was constrained, so
      `{"en":"hat"}` and `{"de":"hut","en":"hat"}` coexisted sharing
      `en=hat`, and the collision surfaced on whichever save later ADDED a
      translation — an error on "add translation", far from "create product";
    * **over-enforced**: `{"en":"hat"}` and `{"de":"hat"}` collided on the
      bare value even though a URL request always carries a language and the
      two can never shadow each other.

  The resolver expands a requested language over its spellings ("en",
  "en-US", …), so the correct bucket is **(base language, value)** — exactly
  what `PhoenixKit.Migrations.Postgres.ShopSlugProjection` builds: a
  trigger-maintained projection table per parent whose PRIMARY KEY is the
  constraint. Its moduledoc carries the full design; this migration is
  dedup → build → drop the old indexes.

  ## Renaming rows, and the line this will not cross

  Existing installs may hold rows that collide in the new bucket, and the
  projection's primary key cannot be built over them. Extras are suffixed
  `-2`, `-3` … by `Slug.ensure_unique/2`'s rule (keeper: live > oldest >
  uuid). **Two live rows sharing a bucket raise instead** — one of them must
  lose a working public URL, and that is the operator's call, not an
  unattended upgrade's (V167 precedent: refuse, and name the value).

  ## `extract_primary_slug` stays

  No Elixir code calls it; the two indexes were its only consumers. Dropping
  a function other installs' catalogs still carry is manifest churn for no
  gain — it simply becomes unused (the V169 treatment for the old indexes
  themselves: `presence: :legacy_optional` in the manifest, `create: nil`).

  ## down/1 is lossy, and may refuse

  The suffixed slugs are not restored (nothing records the originals —
  V151/V167 precedent), and recreating the old UNIQUE primary-slug indexes
  can FAIL outright: data legitimate under V171 — `{"en":"hat"}` alongside
  `{"de":"hat"}` — collides in the old bucket. That refusal is honest; an
  operator rolling back must first undo whatever cross-language pairs were
  created under the new contract.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '171'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '170'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
