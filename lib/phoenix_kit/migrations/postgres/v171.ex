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
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.ShopSlugProjection

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Bounded rather than indefinite: the trigger creation takes ACCESS
    # EXCLUSIVE on each parent, and a migration waiting forever behind a long
    # read is a silent hang with nothing printed (V163 precedent).
    execute("SET lock_timeout = '5000ms'")

    for spec <- ShopSlugProjection.specs() do
      execute(ShopSlugProjection.dedupe_sql(spec.parent, spec.live_statuses, p))

      for sql <- ShopSlugProjection.up_sql(spec, p) do
        execute(sql)
      end
    end

    # The old expression indexes are superseded, not replaced in place — the
    # projection pkeys enforce the corrected bucket. Dropped AFTER the
    # projection exists so there is no window with no enforcement at all.
    execute("DROP INDEX IF EXISTS #{p}idx_shop_products_slug_primary")
    execute("DROP INDEX IF EXISTS #{p}idx_shop_categories_slug_primary")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '171'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    for spec <- Enum.reverse(ShopSlugProjection.specs()) do
      for sql <- ShopSlugProjection.down_sql(spec, p) do
        execute(sql)
      end
    end

    # See the moduledoc: these can refuse over data that is legitimate under
    # V171. A refusal here is the correct outcome, not a bug.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_shop_products_slug_primary
      ON #{p}phoenix_kit_shop_products
      USING btree (#{p}extract_primary_slug(slug))
      WHERE (#{p}extract_primary_slug(slug) IS NOT NULL)
    """)

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS idx_shop_categories_slug_primary
      ON #{p}phoenix_kit_shop_categories
      USING btree (#{p}extract_primary_slug(slug))
      WHERE (#{p}extract_primary_slug(slug) IS NOT NULL)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '170'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
