defmodule PhoenixKit.Migrations.Postgres.ShopSlugProjection do
  @moduledoc """
  The DDL for the shop slug projection tables, owned here so V171 and any
  future repair path build the SAME objects from one definition.

  ## What the projection is

  `phoenix_kit_shop_products.slug` and `phoenix_kit_shop_categories.slug` are
  jsonb maps of language → slug. The V52-era uniqueness story was an
  expression index on `extract_primary_slug(slug)` — the alphabetically-first
  key's value — which simultaneously under- and over-enforced:

    * **under**: only the primary language was constrained at all, so
      `{"en":"hat"}` and `{"de":"hut","en":"hat"}` coexisted sharing `en=hat`,
      and the collision surfaced on whichever save later ADDED a translation —
      far from the create that caused it;
    * **over**: `{"en":"hat"}` and `{"de":"hat"}` collided on the bare value
      `hat` even though they can never shadow each other in a URL.

  The correct bucket is **(base language, value)** — base, because the
  resolver expands a requested language over its spellings (`"en"`,
  `"en-US"`, …), so spellings must share one bucket. Each parent row's slug
  map is projected into `phoenix_kit_shop_{product,category}_slugs` rows
  `(lang, value, owner uuid)` by an AFTER trigger, and the projection's
  primary key IS the uniqueness constraint. Empty values are never projected
  (an unromanizable title yields no slug, not an empty one).

  Ecto's `unique_constraint` in `phoenix_kit_ecommerce` names the projection
  pkeys, so a collision comes back as a changeset error on `:slug` rather
  than a raw `Postgrex.Error` — the first time that has been true for these
  tables.
  """

  @doc "The two parents and their projections, in creation order."
  def specs do
    [
      %{
        parent: "phoenix_kit_shop_products",
        projection: "phoenix_kit_shop_product_slugs",
        owner_column: "product_uuid",
        trigger_fn: "sync_shop_product_slugs",
        trigger: "trg_shop_product_slugs",
        # A draft has no public URL; an active product does. Used by the
        # V171 dedup to decide who keeps a colliding slug.
        live_statuses: "('active')"
      },
      %{
        parent: "phoenix_kit_shop_categories",
        projection: "phoenix_kit_shop_category_slugs",
        owner_column: "category_uuid",
        trigger_fn: "sync_shop_category_slugs",
        trigger: "trg_shop_category_slugs",
        # Unlisted categories are URL-reachable, so they count as live.
        live_statuses: "('active', 'unlisted')"
      }
    ]
  end

  @doc """
  DDL creating one projection: table, sync function, trigger, backfill.

  Idempotent (`IF NOT EXISTS` / `CREATE OR REPLACE` / `ON CONFLICT DO
  NOTHING`), so a repair can re-run it over a half-built state.
  """
  def up_sql(%{} = spec, p) do
    [
      """
      CREATE TABLE IF NOT EXISTS #{p}#{spec.projection} (
        lang text NOT NULL,
        value text NOT NULL,
        #{spec.owner_column} uuid NOT NULL
          REFERENCES #{p}#{spec.parent}(uuid) ON DELETE CASCADE,
        PRIMARY KEY (lang, value)
      )
      """,
      # Per-owner lookups (the CASCADE path, and "all slugs of this product").
      """
      CREATE INDEX IF NOT EXISTS #{spec.projection}_#{spec.owner_column}_idx
        ON #{p}#{spec.projection} (#{spec.owner_column})
      """,
      # Delete-then-insert rather than diffing: a slug map is small, and the
      # rewrite keeps the function immune to key renames and removals.
      # Spellings fold to their base language (en-US -> en) because the
      # resolver treats spellings as one bucket; DISTINCT absorbs a row
      # carrying two spellings of one language with the same value.
      """
      CREATE OR REPLACE FUNCTION #{p}#{spec.trigger_fn}() RETURNS trigger
      LANGUAGE plpgsql AS $$
      BEGIN
        DELETE FROM #{p}#{spec.projection} WHERE #{spec.owner_column} = NEW.uuid;

        INSERT INTO #{p}#{spec.projection} (lang, value, #{spec.owner_column})
        SELECT DISTINCT lower(split_part(e.key, '-', 1)), e.value, NEW.uuid
          FROM jsonb_each_text(COALESCE(NEW.slug, '{}'::jsonb)) e
         WHERE e.value <> '';

        RETURN NEW;
      END $$
      """,
      "DROP TRIGGER IF EXISTS #{spec.trigger} ON #{p}#{spec.parent}",
      """
      CREATE TRIGGER #{spec.trigger}
        AFTER INSERT OR UPDATE OF slug ON #{p}#{spec.parent}
        FOR EACH ROW EXECUTE FUNCTION #{p}#{spec.trigger_fn}()
      """,
      # Existing rows, projected once. Runs after the V171 dedup, so the
      # primary key cannot conflict; ON CONFLICT guards a repair re-run.
      """
      INSERT INTO #{p}#{spec.projection} (lang, value, #{spec.owner_column})
      SELECT DISTINCT lower(split_part(e.key, '-', 1)), e.value, t.uuid
        FROM #{p}#{spec.parent} t,
             jsonb_each_text(COALESCE(t.slug, '{}'::jsonb)) e
       WHERE e.value <> ''
      ON CONFLICT (lang, value) DO NOTHING
      """
    ]
  end

  @doc "Removes one projection: trigger, function, table."
  def down_sql(%{} = spec, p) do
    [
      "DROP TRIGGER IF EXISTS #{spec.trigger} ON #{p}#{spec.parent}",
      "DROP FUNCTION IF EXISTS #{p}#{spec.trigger_fn}()",
      "DROP TABLE IF EXISTS #{p}#{spec.projection}"
    ]
  end

  @doc """
  The V171 dedup for one parent table, as a single `DO` block.

  Buckets every jsonb slug entry by (base language, value), counting **owner
  rows, not entries**: one row carrying two spellings of a language at the
  same value (`{"en":"hat","en-GB":"hat"}`) projects — via the trigger's
  `SELECT DISTINCT` — to a single projection row, so it is not a collision
  and must be left alone. Counting entries instead made it one: an active
  product in that shape aborted the upgrade with "shared by 2 live rows",
  and a draft one had a spelling silently rewritten to `hat-2`, changing a
  live URL to satisfy a constraint that was never in danger.

  Two LIVE rows in one bucket RAISE — one of them must lose a working public
  URL, and that is an editorial decision, not an unattended upgrade's (V167
  precedent: refuse, and name the value). Otherwise the keeper is live first,
  then oldest `inserted_at`, then uuid — `timestamps()` stores whole seconds,
  so ties are ordinary — and every later row is rewritten in place to
  `value-2`, `value-3`, … probing the WHOLE table so an unrelated `hat-2`
  pushes the suffix to `hat-3` (`Slug.ensure_unique/2`'s rule, applied in
  SQL). A losing row's spellings move together, to the one candidate: they
  share the bucket, so splitting them would invent a second URL.

  Parameterized by table name so the integration tests can drive the same
  SQL against a scratch clone and manufacture the duplicates a current
  install can no longer produce.
  """
  def dedupe_sql(table, live_statuses, p) do
    """
    DO $$
    DECLARE
      g RECORD;
      r RECORD;
      k text;
      candidate text;
      n int;
    BEGIN
      FOR g IN
        SELECT lower(split_part(e.key, '-', 1)) AS lang,
               e.value AS val,
               count(DISTINCT t.uuid) FILTER (WHERE t.status IN #{live_statuses}) AS live_n
          FROM #{p}#{table} t,
               jsonb_each_text(COALESCE(t.slug, '{}'::jsonb)) e
         WHERE e.value <> ''
         GROUP BY 1, 2
        HAVING count(DISTINCT t.uuid) > 1
      LOOP
        IF g.live_n > 1 THEN
          RAISE EXCEPTION
            'Cannot apply V171: slug "%" (%) is shared by % live rows in #{table}. Give one of them a different slug, then upgrade.',
            g.val, g.lang, g.live_n;
        END IF;
      END LOOP;

      FOR r IN
        SELECT * FROM (
          SELECT owned.uuid,
                 owned.lang,
                 owned.value,
                 owned.keys,
                 row_number() OVER (
                   PARTITION BY owned.lang, owned.value
                   ORDER BY owned.live_rank,
                            owned.inserted_at ASC,
                            owned.uuid ASC) AS rn
            FROM (
              -- One row per (owner, bucket): every spelling the owner spends
              -- on this bucket, collected so they can move together.
              SELECT t.uuid,
                     lower(split_part(e.key, '-', 1)) AS lang,
                     e.value AS value,
                     array_agg(e.key) AS keys,
                     CASE WHEN t.status IN #{live_statuses} THEN 0 ELSE 1 END AS live_rank,
                     t.inserted_at
                FROM #{p}#{table} t,
                     jsonb_each_text(COALESCE(t.slug, '{}'::jsonb)) e
               WHERE e.value <> ''
               GROUP BY t.uuid,
                        lower(split_part(e.key, '-', 1)),
                        e.value,
                        CASE WHEN t.status IN #{live_statuses} THEN 0 ELSE 1 END,
                        t.inserted_at
            ) owned) ranked
         WHERE rn > 1
         ORDER BY lang, value, rn
      LOOP
        n := 2;

        LOOP
          candidate := r.value || '-' || n;

          EXIT WHEN NOT EXISTS (
            SELECT 1
              FROM #{p}#{table} t2,
                   jsonb_each_text(COALESCE(t2.slug, '{}'::jsonb)) e2
             WHERE lower(split_part(e2.key, '-', 1)) = r.lang
               AND e2.value = candidate);

          n := n + 1;
        END LOOP;

        RAISE NOTICE 'V171: #{table} % slug % % -> %', r.uuid, r.keys, r.value, candidate;

        FOREACH k IN ARRAY r.keys LOOP
          UPDATE #{p}#{table}
             SET slug = jsonb_set(slug, ARRAY[k], to_jsonb(candidate))
           WHERE uuid = r.uuid;
        END LOOP;
      END LOOP;
    END $$;
    """
  end
end
