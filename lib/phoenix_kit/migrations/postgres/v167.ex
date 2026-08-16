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

  No `CONCURRENTLY`: a fresh install runs this chain inside a transaction, and
  `v163_uuid_integrity_test.exs` asserts the chain never emits it.

  `phoenix_kit_post_groups` is deliberately untouched — its schema declares a
  composite `[:user_uuid, :slug]` constraint, so a global unique would be
  wrong there, and it is a separate missing index.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Bounded rather than indefinite: this takes an ACCESS EXCLUSIVE lock to
    # swap the index, and a migration that waits forever behind a long read is
    # a silent hang with nothing printed (V163 precedent).
    execute("SET lock_timeout = '5000ms'")

    execute("""
    DO $$
    DECLARE
      g RECORD;
      r RECORD;
      suffix text;
      base text;
      candidate text;
      n int;
    BEGIN
      -- Refuse before rewriting anything: two reachable posts on one slug is
      -- an editorial call, and this runs unattended.
      FOR g IN
        SELECT slug,
               count(*) FILTER (
                 WHERE status IN ('public', 'unlisted', 'scheduled')) AS live_n
          FROM #{p}phoenix_kit_posts
         GROUP BY slug
        HAVING count(*) > 1
      LOOP
        IF g.live_n > 1 THEN
          RAISE EXCEPTION
            'Cannot apply V167: slug % is shared by % live posts. Give one of them a different slug, then upgrade.',
            g.slug, g.live_n;
        END IF;
      END LOOP;

      FOR r IN
        SELECT uuid, slug FROM (
          SELECT uuid,
                 slug,
                 row_number() OVER (
                   PARTITION BY slug
                   ORDER BY CASE
                              WHEN status IN ('public', 'unlisted', 'scheduled') THEN 0
                              ELSE 1
                            END,
                            inserted_at ASC,
                            uuid ASC) AS rn
            FROM #{p}phoenix_kit_posts) ranked
         WHERE rn > 1
         ORDER BY slug, rn
      LOOP
        n := 2;

        LOOP
          suffix := '-' || n;

          -- slug is varchar(255) and Postgres ERRORS on overflow rather than
          -- truncating, so the base is trimmed to leave room for the suffix.
          -- The trailing-dash strip stops "foo-" || "-2".
          base := regexp_replace(left(r.slug, 255 - length(suffix)), '-+$', '');
          candidate := base || suffix;

          -- Probes every slug, not just this group's, so an unrelated post
          -- already holding "foo-2" pushes this one to "foo-3".
          EXIT WHEN NOT EXISTS (
            SELECT 1 FROM #{p}phoenix_kit_posts WHERE slug = candidate);

          n := n + 1;
        END LOOP;

        RAISE NOTICE 'V167: post % slug % -> %', r.uuid, r.slug, candidate;

        UPDATE #{p}phoenix_kit_posts SET slug = candidate WHERE uuid = r.uuid;
      END LOOP;
    END $$;
    """)

    # See the moduledoc: IF NOT EXISTS matches by name, so without this the
    # CREATE below is a no-op that stamps the bug as fixed.
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_posts_slug_index")

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_posts_slug_index
      ON #{p}phoenix_kit_posts USING btree (slug)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '167'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Lossy, and says so. The index reverts; the slugs this migration
    # suffixed do not, because the rows they were taken from are gone as far
    # as this direction can tell. Restoring them would need the original
    # values, which nothing records (V151 precedent for a one-way repair).
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_posts_slug_index")

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_posts_slug_index
      ON #{p}phoenix_kit_posts USING btree (slug)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '166'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
