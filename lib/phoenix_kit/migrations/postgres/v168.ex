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
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Bounded rather than indefinite: this takes an ACCESS EXCLUSIVE lock to swap the
    # index, and a migration that waits forever behind a long read is a silent hang
    # with nothing printed (V163 precedent).
    execute("SET lock_timeout = '5000ms'")

    dedup_tickets(p)
    dedup_post_groups(p)

    # IF NOT EXISTS matches by NAME, so creating the unique index without dropping the
    # non-unique one of the same name is a no-op that reports success. V167 hit this.
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_tickets_slug_index")

    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_tickets_slug_index
      ON #{p}phoenix_kit_tickets USING btree (slug)
    """)

    # Named exactly as post_group.ex:141 declares it; Ecto matches the constraint to
    # the index by name, so a different name here would leave the bug in place.
    execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_post_groups_user_uuid_slug_index
      ON #{p}phoenix_kit_post_groups USING btree (user_uuid, slug)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '168'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # Lossy, and says so. The indexes revert; the slugs this migration suffixed do
    # not, because nothing records the values they replaced (V151/V167 precedent for
    # a one-way repair).
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_post_groups_user_uuid_slug_index")
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_tickets_slug_index")

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_tickets_slug_index
      ON #{p}phoenix_kit_tickets USING btree (slug)
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '167'")
  end

  # Oldest row keeps the bare slug; every later collision is suffixed -2, -3, … past
  # whatever is already taken, matching `PhoenixKit.Utils.Slug.ensure_unique/2` so a
  # repaired row and a freshly generated one agree on the rule.
  defp dedup_tickets(p) do
    execute("""
    DO $$
    DECLARE
      r RECORD;
      suffix text;
      base text;
      candidate text;
      n int;
    BEGIN
      FOR r IN
        SELECT uuid, slug FROM (
          SELECT uuid,
                 slug,
                 row_number() OVER (
                   PARTITION BY slug
                   ORDER BY inserted_at ASC, uuid ASC) AS rn
            FROM #{p}phoenix_kit_tickets) ranked
         WHERE rn > 1
         ORDER BY slug, rn
      LOOP
        n := 2;

        LOOP
          suffix := '-' || n;

          -- slug is varchar(255) and Postgres ERRORS on overflow rather than
          -- truncating, so the base is trimmed to leave room for the suffix. The
          -- trailing-dash strip stops "foo-" || "-2".
          base := regexp_replace(left(r.slug, 255 - length(suffix)), '-+$', '');
          candidate := base || suffix;

          EXIT WHEN NOT EXISTS (
            SELECT 1 FROM #{p}phoenix_kit_tickets WHERE slug = candidate);

          n := n + 1;
        END LOOP;

        RAISE NOTICE 'V168: ticket % slug % -> %', r.uuid, r.slug, candidate;

        UPDATE #{p}phoenix_kit_tickets SET slug = candidate WHERE uuid = r.uuid;
      END LOOP;
    END $$;
    """)
  end

  # Same rule, partitioned by the OWNER as well as the slug: two users may hold the
  # same slug, so only a repeat within one `user_uuid` is a duplicate. The free-slug
  # probe is scoped to that user for the same reason.
  defp dedup_post_groups(p) do
    execute("""
    DO $$
    DECLARE
      r RECORD;
      suffix text;
      base text;
      candidate text;
      n int;
    BEGIN
      FOR r IN
        SELECT uuid, user_uuid, slug FROM (
          SELECT uuid,
                 user_uuid,
                 slug,
                 row_number() OVER (
                   PARTITION BY user_uuid, slug
                   ORDER BY inserted_at ASC, uuid ASC) AS rn
            FROM #{p}phoenix_kit_post_groups) ranked
         WHERE rn > 1
         ORDER BY user_uuid, slug, rn
      LOOP
        n := 2;

        LOOP
          suffix := '-' || n;
          base := regexp_replace(left(r.slug, 255 - length(suffix)), '-+$', '');
          candidate := base || suffix;

          EXIT WHEN NOT EXISTS (
            SELECT 1 FROM #{p}phoenix_kit_post_groups
             WHERE user_uuid = r.user_uuid AND slug = candidate);

          n := n + 1;
        END LOOP;

        RAISE NOTICE 'V168: post group % (user %) slug % -> %',
          r.uuid, r.user_uuid, r.slug, candidate;

        UPDATE #{p}phoenix_kit_post_groups SET slug = candidate WHERE uuid = r.uuid;
      END LOOP;
    END $$;
    """)
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
