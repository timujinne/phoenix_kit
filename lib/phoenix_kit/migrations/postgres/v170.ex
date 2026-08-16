defmodule PhoenixKit.Migrations.Postgres.V170 do
  @moduledoc """
  V170: index support and a uniqueness backstop for notification collapsing.

  `Notifications.upsert_inapp/3` (added alongside the unseen-first inbox
  ordering) shipped with neither:

    * **The dedupe lookup walked the inbox.** `find_collapsible/2` filters on
      `metadata->>'dedupe_key'` under recipient + unseen, and the only inbox
      index — `(recipient_uuid, inserted_at DESC) WHERE dismissed_at IS NULL`
      (V104, re-created by the V135 squash) — cannot serve either that lookup
      or the new `(seen_at IS NOT NULL, inserted_at DESC, uuid DESC)` ordering,
      so every bell mount and every upsert re-sorted or re-walked a
      recipient's whole undismissed backlog (thousands of rows for a user who
      never dismisses, multiplied by fan-out on the write path).

    * **The find-then-insert had no backstop.** Two concurrent upserts for the
      same absent key (parallel Oban workers, two nodes) both read nil and
      both inserted; the user got two unseen rows for one logical key, pinned
      to the top by the unseen-first ordering, and later refreshes folded into
      only one of them — the stale twin sat there until manually dismissed.

  Two indexes fix both:

    * `phoenix_kit_notifications_dedupe_unseen_idx` — partial UNIQUE on
      `(recipient_uuid, (metadata->>'dedupe_key'))` over undismissed, unseen,
      keyed rows. Serves `find_collapsible/2`'s exact predicate AND turns the
      race's second insert into a constraint violation the code retries as a
      collapse (`Notifications.insert_collapsible/3`). Rows without a dedupe
      key — every notification the fan-out path creates — are outside the
      partial predicate and completely unaffected.

    * `phoenix_kit_notifications_recipient_unseen_first_idx` — on
      `(recipient_uuid, (seen_at IS NOT NULL), inserted_at DESC, uuid DESC)`
      over undismissed rows, matching `order_unseen_first/1`'s ORDER BY
      expression term-for-term so the bell's `recent_for_user` and the inbox
      pages come straight off the index again.

  ## Existing duplicates

  A unique index cannot be created over rows that already violate it, and the
  raced installs are exactly the ones carrying duplicates. Before creating the
  index, all but the newest unseen row per `(recipient, key)` — the same
  "newest wins" choice `find_collapsible/2` makes, `inserted_at` then `uuid`
  (UUIDv7, time-ordered below the timestamp's granularity) — are marked
  **dismissed**. Dismissal, not deletion: the rows and their history remain,
  they simply stop occupying the inbox — which is where the collapsing API
  would have put them had it won the race in the first place.

  The fold and the index creation share one `SHARE ROW EXCLUSIVE` table lock,
  so a concurrent insert cannot re-introduce a duplicate in the gap between
  them and abort the migration.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)
    schema = schema_name(prefix)

    execute("""
    DO $$
    BEGIN
      -- The table guard exists for the same reason every LOCK TABLE in this
      -- chain carries one: LOCK has no IF EXISTS form, and a database that
      -- somehow lacks the table must skip, not abort the whole migration.
      IF EXISTS (
        SELECT 1 FROM pg_class t
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE t.relname = 'phoenix_kit_notifications' AND n.nspname = '#{schema}'
      ) AND NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'phoenix_kit_notifications_dedupe_unseen_idx'
          AND schemaname = '#{schema}'
      ) THEN
        -- Writes blocked (reads fine) from the duplicate fold through index
        -- creation, so no new duplicate can slip into the gap and abort us.
        LOCK TABLE #{p}phoenix_kit_notifications IN SHARE ROW EXCLUSIVE MODE;

        WITH ranked AS (
          SELECT uuid,
                 row_number() OVER (
                   PARTITION BY recipient_uuid, metadata->>'dedupe_key'
                   ORDER BY inserted_at DESC, uuid DESC
                 ) AS rn
          FROM #{p}phoenix_kit_notifications
          WHERE seen_at IS NULL
            AND dismissed_at IS NULL
            AND metadata->>'dedupe_key' IS NOT NULL
        )
        UPDATE #{p}phoenix_kit_notifications n
        SET dismissed_at = now()
        FROM ranked r
        WHERE n.uuid = r.uuid AND r.rn > 1;

        CREATE UNIQUE INDEX phoenix_kit_notifications_dedupe_unseen_idx
        ON #{p}phoenix_kit_notifications (recipient_uuid, (metadata->>'dedupe_key'))
        WHERE seen_at IS NULL
          AND dismissed_at IS NULL
          AND metadata->>'dedupe_key' IS NOT NULL;
      END IF;
    END
    $$
    """)

    execute("""
    CREATE INDEX IF NOT EXISTS phoenix_kit_notifications_recipient_unseen_first_idx
    ON #{p}phoenix_kit_notifications (recipient_uuid, (seen_at IS NOT NULL), inserted_at DESC, uuid DESC)
    WHERE dismissed_at IS NULL
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '170'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    # The duplicate fold is deliberately not undone: the dismissed twins were
    # duplicates the collapsing API would never have created, and nothing
    # records which rows the fold touched versus which the user dismissed.
    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_notifications_recipient_unseen_first_idx")

    execute("DROP INDEX IF EXISTS #{p}phoenix_kit_notifications_dedupe_unseen_idx")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '169'")
  end

  defp schema_name("public"), do: "public"
  defp schema_name(prefix), do: prefix

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
