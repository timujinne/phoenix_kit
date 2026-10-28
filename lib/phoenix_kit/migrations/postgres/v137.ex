defmodule PhoenixKit.Migrations.Postgres.V137 do
  @moduledoc """
  V137: Email event deduplication indexes + `aws_message_id` backfill, plus
  optional performance indexes for the emails module (`phoenix_kit_emails`).

  ## Event dedup

  The `PhoenixKit.Modules.Emails.Event` schema declares unique constraints that
  the database never enforced (a schema↔DB mismatch). This adds the two partial
  unique indexes that back them, deduping at the DB level — at-least-once SQS
  delivery and racing pollers could previously insert duplicate events:

    - **single-occurrence** types (delivery / bounce / complaint / send / reject /
      delivery_delay / subscription / rendering_failure / queued): one row per
      `(email_log_uuid, event_type)`.
    - **multi-occurrence** types (open / click): one row per
      `(email_log_uuid, event_type, occurred_at)`, so a recipient's repeated
      opens and distinct link clicks are kept while an exact SQS redelivery
      (identical timestamp) is collapsed.

  Pre-existing duplicates are removed first so the unique indexes can be created.
  `phoenix_kit_email_events` has no bigint `id` (dropped in V74); `uuid` is the
  UUIDv7 primary key and is time-ordered, so `MIN(uuid)` per group is the earliest
  row — it is kept, the rest deleted.

  `email_log_uuid` is the canonical FK (NOT NULL, backfilled and FK-constrained in
  V56/V70; the legacy bigint `email_log_id` was dropped in V74).

  ## aws_message_id backfill

  The hot SQS lookup now relies solely on the dedicated indexed `aws_message_id`
  column (the legacy headers-JSONB scan was removed in the app code). Backfill it
  for any legacy rows whose AWS MessageId lives only in the `headers` JSONB.
  `DISTINCT ON (aws_id)` + a `NOT EXISTS` guard keep it safe against the existing
  partial unique index on `aws_message_id`.

  ## Optional performance indexes

  pg_trgm substring-search indexes for the admin email list (`pg_trgm` is enabled
  from V111), per-template open/click analytics composites, and a partial index
  for the archiver's body-compression scan.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '137'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '136'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
