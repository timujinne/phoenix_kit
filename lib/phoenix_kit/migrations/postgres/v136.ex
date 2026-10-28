defmodule PhoenixKit.Migrations.Postgres.V136 do
  @moduledoc """
  V136: Employment history for `phoenix_kit_staff`.

  Replaces the single flat employment span on `phoenix_kit_staff_people`
  (`employment_type` / `employment_start_date` / `employment_end_date` /
  `job_title` / `work_location`) with a first-class **history** of employment
  spans, surfaced as a dedicated tab on the person profile.

  Creates `phoenix_kit_staff_employments` — one row per span, carrying the
  employment type, a translatable `job_title`, the org placement at the time
  (`primary_department_uuid` + a `primary_team_uuid` snapshot), the date range
  (`employment_end_date IS NULL` = the current/open span), `work_location`, and
  free-text `notes`.

  ## Single open span per person

  A partial unique index enforces **at most one open span** (`employment_end_date
  IS NULL`) per person — the "current" employment. The app context closes the
  prior open span when a new one starts.

  ## Denormalized "current" mirror

  The matching columns already on `phoenix_kit_staff_people` are kept as a
  denormalized mirror of the current (open) span — the app's `sync_current/1`
  writes them in the same transaction as any span change, so existing readers
  (overview org tree, people list) need no join. This migration does NOT drop
  those columns.

  ## Backfill

  One open span per existing person is seeded from their current columns
  (`employment_type` / `job_title` / dates / `primary_department_uuid` /
  `work_location`), copying any per-locale `job_title` overrides out of the
  person's `translations` JSONB into the span's `translations`. Guarded by a
  `NOT EXISTS` check on the span table so a re-run is a safe no-op; people with
  no employment data at all are skipped (they start with an empty history).
  `primary_team_uuid` is left null on backfill — the person's team comes from the
  many-to-many `team_memberships`, which has no single "primary" to copy.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '136'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '135'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
