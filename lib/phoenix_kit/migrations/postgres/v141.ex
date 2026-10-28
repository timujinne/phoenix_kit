defmodule PhoenixKit.Migrations.Postgres.V141 do
  @moduledoc """
  V141: Personal calendar events + participants for the
  `phoenix_kit_calendar` module.

  One implicit personal calendar per user — events are keyed by
  `owner_uuid` (no calendars table in v1; recurrence is deliberately
  deferred).

  Time model (mirrors `phoenix_live_calendar`'s Event semantics):

  - Timed events use the `starts_at`/`ends_at` UTC pair; `ends_at` is
    EXCLUSIVE (`[start, end)`, iCal/RFC 5545 style).
  - All-day events use the `starts_on`/`ends_on` DATE pair (also
    end-exclusive) — proper date semantics instead of UTC-midnight
    instants, so a "day" never shifts across timezones/DST.
  - A CHECK constraint enforces exactly one pair per row, matching the
    `all_day` flag, with end > start on both pairs.

  `owner_uuid` cascades on user delete — a personal calendar follows its
  account's lifecycle. `location_uuid` optionally links a stored location
  from the locations module (loose uuid reference, NO cross-module FK —
  the location NAME is snapshotted into the `location` string at save, so
  rendering never needs the locations module).

  ## Participants

  `phoenix_kit_calendar_event_participants` attaches people to an event.
  Loose `kind` + `target_uuid` references (activity-feed pattern — no
  cross-module FKs) with a `display_name` snapshot frozen at save, so
  participants render even if a source module is later disabled or the
  record deleted. Kinds: `user`, `staff_person`, `crm_contact`,
  `crm_company`, `free_text` (free text has no target and grants no
  visibility).

  Visibility is resolved LIVE at query time by joining the PHYSICAL
  staff/CRM tables (they exist in every install via these core
  migrations, so no module code is required and empty tables no-op):
  a company participant means "whoever is a member of that company NOW",
  and a staff person / CRM contact resolves through its current
  `user_uuid` link. `added_by_uuid` records who attached the participant.

  All statements are idempotent AND additive — this migration was
  extended in place while unreleased (per project policy); re-running it
  on a database that has the earlier shape adds only the missing pieces.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '141'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '140'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
