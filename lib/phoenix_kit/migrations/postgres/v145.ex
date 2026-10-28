defmodule PhoenixKit.Migrations.Postgres.V145 do
  @moduledoc """
  V145: Newsletters Send Settings — `phoenix_kit_newsletters_send_profiles`.

  Adds the send-profile table backing the newsletters module's "Send
  Settings" admin screen: named send configurations that reference a
  core Integrations connection (by `integration_uuid`, no FK — consistent
  with the codebase's loose-UUID pattern for cross-module references, see
  v138/v140) and carry per-account send parameters (from-name/email,
  reply-to, signature, rate limits, `advanced` per-provider extras).
  Multiple profiles may share one integration. At most one profile may be
  `is_default` (the service-wide default), enforced by a partial unique
  index.

  Also adds `send_profile_uuid` (bare UUID, no FK) to
  `phoenix_kit_newsletters_broadcasts`, letting each broadcast pin which
  send profile delivers it — folded in here rather than a follow-up
  migration since V145 hasn't shipped anywhere yet.

  All statements are idempotent, safe to re-run.

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

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '145'")
  end

  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '144'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
