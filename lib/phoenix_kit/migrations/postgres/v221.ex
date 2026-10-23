defmodule PhoenixKit.Migrations.Postgres.V221 do
  @moduledoc """
  V221: a country on the user.

  One additive column:

    * **`phoenix_kit_users.country`** (`varchar(2)`, `NULL`), the ISO 3166-1
      alpha-2 code of the country a person lives in or a company is based in.
      It decides how dates are written for that account
      (`PhoenixKit.Users.FormatCountry`). `NULL` means "not chosen": the
      resolver then looks at the company, the registration country and the
      site default, in that order.

  Nothing is backfilled. `registration_country` is a GeoIP guess, and the
  resolver already falls back to it at read time, so copying it here would turn
  a guess into stored profile data nobody confirmed. No constraint either: the
  code is checked against `BeamLabCountries` by the changeset, and a data set
  that gains a code must not need a migration.

  ## Locks

  `ADD COLUMN` with no default: a catalog change, no table rewrite. Re-runnable.

  ## Down

  Drops the column: every chosen country is lost, and accounts fall back to the
  resolver's other sources.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.V203

  @doc false
  def up(opts) do
    opts |> Map.get(:prefix, "public") |> up_statements() |> Enum.each(&execute/1)
  end

  @doc "Rolls V221 back: the `country` column goes."
  def down(opts) do
    opts |> Map.get(:prefix, "public") |> down_statements() |> Enum.each(&execute/1)
  end

  @doc false
  def up_statements(prefix) do
    p = V203.prefix_str(prefix)

    [
      "ALTER TABLE #{p}phoenix_kit_users ADD COLUMN IF NOT EXISTS country character varying(2)",
      "COMMENT ON TABLE #{p}phoenix_kit IS '221'"
    ]
  end

  @doc false
  def down_statements(prefix) do
    p = V203.prefix_str(prefix)

    [
      "ALTER TABLE #{p}phoenix_kit_users DROP COLUMN IF EXISTS country",
      "COMMENT ON TABLE #{p}phoenix_kit IS '220'"
    ]
  end
end
