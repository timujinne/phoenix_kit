defmodule PhoenixKit.Migrations.Postgres.V160 do
  @moduledoc """
  V160: Widen `phoenix_kit_settings.value` from `varchar(255)` to `text`.

  V03 created the column as `:string`, which Ecto renders as `VARCHAR(255)`,
  while `PhoenixKit.Settings.Setting` has always validated `:value` at
  `max: 1000`. Any setting between 256 and 1000 characters therefore passed the
  changeset and then died at the database with a raw `Postgrex.Error` — not a
  changeset error a form could render, but a 500.

  Nothing was obviously over the limit until settings started carrying lists:
  the sitemap's default exclude patterns serialize to ~450 characters, so
  saving them was a guaranteed crash. Widening the column fixes the whole
  class rather than that one key.

  `varchar(n)` → `text` is a catalog-only change in PostgreSQL: no table
  rewrite, no data validation pass, and the `ACCESS EXCLUSIVE` lock is held
  only for the metadata update.
  """

  use Ecto.Migration

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("ALTER TABLE #{p}phoenix_kit_settings ALTER COLUMN value TYPE TEXT")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '160'")
  end

  @doc """
  Narrows `value` back to `varchar(255)`.

  **Lossy rollback:** this fails outright if any stored value is longer than
  255 characters, which is the honest outcome — silently truncating a host's
  settings would be worse than refusing. Shorten or delete those rows first.
  """
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    p = prefix_str(prefix)

    execute("ALTER TABLE #{p}phoenix_kit_settings ALTER COLUMN value TYPE VARCHAR(255)")

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '159'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
