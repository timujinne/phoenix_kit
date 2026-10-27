defmodule PhoenixKit.Migrations.Postgres.V225 do
  @moduledoc """
  V225: a short code on every file, for addresses a person can read out.

  One additive column and one index:

    * **`phoenix_kit_files.short_code`** (`varchar(12)`, `NULL`), a random
      8-character code (`k3Fq9xA2`) that names the file in a URL instead of its
      36-character UUID. The alphabet is base58: no `0`, `O`, `I` or `l`, so a code
      survives being read aloud or copied from a screenshot. `PhoenixKit.Modules.Storage.ShortCode`
      makes them; the `File` changeset gives one to every new file.
    * **`phoenix_kit_files_short_code_index`**, unique, where the column is not `NULL`.

  ## Backfill

  Every existing file gets a code here, in SQL, so an address can be built for any
  file at once. A code that two files drew is redrawn for all but one of them, until
  none repeat, and only then is the unique index built. The codes are random, not derived
  from anything, so they leak nothing about the file.

  ## Locks

  The backfill is one `UPDATE` of the table and the index build takes a SHARE lock on it:
  reads continue, writes wait. Both are bounded by `lock_timeout` for the `ALTER`, not for the
  `UPDATE`, so run this on a site with a very large `phoenix_kit_files` in a quiet window. The
  index name stays bare on CREATE (prefix-safe migration rules). Re-runnable.

  ## Down

  Drops the index and the column: addresses that used a code stop working, and the files
  are untouched.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.V203

  @alphabet "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @doc false
  def up(opts) do
    opts |> Map.get(:prefix, "public") |> up_statements() |> Enum.each(&execute/1)
  end

  @doc "Rolls V225 back: the index and the `short_code` column go."
  def down(opts) do
    opts |> Map.get(:prefix, "public") |> down_statements() |> Enum.each(&execute/1)
  end

  # A code of 8 random characters of the alphabet. `f.uuid IS NOT NULL` ties the
  # subquery to the row, so `random()` is drawn again for every file.
  defp draw do
    "(SELECT string_agg(substr('#{@alphabet}', 1 + floor(random() * 58)::int, 1), '') " <>
      "FROM generate_series(1, 8) WHERE f.uuid IS NOT NULL)"
  end

  @doc false
  def up_statements(prefix) do
    p = V203.prefix_str(prefix)

    [
      "SET lock_timeout = '5000ms'",
      "ALTER TABLE #{p}phoenix_kit_files ADD COLUMN IF NOT EXISTS short_code character varying(12)",
      "RESET lock_timeout",
      "UPDATE #{p}phoenix_kit_files f SET short_code = #{draw()} WHERE f.short_code IS NULL",
      """
      DO $$
      DECLARE n integer;
      BEGIN
        LOOP
          UPDATE #{p}phoenix_kit_files f SET short_code = #{draw()}
           WHERE f.uuid IN (
             SELECT uuid FROM (
               SELECT uuid, row_number() OVER (PARTITION BY short_code ORDER BY uuid) AS rn
                 FROM #{p}phoenix_kit_files WHERE short_code IS NOT NULL
             ) d WHERE d.rn > 1);
          GET DIAGNOSTICS n = ROW_COUNT;
          EXIT WHEN n = 0;
        END LOOP;
      END $$
      """,
      """
      CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_files_short_code_index
        ON #{p}phoenix_kit_files USING btree (short_code) WHERE (short_code IS NOT NULL)
      """,
      "COMMENT ON TABLE #{p}phoenix_kit IS '225'"
    ]
  end

  @doc false
  def down_statements(prefix) do
    p = V203.prefix_str(prefix)

    [
      "DROP INDEX IF EXISTS #{p}phoenix_kit_files_short_code_index",
      "ALTER TABLE #{p}phoenix_kit_files DROP COLUMN IF EXISTS short_code",
      "COMMENT ON TABLE #{p}phoenix_kit IS '224'"
    ]
  end
end
