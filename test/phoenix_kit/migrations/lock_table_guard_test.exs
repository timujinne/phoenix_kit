defmodule PhoenixKit.Migrations.LockTableGuardTest do
  @moduledoc """
  `LOCK TABLE` inside a migration must sit inside a table-existence guard.

  Unlike almost every other statement this chain emits, `LOCK TABLE` has no
  `IF EXISTS` form. `DROP CONSTRAINT IF EXISTS`, `DROP INDEX IF EXISTS` and
  `CREATE TABLE IF NOT EXISTS` all forgive a missing relation; `LOCK TABLE`
  raises `relation does not exist` and aborts the enclosing transaction — which
  on a partial install (a host that never enabled the module owning the table)
  takes the whole migration down with it.

  V169 shipped with exactly that asymmetry: `up/1` wrapped its
  `phoenix_kit_entity_data` work in a `pg_class`/`pg_namespace` existence check
  and said so in a comment, while `down/1` reached straight for
  `LOCK TABLE ... IN EXCLUSIVE MODE` on the same table. An install without the
  entity tables would skip the relaxation on the way up and then fail rolling
  back — and `up/1` having skipped it is precisely why there was nothing for
  `down/1` to undo.

  DB-free: statically scans migration SOURCE TEXT, never touches a database.
  The rule is checked per `DO $$ … $$` block, because that is the scope a
  PL/pgSQL `IF EXISTS (…) THEN` guard actually covers — a guard in a *different*
  `execute/1` call in the same file protects nothing.
  """

  use ExUnit.Case, async: true

  @migrations_dir "lib/phoenix_kit/migrations/postgres"

  # `LOCK TABLE <prefix>?<table>` — the prefix is interpolated (`#{p}`) rather
  # than literal, so it is matched loosely and only the table name is captured.
  @lock_pattern ~r/LOCK\s+TABLE\s+\S*?"?(phoenix_kit_[a-zA-Z0-9_]+)"?/i

  # Each `DO $$ … $$` body. Non-greedy so adjacent blocks in one file stay
  # separate rather than collapsing into a single span.
  @do_block_pattern ~r/DO\s+\$\$(.*?)\$\$/s

  test "every LOCK TABLE in the migration chain sits inside a table-existence guard" do
    offenders =
      @migrations_dir
      |> Path.join("v*.ex")
      |> Path.wildcard()
      |> Enum.sort()
      |> Enum.flat_map(&unguarded_locks/1)

    assert offenders == [], """
    Found #{length(offenders)} `LOCK TABLE` statement(s) not guarded by a \
    table-existence check in the same `DO $$ … $$` block:

    #{Enum.map_join(offenders, "\n", fn {file, table} -> "  - #{file}: #{table}" end)}

    `LOCK TABLE` has no `IF EXISTS` form, so on an install where the table was \
    never created this raises `relation does not exist` and aborts the whole \
    migration. Wrap it the way V169's `up/1` does:

        IF EXISTS (
          SELECT 1 FROM pg_class t
          JOIN pg_namespace n ON n.oid = t.relnamespace
          WHERE t.relname = '<table>' AND n.nspname = '\#{schema}'
        ) THEN
          LOCK TABLE \#{p}<table> IN EXCLUSIVE MODE;
          ...
        END IF;

    Note the schema anchor on the guard — an unanchored `relname` check passes \
    on a same-named table in another schema, which is the prefix-safety rule in \
    this repo's AGENTS.md.
    """
  end

  defp unguarded_locks(path) do
    file = Path.basename(path)
    source = File.read!(path)

    @do_block_pattern
    |> Regex.scan(source, capture: :all_but_first)
    |> Enum.flat_map(fn [block] ->
      block
      |> then(&Regex.scan(@lock_pattern, &1, capture: :all_but_first))
      |> Enum.map(fn [table] -> table end)
      |> Enum.uniq()
      |> Enum.reject(&guarded?(block, &1))
      |> Enum.map(&{file, &1})
    end)
    |> Enum.uniq()
  end

  # The guard this looks for is the shape the chain actually uses: a name-based
  # `pg_class` lookup for the same table. Deliberately does NOT require the
  # `pg_namespace` join — the schema anchor is a separate rule with its own
  # prefix tests, and conflating them would make THIS failure message point at
  # the wrong fix.
  defp guarded?(block, table) do
    Regex.match?(~r/relname\s*=\s*'#{Regex.escape(table)}'/i, block)
  end
end
