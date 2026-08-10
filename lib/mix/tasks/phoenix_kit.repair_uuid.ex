defmodule Mix.Tasks.PhoenixKit.RepairUuid do
  @shortdoc "Repairs phoenix_kit tables whose uuid column is not a proper primary key"

  @moduledoc """
  Repairs `phoenix_kit_*` tables whose `uuid` column is the wrong type, nullable,
  or not the primary key.

  V163 performs this repair automatically during `mix ecto.migrate`, but skips
  any table large enough that the rewrite's `ACCESS EXCLUSIVE` lock would be an
  outage rather than a pause. This task is the deliberate, operator-chosen path
  for those — run it in a maintenance window.

      mix phoenix_kit.repair_uuid                       # every table that needs it
      mix phoenix_kit.repair_uuid phoenix_kit_email_events
      mix phoenix_kit.repair_uuid --dry-run             # show the SQL, change nothing
      mix phoenix_kit.repair_uuid --prefix tenant_a

  ## What it costs

  `ALTER COLUMN … TYPE uuid` rewrites the table and holds an `ACCESS EXCLUSIVE`
  lock for the duration — no reads, no writes, and behind a connection pooler
  that means the pool fills rather than merely waiting. There is no concurrent
  form of a type change; the size of the table is the size of the outage.

  The primary key is cheaper here than in the migration: outside a transaction
  the unique index is built `CONCURRENTLY` and then attached, so the exclusive
  lock covers only the attach. That is why this task is not simply "V163 without
  the limit".

  ## Safety

  Nothing is destructive except de-duplication, which deletes rows that share a
  uuid — on a table that has run without a primary key those are the same
  logical row stored twice, and a duplicate makes `ADD PRIMARY KEY` impossible.
  `--dry-run` prints every statement, including the delete, without executing.

  Values that cannot be cast to `uuid` abort that table with the query to
  inspect them; other tables still proceed.
  """

  use Mix.Task

  alias PhoenixKit.Install.PrefixConfig
  alias PhoenixKit.Migrations.UUIDIntegrity

  @requirements ["app.start"]

  @switches [dry_run: :boolean, prefix: :string]

  @impl Mix.Task
  def run(args) do
    {opts, tables} = OptionParser.parse!(args, strict: @switches)

    # Same resolution the doctor and installer use: --prefix > app config > public
    prefix = PrefixConfig.resolve_prefix(opts)
    dry_run? = opts[:dry_run] || false
    repo = PhoenixKit.RepoHelper.repo()

    broken = UUIDIntegrity.broken_tables(repo, prefix)

    case {filter_requested(broken, tables), tables} do
      {[], []} ->
        Mix.shell().info([:green, "✓ Every phoenix_kit table has a proper uuid primary key."])

      # Named tables that need nothing must NOT report the global all-clear.
      # V163's log tells an operator to run this task with a table name, so a
      # typo — or a table already repaired, or the wrong --prefix — would
      # otherwise answer "everything is fine" and change nothing.
      {[], named} ->
        Mix.shell().info([
          :yellow,
          "Nothing to do: none of the named table(s) need repair — #{Enum.join(named, ", ")}.",
          :reset,
          "\nRun without arguments to list every table that does (prefix: #{prefix})."
        ])

      {found, _} ->
        Mix.shell().info("Tables needing repair: #{length(found)}")
        Enum.each(found, &repair(repo, prefix, &1, dry_run?))
        report(dry_run?)
    end
  end

  defp filter_requested(broken, []), do: broken

  defp filter_requested(broken, requested) do
    Enum.filter(broken, &(&1.name in requested))
  end

  defp repair(repo, prefix, %{name: name} = table, dry_run?) do
    qualified = UUIDIntegrity.qualify(prefix, name)

    if UUIDIntegrity.castable?(repo, qualified, table) do
      rows = UUIDIntegrity.estimated_rows(repo, prefix, name)

      # `:unknown` is said out loud rather than printed as a number. This task
      # is the maintenance-window path the migration defers TO, so the operator
      # deciding whether they have a window needs to know the size is a guess
      # nobody has ever taken — not read "~0 rows" and size the window for it.
      size =
        case rows do
          :unknown -> "size unknown — never analyzed"
          n -> "~#{n} rows"
        end

      Mix.shell().info([
        :cyan,
        "\n#{name}",
        :reset,
        " (#{size}) #{UUIDIntegrity.describe(table)}"
      ])

      announce_duplicates(repo, qualified, table)

      # concurrent_index: this task runs outside a transaction, so the unique
      # index can be built without holding the table against readers.
      qualified
      |> UUIDIntegrity.repair_statements(prefix, table, concurrent_index: true)
      |> Enum.each(&run_statement(repo, &1, dry_run?))
    else
      Mix.shell().error("""
      #{name}: uuid holds values that are not valid UUIDs — skipped. Inspect with:
        SELECT uuid FROM #{qualified}
         WHERE uuid IS NOT NULL AND uuid !~* '#{uuid_regex()}' LIMIT 20;
      """)
    end
  end

  defp run_statement(_repo, sql, true), do: Mix.shell().info(["  [dry-run] ", String.trim(sql)])

  defp run_statement(repo, sql, false) do
    Mix.shell().info(["  ", String.trim(sql)])
    repo.query!(sql, [], timeout: :infinity)
  end

  # The DELETE is the one destructive statement in the list `--dry-run` prints,
  # and how many rows it takes is not visible from the SQL itself.
  defp announce_duplicates(_repo, _qualified, %{has_pk: true}), do: :ok

  defp announce_duplicates(repo, qualified, _table) do
    case UUIDIntegrity.duplicate_rows(repo, qualified) do
      n when n > 0 ->
        Mix.shell().info([:yellow, "  #{n} row(s) share a uuid and will be DELETED"])

      _ ->
        :ok
    end
  end

  defp report(true) do
    Mix.shell().info([:yellow, "\nDry run — nothing was changed."])
  end

  defp report(false) do
    Mix.shell().info([:green, "\n✓ Repair complete. Re-run mix phoenix_kit.doctor to confirm."])
  end

  defp uuid_regex, do: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
end
