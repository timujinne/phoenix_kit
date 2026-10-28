# rehearse_module_chains.exs — step 8 of the module-table-ownership plan, rehearsed.
#
# Plan: dev_docs/plans/2026-10-25-module-table-ownership.md.
#
# Core's chain still creates the 141 module-owned tables, so no host has yet run
# the module chains with nothing under them. This script does it, in a scratch
# schema: core's chain, then every owner module's chain on top (today's install),
# then drops all module-owned tables and runs the chains again, alone, in order
# (what a fresh install is once core stops creating them), and compares the two
# (`PhoenixKit.TestSupport.ModuleChainCheck.check_all/3`).
#
# It runs the chains twice, as a control and as the proof:
#
#   * name order   — what `mix phoenix_kit.update` did before `Modules.order_by_dependencies/1`;
#                    expected to fail on a chain that references another module's table;
#   * dependency order — `Modules.order_by_dependencies/2` over the modules' own mix.exs
#                    deps. This is the result that counts: a non-zero exit when it differs.
#
# `--edge a:b` (repeatable) adds a dependency the mix.exs files do not declare:
# `--edge document_creator:projects` puts document_creator after projects.
#
# The module checkouts are read from `--workspace` (default: core's parent
# directory): each `phoenix_kit_*` with a `migration_module/0` whose OTP app owns
# tables in `ModuleOwnedTables`. Their migration sources are compiled from there.
#
# `--record-full FILE` builds core's chain and every module chain (in dependency
# order) in a scratch schema and writes the whole schema, core's tables, functions,
# seeds and all, to FILE. `--compare-full FILE` builds the same and diffs it with
# FILE. Record on a core that still creates the module tables, compare on one that
# no longer does (step 8): the two must be equal.
#
# Run from core, MIX_ENV=test, against an EMPTY database (some chains look
# constraints up by name only, so tables left in `public` hide them):
#
#   PGDATABASE=pk_modgen_empty MIX_ENV=test mix run dev_docs/squash/rehearse_module_chains.exs

System.put_env("PK_GEN_LIBRARY", "1")
Code.require_file(Path.join(__DIR__, "generate_baseline.exs"))

defmodule PhoenixKit.Squash.RehearseModuleChains do
  @moduledoc false

  alias PhoenixKit.Migrations.ModuleOwnedTables
  alias PhoenixKit.Migrations.Modules
  alias PhoenixKit.Squash.RepoHelper
  alias PhoenixKit.TestSupport.ModuleChainCheck

  # Objects a chain adds only where another package's table exists, so a run
  # without that package differs from today's by design.
  @guarded ["phoenix_kit_doc_documents_project_uuid_fkey"]

  def main(argv) do
    {opts, [], []} =
      OptionParser.parse(argv,
        strict: [
          workspace: :string,
          edge: [:string, :keep],
          record_full: :string,
          compare_full: :string
        ]
      )

    workspace = Path.expand(opts[:workspace] || Path.join(__DIR__, "../../.."))

    packages = packages(workspace)
    chains = Enum.filter(packages, &(&1.migrations && ModuleOwnedTables.tables_for(&1.app) != []))

    compile!(Enum.flat_map(chains, & &1.sources))
    repo = RepoHelper.start!()

    by_name = Enum.sort_by(chains, & &1.app)
    edges = for e <- Keyword.get_values(opts, :edge), [a, b] = String.split(e, ":"), do: {a, b}
    by_deps = order(by_name, packages, edges)

    IO.puts("#{length(chains)} owner modules")
    IO.puts("dependency order: " <> Enum.map_join(by_deps, " ", &short(&1.app)))

    cond do
      opts[:record_full] -> record_full(repo, by_deps, opts[:record_full])
      opts[:compare_full] -> compare_full(repo, by_deps, opts[:compare_full])
      true -> rehearse(repo, by_name, by_deps)
    end
  end

  defp rehearse(repo, by_name, by_deps) do
    run(repo, "name order (control)", by_name)

    case run(repo, "dependency order", by_deps) do
      :ok -> IO.puts("OK rehearse_module_chains.exs")
      :error -> System.halt(1)
    end
  end

  @full_schema "pk_step8_full"

  defp record_full(repo, chains, file) do
    snapshot = full_snapshot(repo, chains)
    File.write!(file, :erlang.term_to_binary(snapshot))
    IO.puts("recorded #{file}: " <> counts(snapshot))
  end

  defp compare_full(repo, chains, file) do
    recorded = file |> File.read!() |> :erlang.binary_to_term()
    now = full_snapshot(repo, chains)

    diffs =
      for kind <- Map.keys(recorded),
          {key, was} <- recorded[kind] |> Map.to_list(),
          now[kind][key] != was do
        "#{kind} #{inspect(key)}: " <>
          if Map.has_key?(now[kind], key), do: "differs", else: "missing"
      end ++
        for kind <- Map.keys(now),
            key <- Map.keys(now[kind]),
            not Map.has_key?(recorded[kind], key) do
          "#{kind} #{inspect(key)}: extra"
        end

    diffs = Enum.reject(diffs, fn line -> Enum.any?(@guarded, &String.contains?(line, &1)) end)

    case diffs do
      [] ->
        IO.puts("OK the schema equals the recorded one (" <> counts(now) <> ")")

      diffs ->
        IO.puts("#{length(diffs)} differences:")
        diffs |> Enum.sort() |> Enum.take(200) |> Enum.each(&IO.puts("  " <> &1))

        if System.get_env("PK_VERBOSE") do
          for kind <- Map.keys(recorded),
              {key, was} <- recorded[kind],
              now[kind][key] not in [nil, was] do
            IO.puts(
              "\n#{kind} #{inspect(key)}\n  was: #{inspect(was, limit: :infinity)}\n  now: #{inspect(now[kind][key], limit: :infinity)}"
            )
          end
        end

        System.halt(1)
    end
  end

  defp counts(snapshot), do: Enum.map_join(snapshot, ", ", fn {k, v} -> "#{map_size(v)} #{k}" end)

  # The catalog the core generator reads, plus triggers, with column positions
  # dropped (a chain may order the columns of a table it creates differently).
  defp full_snapshot(repo, chains) do
    case ModuleChainCheck.build_all(repo, Enum.map(chains, & &1.migrations), @full_schema) do
      :ok -> :ok
      {:error, message} -> raise message
    end

    snapshot = PhoenixKit.Squash.Generate.Catalog.snapshot(repo, @full_schema)

    triggers =
      repo.query!(
        "SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND NOT t.tgisinternal",
        [@full_schema],
        log: false
      ).rows
      |> Map.new(fn [table, name, def] -> {{table, name}, def} end)

    repo.query!(~s(DROP SCHEMA IF EXISTS "#{@full_schema}" CASCADE), [], log: false)

    snapshot
    |> Map.take([:tables, :columns, :indexes, :constraints, :sequences, :functions, :seeds])
    |> normalize()
    |> Map.update!(:columns, fn columns ->
      Map.new(columns, fn {k, v} -> {k, Map.delete(v, :pos)} end)
    end)
    |> Map.put(:triggers, triggers)
  end

  # Two spellings Postgres stores for the same CHECK / partial index (an array
  # literal cast as a whole or per element), and timestamps a seed stamps with
  # the clock, compare equal.
  defp normalize(term) when is_map(term) and not is_struct(term),
    do: Map.new(term, fn {k, v} -> {k, normalize(v)} end)

  defp normalize(term) when is_binary(term) do
    term
    |> String.replace(~r/\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(\.\d+)?\+\d\d/, "<ts>")
    |> String.replace(["::character varying", "::text[]", "::text"], "")
    |> String.replace(["(", ")"], "")
  end

  defp normalize(term) when is_list(term), do: Enum.map(term, &normalize/1)
  defp normalize(term), do: term

  defp run(repo, label, chains) do
    case ModuleChainCheck.check_all(repo, Enum.map(chains, & &1.migrations), allow: @guarded) do
      :ok ->
        IO.puts("#{label}: all chains build the same tables as today")
        :ok

      {:error, report} ->
        IO.puts("#{label}: FAILS\n" <> indent(report))
        :error
    end
  end

  defp indent(text), do: text |> String.split("\n") |> Enum.map_join("\n", &("    " <> &1))
  defp short(app), do: app |> Atom.to_string() |> String.replace_prefix("phoenix_kit_", "")

  # Every phoenix_kit_* checkout: its OTP app, its mix.exs deps on siblings, and,
  # when it declares a migration module, where that module's source is.
  defp packages(workspace) do
    for dir <- Path.wildcard(Path.join(workspace, "phoenix_kit_*")),
        dir != Path.join(workspace, "phoenix_kit_bookings"),
        File.exists?(Path.join(dir, "mix.exs")) do
      mix = File.read!(Path.join(dir, "mix.exs"))
      lib = Path.join(dir, "lib")
      migrations = migration_module(lib)

      %{
        app: mix |> then(&Regex.run(~r/app: :(\w+)/, &1)) |> Enum.at(1) |> String.to_atom(),
        deps: deps(mix),
        migrations: migrations,
        sources: if(migrations, do: sources(lib, migrations), else: [])
      }
    end
  end

  defp deps(mix) do
    ~r/(?:\{|pk_dep\()\s*:(phoenix_kit_\w+)\s*,[^\n]*/
    |> Regex.scan(mix)
    |> Enum.reject(fn [line, _] -> line =~ "only:" end)
    |> Enum.map(fn [_, app] -> String.to_atom(app) end)
  end

  defp migration_module(lib) do
    lib
    |> Path.join("**/*.ex")
    |> Path.wildcard()
    |> Enum.find_value(fn file ->
      case Regex.run(~r/^\s*def migration_module,\s*do:\s*([\w.]+)/m, File.read!(file)) do
        [_, name] -> Module.concat([name])
        nil -> nil
      end
    end)
  end

  # The file defining the migrations module, what sits beside it in its own
  # directory, and the schema files with `column_widths/0` that chains read.
  defp sources(lib, migrations) do
    name = inspect(migrations)
    files = Path.wildcard(Path.join(lib, "**/*.ex"))
    own = Enum.filter(files, &(File.read!(&1) =~ ~r/defmodule #{Regex.escape(name)} do/))
    nested = Enum.flat_map(own, &Path.wildcard(Path.join(Path.rootname(&1), "**/*.ex")))
    widths = Enum.filter(files, &(File.read!(&1) =~ "def column_widths"))
    Enum.uniq(own ++ nested ++ widths)
  end

  # Dependency order from the modules' own mix.exs, followed through packages
  # that have no chain (a dependency counts transitively).
  defp order(chains, packages, edges) do
    by_app = Map.new(packages, &{&1.app, &1})

    deps =
      Map.new(chains, fn chain ->
        reachable = reachable(chain.app, by_app, MapSet.new()) |> MapSet.delete(chain.app)

        extra =
          for {a, b} <- edges,
              "phoenix_kit_" <> a == Atom.to_string(chain.app),
              do: String.to_atom("phoenix_kit_" <> b)

        {chain.app,
         for(
           a <- Enum.uniq(MapSet.to_list(reachable) ++ extra),
           c <- chains,
           c.app == a,
           do: c.app
         )}
      end)

    chains
    |> Enum.map(&%{module: &1.app, chain: &1})
    |> Modules.order_by_dependencies(deps)
    |> Enum.map(& &1.chain)
  end

  defp reachable(app, by_app, seen) do
    if MapSet.member?(seen, app) or not Map.has_key?(by_app, app) do
      MapSet.put(seen, app)
    else
      Enum.reduce(by_app[app].deps, MapSet.put(seen, app), &reachable(&1, by_app, &2))
    end
  end

  defp compile!(sources) do
    sources
    |> Enum.uniq()
    |> Enum.sort()
    |> Kernel.ParallelCompiler.compile(return_diagnostics: true)
    |> case do
      {:ok, _modules, _warnings} -> :ok
      {:error, errors, _warnings} -> raise "cannot compile module sources: #{inspect(errors)}"
    end
  end
end

PhoenixKit.Squash.RehearseModuleChains.main(System.argv())
