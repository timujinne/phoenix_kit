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
      OptionParser.parse(argv, strict: [workspace: :string, edge: [:string, :keep]])

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

    run(repo, "name order (control)", by_name)

    case run(repo, "dependency order", by_deps) do
      :ok -> IO.puts("OK rehearse_module_chains.exs")
      :error -> System.halt(1)
    end
  end

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
