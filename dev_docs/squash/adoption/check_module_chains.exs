# check_module_chains.exs — runs PhoenixKit.TestSupport.ModuleChainCheck over
# every module chain in the workspace, from core's test VM.
#
# For each sibling checkout `../phoenix_kit_*` whose lib/ defines
# `migration_module/0`, loads the module's compiled beams from its own
# `_build/test` (compile it there first: `MIX_ENV=test mix compile`), and checks
# that its chain builds the tables `ModuleOwnedTables` lists for it (plus every
# table it creates itself) the same way with and without core. Nothing is
# changed in the module checkouts; each check uses a scratch schema of its own.
#
#   MIX_ENV=test mix run --no-start dev_docs/squash/adoption/check_module_chains.exs [app ...]
#
# With app names (`phoenix_kit_sync`), only those. Uses the suite's database.
# A module whose beams are missing or stale is reported, not checked.
{:ok, _} = Application.ensure_all_started(:ecto_sql)
{:ok, _} = PhoenixKit.Test.Repo.start_link(pool_size: 4, log: false)

alias PhoenixKit.Migrations.ModuleOwnedTables
alias PhoenixKit.TestSupport.ModuleChainCheck

workspace = Path.expand("../../../..", __DIR__)
only = System.argv()

chains =
  for dir <- Path.wildcard(Path.join(workspace, "phoenix_kit_*")),
      File.exists?(Path.join(dir, "mix.exs")),
      app = Regex.run(~r/app:\s*:(\w+)/, File.read!(Path.join(dir, "mix.exs")), capture: :all_but_first),
      app = app && hd(app),
      only == [] or app in only,
      source = dir |> Path.join("lib/**/*.ex") |> Path.wildcard() |> Enum.map_join("\n", &File.read!/1),
      [mod] <- [Regex.run(~r/def migration_module,\s*do:\s*([A-Z][\w.]+)/, source, capture: :all_but_first)],
      mod != "MyModule.Migrations",
      do: {app, Module.concat([mod]), Path.join(dir, "_build/test/lib/#{app}/ebin")}

for {_app, _mod, ebin} <- chains, do: Code.append_path(ebin)

for {app, mod, ebin} <- Enum.sort(chains) do
  tables = ModuleOwnedTables.tables_for(String.to_atom(app))

  result =
    cond do
      not File.dir?(ebin) -> {:skipped, "no #{ebin} — run MIX_ENV=test mix compile there"}
      not Code.ensure_loaded?(mod) -> {:skipped, "#{inspect(mod)} not in #{ebin} — recompile it"}
      true -> ModuleChainCheck.check(PhoenixKit.Test.Repo, mod, tables: tables)
    end

  case result do
    :ok -> IO.puts("OK       #{app} (#{length(tables)} core-created tables)")
    {:skipped, why} -> IO.puts("SKIPPED  #{app}: #{why}")
    {:error, report} -> IO.puts("DIFFERS  #{app} (#{length(tables)} core-created tables)\n" <> report)
  end
end
