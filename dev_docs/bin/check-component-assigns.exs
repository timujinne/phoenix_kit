# Sweep every sibling module checkout for function components reading assigns
# they neither declare nor self-assign — the class that shipped
# BeamLabEU/phoenix_kit_open_graph#7 and that the compiler cannot see.
#
# Read-only. Run from the core checkout, next to its siblings:
#
#     MIX_ENV=test mix run --no-start dev_docs/bin/check-component-assigns.exs
#
# Exit status: number of findings (0 = clean), so it can gate a script.
# Policy and per-pattern rationale: PhoenixKit.Conformance.ComponentAssigns.
# Modules can adopt the same check as a local test once their core pin ships
# that module; this script is the not-pin-gated way to sweep the whole tree.
repos =
  "../phoenix_kit*"
  |> Path.wildcard()
  |> Enum.filter(&File.dir?(Path.join(&1, "lib")))

total =
  for repo <- repos, reduce: 0 do
    acc ->
      violations =
        Path.join(repo, "lib/**/*.ex")
        |> Path.wildcard()
        |> PhoenixKit.Conformance.ComponentAssigns.violations()

      unless violations == [] do
        IO.puts("\n== #{Path.basename(repo)} (#{length(violations)})")

        Enum.each(
          violations,
          &IO.puts("  #{&1.file}:#{&1.line}  #{&1.component}/1 reads @#{&1.assign}")
        )
      end

      acc + length(violations)
  end

IO.puts("#{total} finding(s) across #{length(repos)} repo(s)")
if total > 0, do: System.halt(min(total, 255))
