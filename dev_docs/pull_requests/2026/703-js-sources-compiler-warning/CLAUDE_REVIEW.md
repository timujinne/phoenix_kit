# PR #703 — Warn when a module's JS hooks will never be loaded

**Reviewer:** Claude (post-merge sweep, 2026-08-11)
**Verdict:** Merged. One MEDIUM bug fixed on main.

## Summary

The check is well-placed and the restraint is right. `phoenix_kit_routes()` is
the only place that can see both facts (what is installed, what is in
`:compilers`), it runs in the macro body rather than the quoted code so it
fires at host-router compile time, and it is silent both when the compiler is
present and when nothing declares a bundle. The moduledoc correction about
LiveView 1.1 `getHookDefinition/1` is accurate and worth having recorded — the
old rationale was telling module authors that host wiring is unavoidable when
it stopped being so.

The split into `warn_missing_js_compiler/2` for testability is the right call
for the reason the PR gives: routed through real discovery, the interesting
branch would only run on a misconfigured host, i.e. never in this suite.

## BUG - MEDIUM: the warning breaks the build on any `--warnings-as-errors` host

`lib/phoenix_kit_web/integration.ex` — `warn_missing_js_compiler/2` emitted via
`IO.warn/1`.

`IO.warn/1` registers a **compiler diagnostic**. On a host compiling with
`--warnings-as-errors` — the ordinary CI setting — this does not warn, it fails
the compile. Verified directly rather than assumed:

```
$ mix compile --warnings-as-errors     # module body calling IO.warn/1
warning: compile-time warning from IO.warn
Compilation failed due to warnings while using the --warnings-as-errors option
EXIT=1
```

This contradicts the PR's own design in two places. The stated guarantee is
"It can never fail a host's compile", and the implementation backs that up
everywhere else: `modules_declaring_js_sources/0` rescues discovery, and
`js_compiler_configured?/0` guards the Mix lookup and defaults to *silent* when
Mix is unloaded. Both exist because a warning is not worth taking a build down
for. `IO.warn/1` then takes the build down.

The impact is worse than a normal breaking change because of who it lands on:
a host upgrading `phoenix_kit` gets a red CI over a condition in **mix.exs**
that is not a regression in their own code, and the stacktrace `IO.warn`
attaches points into `elixir_compiler.erl` internals rather than at anything
they wrote. The only way to turn it off is to make the change it is asking
for. That is a breaking change wearing a warning's clothes — and precisely the
kind of thing that gets a library pinned.

**Fixed on main:** emit with `IO.puts(:stderr, ...)`, prefixed `warning:`.
Identical visibility in build output, not a diagnostic. Pinned by a new test
using `Code.with_diagnostics/1` asserting the call registers none — the
existing `capture_io(:stderr, …)` assertions all still hold unchanged, which
is itself the evidence that visibility was not what changed.

## Notes, not defects

- Placement in the macro body (not the `quote`) is correct and load-bearing;
  worth keeping in mind if anyone reorganises `phoenix_kit_routes/0`.
- `js_compiler_configured?/0` returning `true` (silent) when Mix is unloaded is
  the right default — the compile already happened by then.
- The three corrections in the PR description's "Scope" section were spot-checked
  and hold: `merge_user_custom_fields/3` does exist and does the atomic
  `COALESCE(?, '{}'::jsonb) || ?` merge described.
