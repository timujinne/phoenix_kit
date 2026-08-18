# Claude Review — PR #736 "Track the pre-commit hook at .githooks/ and add a doctor check for it"

**Merge commit:** f469ce2e713519a2f2548414bc51adc8754b32d1
**Author:** timujinne (feature/tracked-git-hooks)
**Files:** `.githooks/pre-commit` (new), `AGENTS.md`, `dev_docs/investigations/2026-08-18-tracked-git-hooks.md` (new), `lib/mix/tasks/phoenix_kit.doctor.ex`, `test/mix/tasks/phoenix_kit_doctor_test.exs`

## BUG - HIGH: "Git Hooks" doctor check fires on every consuming host app, not just the phoenix_kit repo, and can never pass there

`lib/mix/tasks/phoenix_kit.doctor.ex:141` adds `run_check("Git Hooks", fn -> check_git_hooks() end)` unconditionally to the same checks list as "Sitemap Discoverability", "Oban Configuration", "daisyUI Version", etc. — all of which diagnose a **host app's installed PhoenixKit**. `mix phoenix_kit.doctor`'s moduledoc confirms this framing ("Diagnoses PhoenixKit installation, migration, and runtime issues"), and the repo's own `mix.exs` has `app: :phoenix_kit` with `ecto_repos: []` outside `test.exs` — i.e. `phoenix_kit` itself is the library, not a runnable host, so this task is meant to run from a *consuming* application's directory.

`check_git_hooks/0` (`lib/mix/tasks/phoenix_kit.doctor.ex:257-260`) checks `File.exists?(".githooks/pre-commit")` and `core.hooksPath` relative to whatever directory `mix phoenix_kit.doctor` runs in — i.e. **the host app's own repo**. But `.githooks/pre-commit` is a phoenix_kit-core-repo-only dev convention (per `AGENTS.md` step 0, "First clone only"); nothing in `phoenix_kit.install`/`phoenix_kit.update` ever copies a `.githooks/pre-commit` or wires `core.hooksPath` into a host app (confirmed: no hits for `githooks`/`hooksPath` in the install/update tasks). A host has no way to make this check pass — it will permanently report `tracked?: false` → *".githooks/pre-commit is missing from this checkout, so there is nothing to enable."* on every single install that runs `mix phoenix_kit.doctor`, which is documented as safe to run in deploy scripts.

**Impact:** every consumer of the library gets a spurious, unfixable WARN mixed in with real installation-health findings, teaching users to ignore doctor output.

**Fix applied:** `check_git_hooks/0` is now only added to the `run/1` results list when `Mix.Project.config()[:app] == :phoenix_kit` (new `git_hooks_check/0`, `lib/mix/tasks/phoenix_kit.doctor.ex`), mirroring how `oban_config` already distinguishes "the host's app" from `:phoenix_kit` earlier in the same task. The pure `git_hooks_verdict/1` function and its contributor-facing behavior (AGENTS.md step 0) are unchanged — this only changes whether the check runs, not what it says. Added a moduledoc entry (#26) documenting the phoenix_kit-repo-only scoping. All 39 existing doctor tests still pass unchanged (they exercise `git_hooks_verdict/1` directly).

## BUG - MEDIUM: `.githooks/pre-commit` enforces a weaker, format-mutating gate than `mix precommit`, so "checks passed" doesn't mean what AGENTS.md implies

`.githooks/pre-commit:184` runs `mix quality` (`format`, `credo --strict`, `dialyzer` — `mix.exs:357`), not `mix quality.ci` (`format --check-formatted`, `credo --strict`, `dialyzer` — `mix.exs:358`) that both `mix precommit` and the manual-dispatch CI workflow use. Concretely:

- `mix format` (no `--check-formatted`) **rewrites files in place**. Since this runs as a `pre-commit` hook *after* `git add` staged the index, a file the hook reformats leaves the **working tree** ahead of what was just committed — the commit succeeds with old (possibly unformatted) staged content, and `git status` immediately after shows an unstaged diff. `mix precommit`/CI would have failed loudly instead (`format --check-formatted`); the hook silently "fixes" it and lets the commit through with mismatched content.
- The hook also never runs `deps.unlock --check-unused` or `test.js`, both part of `mix precommit`. A commit can pass the hook's "🎉 All pre-commit checks passed!" banner while still failing `mix precommit`/CI on an unused dep or a broken JS test.
- The hook additionally runs `mix docs` (`.githooks/pre-commit:184`), which is not part of `mix precommit` at all (it's a `prerelease`-only step) — an extra gate contributors didn't ask for and that isn't documented as required.

**Impact:** "pre-commit checks passed" (the hook's own banner) reads as equivalent to `mix precommit` passing (AGENTS.md step 0 frames the hook as "enabling" the workflow's `mix precommit` gate), but it is neither a superset nor a strict subset — it's a different, partially-weaker, partially-different set of checks. Contributors can get a false green from the hook and fail CI, or get a dirty working tree right after a hook-approved commit.

**Fix applied:** `.githooks/pre-commit` now runs the same four steps as `mix precommit`, in the same order: `mix compile --warnings-as-errors --all-warnings`, `mix deps.unlock --check-unused`, `mix quality.ci`, `mix test.js`. The unrelated `mix docs` step was dropped (not part of `precommit`, not documented as required — a `prerelease`-only step per `mix.exs`). Updated `failing_stage`'s comment and `advise_memory`'s command list to match. Verified `bash -n` syntax and ran `mix test test/mix/tasks/phoenix_kit_doctor_test.exs` clean (unaffected — no test exercises the shell script directly).

## NITPICK: `check_git_hooks` and helpers are otherwise well-designed

`git_hooks_verdict/1` (`lib/mix/tasks/phoenix_kit.doctor.ex:189-232`) correctly distinguishes "not a repo / git unavailable" from "not configured" (the `git config --get core.hooksPath` exit-1-either-way trap is real and correctly guarded against by probing `rev-parse --git-common-dir` first), and `shadow_hook/1` correctly resolves the *common* git dir so a worktree checkout doesn't report a false-clean stale-hook state. Test coverage in `test/mix/tasks/phoenix_kit_doctor_test.exs` for `git_hooks_verdict/1`'s branches is thorough. This part of the design is sound — it's purely the *wiring* into the general host-facing doctor run that's wrong (see BUG - HIGH above).

## Verdict

Both findings were fixed in the coordinating pass (see "Fix applied" notes above). `mix compile --warnings-as-errors` and the doctor test suite (39 tests) pass clean after the fixes. Release-safe as of this review.
