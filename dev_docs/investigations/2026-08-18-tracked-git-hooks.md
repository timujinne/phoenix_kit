# Tracking the pre-commit hook, and a doctor check that admits what it does not know

2026-08-18. Branch `feature/tracked-git-hooks`, commit `fb3b9724`, based on
`upstream/main` (`0636b9ef`).

Written to be read cold, by someone who was not part of the conversation that
produced it.

## Why

This repo's pre-commit hook lived only in `.git/hooks/pre-commit`. `.git/` is
never cloned, never pushed, never reviewed. So the hook existed as a single file
in a single directory on a single machine: a fresh clone had no hook at all, and
nothing anywhere said so. Work that exists in one copy is one `rm -rf` from
gone, and a quality gate nobody knows is missing is worse than one that is
openly absent.

The hook itself had just been rewritten (see
`2026-08-17-precommit-hook-misattributed-failure.md`) to stop blaming credo for
failures that were really the analyzer being OOM-killed. That rewrite would have
died with the container it lived in.

## What changed

| file | change |
|---|---|
| `.githooks/pre-commit` | **new**, mode 100755 — the hook, now tracked |
| `AGENTS.md` | Workflow step 0: the one-time enabling command |
| `lib/mix/tasks/phoenix_kit.doctor.ex` | new "Git Hooks" check + pure verdict function |
| `test/mix/tasks/phoenix_kit_doctor_test.exs` | 9 tests over the verdict's states |

### Adoption is two steps, and git will not do the second for you

    git config core.hooksPath .githooks

Git deliberately refuses to enable hooks from a clone by itself — a clone must
not be able to run code on checkout. One manual command is the floor, and any
proposal claiming zero steps is wrong. That is why the doctor check exists: to
make the omission visible instead of silent.

## The check reports three states, not two

A check that answers "hook not installed" when it merely *failed to look* is
confidently wrong, and sends the reader to fix something that is not broken.
That is the same defect the hook rewrite was about, so it would have been absurd
to reproduce it here.

* **enabled** → `PASS`
* **definitely not enabled** → `WARN`, with the exact command to fix it
* **could not check** → `WARN`, saying so, and explicitly *not* claiming
  anything about whether the hook is installed

### The trap that made this non-trivial

The obvious implementation reads `git config --get core.hooksPath` and treats
exit 1 as "not configured". Verified on this machine:

    inside a repo, key unset   → exit 1
    inside a repo, key set     → exit 0
    OUTSIDE a repository       → exit 1     ← same answer, different meaning
    git absent from PATH       → raises ErlangError :enoent

So exit 1 alone cannot distinguish "not configured" from "not a git repository".
Run `mix phoenix_kit.doctor` from an unpacked release or any non-repo directory
and the naive check would confidently tell you to run a `git config` command
that fixes nothing. Repository-ness is therefore probed separately, with
`git rev-parse --git-common-dir`, and only inside a repo is exit 1 read as fact.

### A second trap: worktrees

Worktrees do not have their own `hooks/` directory — they share the **common**
git dir. A stale-copy check that hardcodes `.git/hooks/pre-commit` reports a
clean tree inside every worktree of a repo that still has one. The check
resolves `--git-common-dir` instead. This repo has three active worktrees, so
this was not hypothetical.

### A third: the executable bit

`.githooks/pre-commit` is committed as mode **100755**. Committed as 100644 it
would be non-executable in every other clone and would silently never run —
"exists but does nothing", which is exactly the failure this change removes.
`git update-index --chmod=+x` guarantees it; `git ls-files -s` shows it.

## Verified by destruction, with the real task

Not by reading the code, and not by asserting the states in a unit test alone.
`mix phoenix_kit.doctor` was run in each state and its output copied verbatim.
States B, C and D were exercised in a throwaway `git clone` so that nothing
touched the shared configuration of this repo's other worktrees.

### A — a fresh checkout, nothing enabled (no manipulation at all)

```
  WARN Git Hooks
       The tracked hook is NOT running: core.hooksPath is not set.
       Fix: git config core.hooksPath .githooks
```

### B — enabled properly

```
  PASS Git Hooks
       tracked hook enabled via core.hooksPath
```

### C — enabled, but a stale copy left in the common hooks dir

```
  WARN Git Hooks
       Enabled, but .git/hooks/pre-commit still exists. core.hooksPath wins, so that copy is
       dead code that will mislead the next reader. Delete it.
```

### D — not a git repository at all (the fail-open case)

```
  WARN Git Hooks
       Could not check — this is not a git repository, or git is unavailable.
       This is NOT the same as "the hook is not installed": nothing was verified.
```

### A' — destruction: `git config --unset core.hooksPath` on a working install

```
core.hooksPath после сноса: exit=1
  WARN Git Hooks
       The tracked hook is NOT running: core.hooksPath is not set.
       Fix: git config core.hooksPath .githooks
```

The check saw it go, and said what to do about it.

Unit tests cover the same states plus the one assertion that matters most —
that the "could not check" and "not enabled" messages are **not equal**, so a
future refactor cannot quietly collapse them back into one:

    29 tests, 0 failures

## Read this before enabling it here

**Do not run `git config core.hooksPath .githooks` in this repository until this
branch has landed on every active branch.** `core.hooksPath` lives in the common
config and applies to all worktrees at once. `.githooks/` exists only on this
branch, so enabling it now would leave every line working on another branch with
**no hook at all** — silently. That is precisely the failure mode this change
exists to prevent, and it would be an ugly way to introduce it.

This is why the shared configuration was left untouched: the states above were
produced in a throwaway clone, and `core.hooksPath` in this repo is still unset.

## One thing left for the repo owner to decide

The hook runs `mix compile --warnings-as-errors`, `mix docs` and `mix quality`.
Whether that gate passes depends on state that is not in the repository: with
the dialyxir PLT already built it passes in about four minutes; with the PLT
absent or invalidated by a `mix.lock` change, rebuilding it needs >2.4 GB of
free memory and gets OOM-killed in a small container. So the gate's colour
depends on whether a file in `_build/` happens to exist. Options: prebuild the
PLT as an explicit setup step, or have the hook detect a missing PLT and say so
before spending four minutes on a run that cannot finish. Measurements are in
`2026-08-17-precommit-hook-misattributed-failure.md`.
