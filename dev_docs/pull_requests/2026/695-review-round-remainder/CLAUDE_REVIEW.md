# PR #695 Review — Close the remaining review findings, rebuilt onto current main

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/695
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`fe3bb9e9`, branch `fix/review-round-remainder` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 8 files, +148 / −48, 1 commit.

---

## Verdict

**Clean. No new defects found.** Six findings, each correctly diagnosed and
correctly fixed, and the two that introduce new return values propagate them
completely — which is the thing this series has repeatedly got wrong, so I
checked every consumer rather than the ones the diff touched.

It also drops the author's own version of the comment-less guard in favour of
`80fc6784`, with an accurate account of why (his required a positive "there is
no comment" and fell through to the destructive branch on any failure to answer;
the replacement requires a positive "the comment reads 1"). Nothing to add.

### `estimated_rows/3` → `:unknown` — every consumer checked

`reltuples = -1` (PostgreSQL ≥ 14, "never vacuumed or analyzed") was being
collapsed to `0` by `COALESCE(NULLIF(c.reltuples, -1), 0)`, so a freshly
restored 200k-row table answered "small enough, proceed" to the guard whose
entire job is to keep an unbounded `ACCESS EXCLUSIVE` pass out of
`mix ecto.migrate`. Correct diagnosis, and the fix is honest rather than
convenient.

Two consumers, both handled **explicitly**:

- `v163.ex` — `too_big_or_unmeasured?(:unknown, _limit), do: true`. Worth calling
  out that this is a pattern match and not `rows > limit`: under Elixir term
  ordering `:unknown > 2_000_000` is already `true`, so the code would have
  behaved correctly by accident. Writing the clause means the next person cannot
  break it by normalising `:unknown` to a number.
- `repair_uuid.ex` — prints `"size unknown — never analyzed"` rather than
  `"~0 rows"` to an operator sizing a maintenance window. Right call; the number
  is the whole reason they are reading that line.

The guard itself is right too: `{:ok, %{rows: [[n]]}} when is_integer(n) and n >= 0`,
so `-1` falls to `:unknown` rather than being negative-but-accepted.

### `Probe.read_comment/2` → `:unparseable` — every consumer checked

Previously both "no comment" and "corrupt comment" returned `nil`, so
`adopt_required_message/0` told the operator the comment was *missing* while the
table said `v164`, and `--adopt` stamped the floor over it. The fourth value
routes to `:comment_unreadable`, which refuses instead of adopting.

Propagation traced end to end:

| Consumer | Handled |
|---|---|
| `Probe` line 66 (only caller of the private `read_comment/2`) | ✅ |
| `CommentPolicy.classify/3` (only caller, `repair.ex:207`) | ✅ new clause |
| `Repair.run` case | ✅ new `:comment_unreadable` branch |
| `Repair.error_message/1` | ✅ new clause |
| `Repair.error/0` type | ✅ union extended |
| `phoenix_kit.repair.ex` JSON path — `error_tag/1` | ✅ by its `{tag, _}` clause |
| `phoenix_kit.doctor.ex` | ✅ routes through `error_message/1` generically |

The refusal reasoning is the best thing in the PR: *"whatever is written there is
the only record of what the last person believed"* — so `--adopt` declines rather
than overwrites. That is the right instinct for a repair tool.

The added `n > 0` guard also incidentally closes a nitpick from the #694 review:
`Probe` and `Common.parse_version_comment/1` now agree on non-positive integers,
where they previously diverged.

### The `'0'` behaviour change is unreachable

`'0'` now returns `:unparseable` where it used to return `0` → `:adopt_required`.
`CommentPolicy.classify(0, …)`'s clause is consequently dead on the Probe path.
Harmless: `rg "IS '0'"` across `lib/` finds nothing, so no migration ever stamps
it.

### The remaining four

- **`mix phoenix_kit.status --verbose` crashed** after printing a correct tree —
  `show_installation_diagnostics/2` had no `{:unknown_version}` clause. Fixed,
  and the commit is candid that this was "the clause I claimed to have added two
  commits ago and had not".
- **V164's post-ADD probe aborted the whole chain.** Moving verification to
  `fk_shape_present/5` was right for correctness and wrong for failure mode: that
  probe raises where the `fk_exists?/3` it replaced returned false, and V164 has
  no `rescue` and no `run_isolated/3`, so one flaky catalog read on one of ~70
  constraints would abort mid-run with earlier repairs already auto-committed
  (`@disable_ddl_transaction`) and the version comment never stamped. Now wrapped
  into a `{:failed, …}` summary line. Correct, and the asymmetry argument for
  wrapping *after* the ADD but not before is right.
- **`comments_fk_on_delete/1` read by name alone**, so an impostor constraint's
  `confdeltype` of `'n'` read as "already SET NULL, nothing to do" and the real
  missing FK was never created. Now anchored on type, arity and column.
  `fk_validated?/3` stays name-only and the comment says exactly why (every
  caller reaches it through the shape gate) — the right way to leave a
  deliberately narrow query in place.
- **V163's deferral text** no longer points at a remedy that cannot work on a
  table whose values are not castable.

---

## Note on the test claim

The PR reports "test/phoenix_kit — 1153 tests, 38 doctests, 0 failures". True,
and scoped: the two tests that are red live in
`test/mix/tasks/phoenix_kit_release_check_test.exs`, outside that path. A full
`mix test` on this tree is **1943 tests, 2 failures**, both the stale
`chain_hash` (see below). My own earlier runs were scoped the same way and missed
them too.

## Note for the release

#695 edits `v163.ex` and `v164.ex` again, so `chain_hash` moves again. As with
#694, both edits are **guard, probe and message logic — no schema objects** — so
they remain in the class `restamp_chain_hash.exs` permits. V165 and V166 are
still the only versions that add manifest objects.

Concretely, the blocker's blast radius is larger than "release_check fails":

```
1) test check_migration_sync/0 … (Mix.Tasks.PhoenixKit.ReleaseCheckTest)
2) test check_manifest_chain_hash/0 … (Mix.Tasks.PhoenixKit.ReleaseCheckTest)
```

`mix test` has been red on `main` since #692 merged. Both failures clear the
moment the manifest question is settled.

## Gate

No code changes in this pass. `mix precommit` passes; `mix test` is 1943 tests,
2 failures, both the manifest hash described above.
