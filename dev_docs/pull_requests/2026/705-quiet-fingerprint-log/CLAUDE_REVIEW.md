# PR #705 — Make the fingerprint log mean something

**Reviewer:** Claude (post-merge sweep, 2026-08-11)
**Verdict:** Merged. One MEDIUM bug fixed on main — the PR's own rule, applied
to the two branches it missed.

## Summary

The diagnosis is right and the direction is right. 765 unactioned warnings plus
`[error] ... possible hijacking attempt` lines on requests that were then served
is a log that teaches people to ignore it, and the duplicate line in
`PhoenixKitWeb.Users.Auth` that said only `"for token"` — naming no token — was
pure volume. Removing it is correct: the surviving line says strictly more.

`session_label/1` is the right shape. Truncated SHA-256 of a bearer credential,
8 hex characters, enough to group lines and useless to anyone who steals the
file. The `defp session_label(_), do: "unknown"` fallback means a caller that
passes nothing still logs rather than crashing a request it was only meant to
describe.

The stated principle is the good part:

> The level follows what actually happens.

## BUG - MEDIUM: the principle was applied to one branch out of three

`lib/phoenix_kit/utils/session_fingerprint.ex` — `verify_fingerprint/4`.

The `{false, false}` branch picks `:error` vs `:warning` from `strict_mode?()`.
The other two branches log at a fixed level: `:warning` for IP-only, `:info` for
user-agent-only.

But strict mode does not only deny the both-changed case. It denies **every**
mismatch — `PhoenixKitWeb.Users.Auth` answers `{:warning, _reason}` with exactly
the same `not SessionFingerprint.strict_mode?()` it answers `{:error, _}` with,
and it is the only consumer of the return value:

```elixir
{:warning, _reason} ->
  not SessionFingerprint.strict_mode?()

{:error, :fingerprint_mismatch} ->
  not SessionFingerprint.strict_mode?()
```

So on a strict-mode host:

- a user whose **browser updated itself** is logged out, and the only record of
  it is an `:info` line — below the default `:warning` threshold, so on a
  normally-configured app there is **no record at all**;
- a user whose **IP changed** is logged out, recorded as a `:warning`
  indistinguishable from the non-strict case where the request was served.

That is the same defect the PR set out to fix, pointing the other way. Before,
`:error` overstated a served request; now `:info` understates a refused one. An
operator working out why a user was bounced has nothing to find — and the
demotion of the user-agent line, which is correct and valuable for the ~99% of
hosts that do not run strict mode, is exactly what hides it for the ones that
do.

**Fixed on main:** extracted `log_mismatch/2`, which takes the level the line
earns *when the request is allowed* and overrides it to `:error` when
`strict_mode?()` denies. Non-strict behaviour is unchanged in all three
branches — the existing tests pass untouched, which is the evidence for that.
Two tests added covering a denied UA-only and a denied IP-only change.

## Notes, not defects

- `strict_mode?()` is now read twice per mismatched request (once here, once by
  the web caller). It is an `Application.get_env` read behind
  `PhoenixKit.Config.get_boolean/2`; not worth threading.
- The test suite lowering `Logger.level` in `setup` with an `on_exit` restore is
  necessary and correctly done — from the outside "logged at `:info`" and "not
  logged" are the same string. `async: false` is right given it mutates Logger
  level and application env.
- `test "a caller that gives no label still logs"` asserts the line survives but
  not that it says `unknown`. Harmless.
