# PR #699 Review — Show the requesting device before the QR approve screen can be used

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/699
**Author:** Alexander Don (alexdont)
**Merged:** 2026-08-10 (`70a246da`, branch `qr-login-device-panel` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-10
**Scope:** 6 files, +259 / −34.

---

## Verdict

**Good, focused PR with an unusually honest diagnosis.** It separates the part
that was PhoenixKit's (a blank device panel under a fully-rendered approval
prompt) from the part that was not (the reporting host's proxy mishandling the
WebSocket upgrade, causing a duplicate mount), and only fixes the former. The
security argument is right: the one screen whose job is *"which device is asking
to sign in as you?"* was rendering the heading, the warning and **both buttons**
while the identifying rows sat behind presence guards on an empty `meta`, which
trains people to approve before the details arrive.

One finding, fixed here, plus the same gap in a second place the PR's own
reasoning covers but its patch doesn't.

### The Iron-Law tension is resolved the right way

Moving the lookup out of the `connected?` gate means it now runs on **both**
renders — normally the thing to avoid. It is correct here: the disconnected
render is what shows the panel, so no amount of `handle_params` or
`assign_async` fixes a static render that must display the data. The PR states
the trade (one extra read of a read-only idempotent lookup, versus a confident
approval prompt with the identity missing) and picks the right side.

---

## BUG - MEDIUM — the new guard covers the raise, not the exit

**File:** `lib/phoenix_kit_web/users/qr_login_confirm.ex`

`look_up/1` was given a `rescue` so a third-party store that fails can't 500 the
dead render. Its comment argues — correctly — that `Keyfob.Store` is a behaviour
a host may implement "over Redis, a database, a cluster-wide cache", and that
those "can be unreachable in ways ETS cannot".

Those stores are reached through a `GenServer.call`, which does **not** raise
when the process is gone or wedged. It **exits** — `:noproc`, `:timeout` — and
`rescue` does not catch an exit.

The PR's own dependency note says so explicitly, one paragraph away:

> before it, a store that wasn't running made the store's reads **raise** and
> its GenServer-backed calls **exit**

So the guard covers one of the two failure modes it names, and the uncovered one
is the likelier of the pair for exactly the third-party stores it exists to
survive — on the dead render, where the same comment notes the cost is a 500
page rather than a quiet remount.

Confirmed rather than reasoned about:

```
rescue only  -> ESCAPED as exit: :noproc
rescue+catch -> :caught_by_catch_exit
```

and the test I added fails without the fix with
`** (exit) exited in: GenServer.call(:phoenix_kit_no_such_keyfob_store, :get, 5000)`.

This is the same rule AGENTS.md already states for settings reads: *"Soft-failure
paths need `rescue` AND `catch :exit`."*

**Fixed:** `catch :exit, reason ->` logs and returns `{:expired, %{}}`, matching
the raise clause. Pinned by a new test whose `ExitingStore.get/1` does a real
`GenServer.call` to a dead name rather than calling `exit/1` by hand, so it
reproduces the shape a store actually produces.

---

## IMPROVEMENT - MEDIUM — the completion path has the same exposure, unguarded

**File:** `lib/phoenix_kit_web/users/qr_login_complete.ex`

The PR pins keyfob `~> 0.1.1` because before it `consume/2` exiting was, in its
words, "a **500 on the finish URL** where 'this link is invalid or has expired'
was both the honest answer and the same outcome".

The pin fixes keyfob's *own* store. `QrLoginComplete.complete/2` still matches
return values in a bare `with`, with no `rescue` and no `catch`:

```elixir
with true <- QrLoginContext.enabled?(),
     {:ok, user_uuid} <- QrLoginContext.consume(token),
```

So for a host-implemented store — the case the PR argues core cannot assume is
total — the 500 it describes is still reachable, on the URL that completes a
login. The reasoning was applied to `peek/1` and not to `consume/2`.

**Fixed:** a `safe_consume/1` that guards **only** the store call, returning
`:error` so the existing `else` gives the honest "invalid or has expired". It is
deliberately not wrapped around the whole `with` — `log_in_user/3` writes the
session, and turning a genuine failure there into a message about the token would
hide a real bug.

---

## Verified and left alone

- **`identifying_details?/1` vs the row guards.** The rows render on truthiness (`:if={@meta[:browser]}`), the summary requires a non-blank binary. No practical mismatch — `device_meta/1` produces binaries or omits the key — and the PR's own test pins that "blank and non-string values do not count".
- **`requested_at` excluded from "we know something".** Correct: it is stamped on every request and says nothing about who is asking.
- **The catch-all `handle_info/2`** added to both QR LiveViews. Right call: the auth `on_mount` hooks pass unrecognised messages through, these modules had no clause, and a crash here is invisible (the client rejoins and reloads, which on the approve screen reads as the scan "not working"). It logs at debug and names the message. The mild cost — a future PubSub clause forgotten would be silently swallowed — is worth less than the crash.
- **`keyfob` pinned `~> 0.1.1`, not `~> 0.1`.** Correct for a 0.x dependency whose failure semantics just changed, and the same reasoning applied to `locale_slug` in #693.
- **`mix.lock`** also moves `phoenix_live_view` 1.2.8 → 1.2.9, a transitive bump not mentioned in the PR body. No API change involved.
- **No information disclosure introduced.** The lookup moving to the dead render does not widen who can read a request's device meta; the mount is authenticated by the `on_mount` chain, which runs for both renders.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit_web/users/qr_login_confirm.ex` | `look_up/1` gains `catch :exit` alongside its `rescue` |
| `lib/phoenix_kit_web/users/qr_login_complete.ex` | `safe_consume/1` guards the store call on the finish URL |
| `test/phoenix_kit_web/users/qr_login_confirm_test.exs` | +1 test: a store that EXITS reads as expired (verified red without the fix) |

## Gate

`mix precommit` clean. `mix test test/phoenix_kit_web/users/qr_login_confirm_test.exs`
— **9 tests, 0 failures**; without the `catch :exit` clause, **1 failure**, which
is the new test doing its job. These need no database, so they genuinely ran.
