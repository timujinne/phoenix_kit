# PR #677 — Host-app feedback triage: security, bugs, and a delivery fix

**Author:** Max Don (`mdon`)
**Merge commit:** `78990518`
**Reviewed:** 2026-08-03, post-merge, against the merged state (including the
four self-review fix commits `f8d1c0d3`…`6d6a7484`).
**Scope:** 84 files, +7176 / −898.

The PR's own three review passes (plan-aware, area-only, blind) found 16 defects
and fixed them in-tree. This pass looked for what survives all three — with
particular attention to the places where a rule is stated in one file and
applied in another, since that is the shape a single-file review cannot see.

Five findings. All fixed here.

---

## BUG - CRITICAL — `ConsentConfigController` collides with the module name published `phoenix_kit_legal` still ships

**Where:** `lib/phoenix_kit_web/controllers/consent_config_controller.ex`,
`lib/phoenix_kit_web/integration.ex:274`

The new controller is named `PhoenixKitWeb.Controllers.ConsentConfigController`
— byte-identical to the module `phoenix_kit_legal` defines. The PR notes this
and calls for a paired legal PR, and that PR exists locally
(`phoenix_kit_legal@a061947`, "Remove the consent-config controller, which core
now owns"). **It is not published.** `phoenix_kit_legal` 0.1.9 went to Hex on
2026-07-26; the removal is dated 2026-08-03 and the version was never bumped.
0.1.9 is the only release on Hex, and it still contains the controller.

Legal's dep requirement is `{:phoenix_kit, "~> 1.7.189"}`, which happily
resolves against this release. So the moment core ships, any host on
`phoenix_kit_legal 0.1.9` compiles one module name into two applications, and
code-path order — not either package — decides which one answers
`/api/consent-config`. Nothing in either package states the dependency, so
nothing detects the breakage.

Coordinating the two publishes would fix the forward order only, and leave every
host that upgrades core first broken until they also upgrade legal.

**Fixed:** renamed to `PhoenixKitWeb.Controllers.ConsentConfig`. The route was
the module's only reference, so the rename is free, and it makes the pair safe
in *both* upgrade orders rather than only the one where legal moves first. Old
legal's copy becomes an unreferenced dead module instead of a coin flip.
Regression test added in `consent_config_test.exs` asserting the route's `plug`
is the new name and explicitly *not* the legal-owned one.

> `phoenix_kit_legal` should still publish 0.1.10 with its removal — but that is
> now hygiene, not a blocker on this release.

## BUG - HIGH — the unadmitted-account janitor starves itself and deactivates nobody

**Where:** `lib/phoenix_kit/users/referrals.ex` — `prune_unadmitted/1`

The candidate query takes the oldest `@prune_batch_size` (500) active accounts
with no `referral_satisfied_at` stamp, then re-checks each through
`access_satisfied?/1`, which is correct and deliberate.

But grandfathered accounts match that pre-filter **permanently**. Grandfathering
is re-evaluated per request and never written down (deliberately — so turning
the setting off parks those accounts), so they never gain a stamp. And
grandfathering is defined as "created at or before the boundary", which makes
grandfathered accounts precisely the *oldest* rows — the ones an
`order_by: [asc: :inserted_at], limit: 500` reaches first.

So on any install with more than 500 pre-existing active users, the batch fills
entirely with exempt accounts, `access_satisfied?/1` rejects all 500, and the
sweep deactivates nobody. Every day. Forever. It fails on exactly the install it
exists for — an established site that has just switched invite-only on — and it
fails *silently*: the per-account check keeps the result correct while the
feature is inert. `{:ok, 0}` is indistinguishable from "nothing to do".

**Fixed:** pushed the grandfather predicate into SQL (`exclude_grandfathered/1`)
so exempt rows never occupy a batch slot. It reads the same setting and the same
boundary `grandfathered?/1` does, and only applies when grandfathering is on and
a boundary exists — with grandfathering off, those accounts are supposed to be
swept, which is the complement the second test pins.

The per-account `access_satisfied?/1` check remains the authority; the
exemptions SQL cannot see (full permissions, a pending invitation) are why.

Extracted `prune_candidates/1` so the exclusion is assertable at two accounts.
Demonstrating the starvation through the sweep itself needs 500 registered users
— a test nobody would run, and therefore not a test.

## BUG - MEDIUM — three soft-failure paths in the new gate code rescue but do not `catch :exit`

**Where:** `lib/phoenix_kit/users/referrals.ex` — `invited?/1`,
`fallback_boundary/0`, `log_deactivation/1`

`AGENTS.md` states the rule, and this file's own `stamp/2` and `dispatch/2`
follow it: an unreachable database *raises* on an unowned checkout but *exits*
on a dead pool, so a path that must not crash needs both clauses. Three of the
new functions have only the `rescue`.

Two of them are on the authentication path, which is what makes this matter:

- `invited?/1` runs a real query (`Invitations.list_pending_for_email/1`) — the
  most likely of the three to exit — and its own comment says "a gate that
  crashes locks users out of the whole application". With only the `rescue`, the
  exit escapes through `access_satisfied?/1` and does exactly that.
- `fallback_boundary/0` is an *uncached* settings read reached from
  `access_required?/0`, i.e. every gated page.
- `log_deactivation/1` is in the Oban sweep; its comment says a failure "must
  not raise: it would abort the remaining candidates AND make Oban retry the
  whole batch against accounts it has already deactivated" — an exit does
  precisely that.

Settings reads are ETS-cached, so this presents as a rare, hard-to-reproduce
lockout rather than a clean failure.

**Fixed:** added `catch :exit, _reason` to all three, matching the surrounding
idiom and message style.

## BUG - MEDIUM — `allow_registration` is not enforced on the magic-link completion route

**Where:** `lib/phoenix_kit_web/users/magic_link_registration.ex`

The PR added a `magic_link_registration_enabled?` gate to the completion page
with the right reasoning: *"a link already sitting in an inbox still creates an
account after an admin has switched magic-link registration off."* That argument
applies with more force to `allow_registration`, the broader "no new accounts at
all" switch — and the completion page never reads it. The *request* page checks
both; the page that actually creates the account checks only the narrow one.

So an admin who closes registration outright still has every in-flight
magic-link token creating accounts. This is the same
button-hidden-route-still-open shape the PR set out to close, one setting over.

**Fixed:** the completion mount now checks both, as a `cond` so the redirect
stays useful — `/users/register` when only magic-link is off, `/users/log-in`
when registration is closed outright (sending them to a closed register page
would just bounce them again). Integration test added to `auth_flows_test.exs`
exercising a real token across the setting flip.

## BUG - MEDIUM — `allow_registration` is checked in `mount/3` but not on submit

**Where:** `lib/phoenix_kit_web/users/registration.ex`

Same class, password path. `mount/3` gates on `allow_registration`; the `"save"`
handler does not. A LiveView socket outlives the page load that created it, so a
form mounted while registration was open keeps a working submit endpoint for as
long as the tab stays open. Closing registration has to close the submit, not
only the entrance.

Narrower than the magic-link gap (it needs a socket held open from before the
flip, rather than a URL), but the same fix and the same principle.

**Fixed:** re-checked at the top of the `"save"` handler, with the body split
into `do_save/3`. No existing test can reach the new branch — when the setting is
off, `mount/3` already redirects — so this is additive.

---

## Reviewed and deliberately not changed

- **`Referrals.prune_candidates/1` remains an N+1** — up to 500 `invited?/1`
  queries per sweep. It runs once daily off-cron on a bounded batch, and
  batching the invitation lookup would duplicate `access_satisfied?/1`'s
  precedence logic in a second place. Worse trade than the query count.
- **`apply_hidden_admin_tabs/1` does not cascade to subtabs.** Hiding a parent
  leaves its children registered, but `get_top_level_tabs/1` filters on
  `parent == nil` and `get_subtabs/2` filters on a parent that is now absent, so
  orphans render nowhere. Cosmetically correct by accident rather than by
  design, but correct.
- **The `"!replace"` sentinel is only honoured in first position.** Documented,
  tested, and deliberately awkward. Accepting it anywhere would make a pattern
  list order-insensitive in one respect and not others.
- **`Cache.expires_at/1` jitter is forward-only** (`ttl + rand(ttl/10)`), so
  entries live slightly longer than the nominal TTL rather than expiring early.
  Correct for a settings cache; noting it because "10% jitter" usually means
  symmetric.
- **`button/1` passing `navigate={nil} patch={nil} href={...}` into `<.link>`**
  is fine — `Phoenix.Component.link/1` dispatches on binary guards, so explicit
  nils fall through to the intended clause.
- **`ensure_worker_cron_entries/2` backfills only the referral PruneWorker.**
  Correct for this PR. Whether `Notifications.PruneWorker` and
  `Storage.Workers.PruneTrashJob` need the same backfill depends on install
  vintages I can't establish from this repo; flagging rather than guessing.

## Verification

`mix precommit` — green (exit 0): `compile --warnings-as-errors --all-warnings`,
`deps.unlock --check-unused`, `quality.ci` (format check + `credo --strict` +
dialyzer), `test.js` (21/21).

`mix test` was not run: no PostgreSQL in this environment, and per `AGENTS.md`
core is not meant to be standalone-tested — the gate is the bar. The five tests
added here (two unit-level on `prune_candidates/1`, one router-level on the
controller name, two integration-level on `allow_registration`) are therefore
**unverified locally** and will first execute in a host suite or CI.
