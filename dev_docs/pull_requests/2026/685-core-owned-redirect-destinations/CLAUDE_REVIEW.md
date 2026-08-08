# PR #685 — Core-owned redirect destinations: one resolver, and an `/admin` landing that admits everyone

**Author:** timujinne · **Merged:** 2026-08-07 (`ed220003`) · **Base:** `main`
**Reviewer:** Claude (Opus 5) · **Reviewed:** 2026-08-07 (post-merge)

**Verdict: sound, and unusually well argued.** The termination argument holds
under adversarial reading — I walked every gate that can now redirect (owner
hook, admin-area hook, module-access hook, the four plugs, the mid-session
scope-refresh eviction) and could not construct a loop. One real regression
found and fixed; the rest are documentation drift and follow-ups.

Gate: `mix precommit` → exit 0. Unit suite (no PostgreSQL): **1594 tests,
18 doctests, 0 failures**, 1219 integration excluded. `mix gettext.extract
--check-up-to-date` clean; all 7 translated locales at 100%, 0 fuzzy.

---

## What the PR does

Replaces eleven hardcoded `"/"` / `Routes.path("/")` destinations with one
resolver, `Routes.safe_destination/2`, which probes every candidate against the
caller's own router (`Phoenix.Router.route_info/4` off `conn.private.phoenix_router`
or `socket.router`) and terminates on a path core declares **and permits**
unconditionally. To make that terminal real, `/admin` was turned into a landing
that admits every authenticated visitor — gate exception via
`Auth.landing_view?/1`, with the whole operator half of the page moved into
`PhoenixKitWeb.Live.Dashboard.Overview` and permission-gated card by card.

---

## BUG — MEDIUM · The home-page fallthrough lost the visitor's locale · **FIXED**

`authenticated_candidates/1` and `anonymous_candidates/0` offered only the bare
`"/"` as the home-page candidate, and `home_or_core_landing/2` probed only `"/"`.

Before this PR the eleven sites emitted `Routes.path("/")` — the *locale-prefixed*
root (`/et`). The design is right that emitting it **unprobed** was the shipped
defect. But the fix dropped the shape entirely rather than probing it, and that
regresses the host configuration core's own release notes have been asking for
("the parent app declares a `/:locale` landing", CHANGELOG 1.7.150):

| Host declares | Before #685 | After #685 (as merged) |
|---|---|---|
| `/` only (e.g. andi) | 404 — the bug | `/` ✔ the fix |
| `/` **and** `/:locale` | `/et` — locale kept | `/` — **language silently flips** |
| `/:locale` only (documented advice) | `/et` ✔ | home page skipped entirely; anonymous chain terminates on `/users/log-in` |

Rows 2 and 3 are logout, the maintenance eject, a failed password reset, a
failed OAuth add-account, and the post-login landing. Row 3 is the worse one: a
logged-out visitor on a correctly-configured multilingual host used to land on
the site home and now lands on the sign-in page.

**Fix applied** (`lib/phoenix_kit/utils/routes.ex`): a private `home_candidates/0`
offers both shapes, locale-prefixed first, *both probed like every other
candidate*. It cannot reintroduce the 404 — that is the whole point of
`routable?/2` — and it collapses to a single `"/"` candidate wherever no locale
prefix applies (single-language install, or default language configured
prefixless). Under a mount prefix `path("/")` yields `/phoenix_kit/en`, which is
core's own mount point rather than the host's home; the probe simply refuses it,
which is precisely why asking the router beats trusting the shape.

The moduledoc invariant was restated accordingly: the guarantee is that nothing
is ever returned **unprobed**, not that a particular shape is never named.

Tests: `safe_destination_test.exs` gains `LocalizedHomeRouter` (declares both
shapes) plus a test asserting the locale-carrying form wins there; the fixture
asserts `Routes.path("/") == "/phoenix_kit/en"` so a config change fails loudly
instead of silently testing nothing. The router is added to THE INVARIANT's
context table, and the categorical `refute result == Routes.path("/")` becomes
"if the result is either home shape, it must be routable in this router" — the
accurate statement.

---

## IMPROVEMENT — HIGH · The design doc that shipped describes a design that was abandoned · **NOTE ADDED**

`dev_docs/plans/2026-08-06-core-owned-redirect-destinations.md`, added by this
PR, ends with "Follow-up: one universal dashboard", which specifies:

- `/dashboard` as the guaranteed landing for every authenticated user;
- `user_dashboard_enabled` stopping at "what the page shows" so the route
  becomes unconditional;
- `home_or_core_landing(nil, _opts)` returning `path("/dashboard")`;
- `terminal/3` losing its probe because the terminal cannot fail.

**None of that shipped.** The landing is `/admin`; `/dashboard` is still
conditionally compiled and is an ordinary probed candidate; the context-less
tail is `path("/admin")`; and `terminal/2` keeps the probe as a diagnostic
(`unreachable_terminal/3` logs, then returns the arm anyway). The doc also
refers to "GLM's Finding 1 / Finding 2" with no such document anywhere in the
tree.

The gating half of that section *did* ship — just on `/admin`. Since the two
halves landed differently, a reader who trusts the doc gets the wrong model of
the code.

**Applied:** a `⚠️ Superseded` block at the head of that section stating what
actually shipped and pointing at `safe_destination/2`'s moduledoc as the source
of truth. The section is left intact as history.

---

## IMPROVEMENT — MEDIUM · `NotificationsBell`'s `can_open_inbox` is frozen at first mount

`layout_wrapper.ex` computes `can_open_inbox` from
`Auth.can_access_admin_view?(scope, Notifications.Inbox)` and passes it in the
bell's `session` map. The bell is `sticky: true` — its session is read once, at
the socket's first mount, and is **not** re-read on `push_navigate` within the
live_session, which is every admin navigation.

This is the one place in the PR where its own invariant — "an entry is rendered
only if the visitor can open it", which the sidebar re-derives every render and
the dashboard re-derives on every scope change via `refresh_view_scope_assigns/1`
— can drift:

- demoted to zero permissions mid-session → the "View all" footer stays, and
  `:phoenix_kit_ensure_admin` bounces the click;
- granted a permission mid-session → the footer stays hidden until a full page
  load.

Impact is small (only visitors holding *zero* permissions are on the false side
of the gate, and the failure is a flash, not a leak), which is why I have not
changed it. The clean fix, if it is ever worth doing: the bell already knows its
`user_uuid`, so subscribe it to `ScopeNotifier` and recompute `can_open_inbox`
on `{:phoenix_kit_scope_roles_updated, uuid}` — the same event
`PhoenixKitWeb.Users.Auth`'s scope-refresh hook already listens for.

---

## IMPROVEMENT — MEDIUM · `Overview.assign_overview/3` queries in `mount/3`

`assign_scope_gates/1` → `assign_statistics(socket, true)` runs
`Roles.get_extended_stats/0`, `Sessions.get_session_stats/0`,
`Presence.get_presence_stats/0`, `Migrations.current_version/0` and
`Migrations.migrated_version_runtime/1` — from `mount/3`, which LiveView calls
twice (dead render + WebSocket).

Pre-existing: the old `dashboard.ex` did exactly this. But the PR promoted it
into a documented, `use`-able entry point whose moduledoc shows
`Overview.assign_overview/3` being called from `mount/3` — so every future
adopter inherits the double query. `handle_params/3` or `assign_async/3` is the
repo-idiomatic home for it.

Two smaller things in the same function, both carried over verbatim:

- `Migrations.migrated_version_runtime(%{prefix: "public"})` hardcodes the
  schema. On a named-schema install (`config :phoenix_kit, prefix:`) System
  Information reports the wrong migrated version.
- `module_toggled/1` now calls `refresh_view_scope_assigns/1`, so a module
  enable/disable broadcast re-runs the three aggregates on **every** connected
  dashboard socket. Correct (a stale gate on the un-evictable landing is worse),
  but worth knowing the cost is now per-socket rather than per-render.

---

## NITPICK · `:return_to` is silently dropped on the anonymous chain

`safe_destination/2` honours `:return_to` only when the scope is authenticated;
`anonymous_candidates/0` ignores it without a trace. Both callers that pass it —
`Session.redirect_back/2` and `OAuth.redirect_back/2` — build their scope by
looking the session token up in the database. That lookup returning `nil`
(token revoked or expired between the pipeline and the redirect) silently
discards the visitor's explicit destination and sends them to `/users/log-in`.

Not reachable today: every caller of both functions requires an already-active
session. But the guard rationale in the `@doc` ("an anonymous pending
destination belongs in the `user_return_to` session key") argues about *intent*,
while the candidate is already `usable_candidate?` + `routable?` guarded, so
honouring it anonymously would be equally safe.

## NITPICK · `push_navigate` vs `redirect` now disagree about the same hazard

`maintenance_page_live.ex` deliberately switched `push_navigate/2` → `redirect/2`
in this PR, with the reason stated inline: "the target may be a host controller
route rather than a LiveView". `apply_scope_refresh_decision/3` (both the
`:evict_admin_area` and `:evict_module` arms) still `push_navigate`s to a value
that came out of `safe_destination/2` and can equally be the host's `/`.
LiveView degrades to a full page load client-side rather than failing, so this
is cosmetic — but the two sites now reason differently about the identical case.

## NITPICK · An invariant-test comment claims more than the test proves

THE INVARIANT asserts "the only admin path the resolver ever synthesizes is the
INDEX". That holds in the test only because the `return_tos` table contains no
admin path — a caller-supplied `return_to: "/admin/users"` with
`skip_admin: false` is returned verbatim (correctly: it is a caller-supplied
path, not a synthesized one). Either add one to the table and assert the
`skip_admin` asymmetry directly, or soften the wording to "synthesizes".

---

## Verified, not assumed

Things I checked against the producing code rather than the PR description:

- **The `/admin` landing really is reachable by everyone.** The admin surface
  has no plug-level auth gate — `public_admin_pipelines/0` is
  `[:browser, :phoenix_kit_auto_setup, :phoenix_kit_locale_validation]`, and the
  `:phoenix_kit_admin_only` pipeline (which does carry `require_admin`) is not
  applied to it. So `admin_gate_decision/2` is genuinely the only gate, and its
  `:landing` branch is reached before `can_access_admin_area?/1`.
- **Termination under `skip_admin`.** Walked the worst case the PR describes —
  `user_dashboard_enabled: false`, `after_login_path: "/admin/users"`, a visitor
  with one non-fallback permission. `admin_area_path?/1` drops the setting,
  `"/"` is not routable, terminal `/admin` renders. Also walked the paths that
  do *not* pass `skip_admin` (`ensure_owner`, `require_owner`, `require_role`):
  they can hand back a gated admin page once, which bounces into the
  `skip_admin` path and terminates there. One extra hop, no loop.
- **`conn_scope/1` reads the right key.** `MultiSession` keeps the active token
  in `:user_token` (`multi_session.ex:573`), so building the scope from the
  session rather than from `conn.assigns` — the stated reason being that
  impersonation and account-switch have already swapped the active account —
  resolves the account the redirect is actually for.
- **All five dashboard card views resolve to a real key.** `PhoenixKitWeb.Users.UserForm`
  ("Add User") is not under `Live.Users` and resolves through no inference
  layer; it is explicitly mapped to `"users"` in `@admin_view_permissions`, so
  the card does not fall into the unmapped fail-closed branch.
- **`can_open_inbox` cannot regress other layouts.** `NotificationsBell` is
  embedded from exactly one place (`layout_wrapper.ex:522`), so the new
  fail-closed default (`session["can_open_inbox"] == true`) cannot hide the
  footer anywhere that used to show it.
- **gettext.** No new untranslated msgids: the welcome block reuses the existing
  `"Welcome back"` and appends the name in markup rather than minting
  `"Welcome back, %{name}"`, and the `"Admin Panel"` label is *omitted* for
  permission-less visitors rather than replaced. `.pot` is up to date.

---

## Behaviour changes that need a CHANGELOG entry

No entry exists yet (`CHANGELOG.md` still heads at 1.7.233, and #685 merged
after it). These are visible to existing installs and should not be discovered
by a host author:

1. **`/admin` admits every authenticated visitor.** One holding no permissions
   gets the welcome block and nothing else — no sidebar, no burger button, no
   drawer column, no "Admin Panel" breadcrumb label, no navigation landmark.
2. **Platform Statistics, System Information and Refresh now require
   `Scope.holds_all_enabled_permissions?/1`.** A default Admin still passes (the
   check compares against the operator baseline, opt-in keys excluded), but a
   narrow custom operator role that previously saw the whole dashboard now sees
   only the cards it has permission for. This is the intended role-agnostic
   policy, but it is a visible reduction for existing installs.
3. **New `main_page_path` site setting** (general settings, beside Project Title
   and Site Address) — the anonymous "home" destination. Empty = core's own
   `/users/log-in`. Deliberately not defaulted to `"/"`.
4. **Every core redirect that pointed at `"/"` now resolves through
   `Routes.safe_destination/2`** and is proven to resolve in the host's router
   before anyone is sent there.

---

## Follow-ups not done here

- The design's **host affordance** (`config :phoenix_kit, home_path: {Mod, :fun}`
  or a macro emitting the validated `/:locale` landing) and the **`doctor`
  warning** for "more than one language enabled and no locale-prefixed root
  route" are both still open. The fix above narrows the need for them but does
  not remove it.
- The design's **locale-canonicalisation** item (redirect `/{locale}` → `/` where
  the prefixed root is a duplicate) did not ship and is not covered by the
  locale matrix the Testing section calls for.
