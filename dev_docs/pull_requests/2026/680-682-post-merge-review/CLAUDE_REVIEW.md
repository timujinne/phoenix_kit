# Post-merge review — PRs #680, #681, #682

**Reviewer**: Claude (post-merge, on `main`)
**Date**: 2026-08-05
**Range**: `6321f5ba..acac57ed` (merges `105840f9`, `62d557d1`, `acac57ed`)
**Shipped in**: 1.7.231

Written as one document because the three PRs merged as a single wave two
minutes apart and share a release. PR #681 already carries a pre-merge
`CLAUDE_REVIEW.md` written by the author's own agent run
(`681-case-insensitive-username/`); this file does not touch it.

**Verdict: all three are sound.** No critical or high-severity bug found.
Both migrations are correct, prefix-safe and idempotent, and `UrlState` is a
genuinely careful piece of work — the constraint derivation about
`handle_params/3` and embeddability is right, verified against
`phoenix_live_view` source below. What follows is one performance fix that
#681 left on the table, one missing test, and a design gap worth recording.

---

## Findings

| # | Severity | PR | Summary | Status |
|---|----------|----|---------|--------|
| 1 | IMPROVEMENT - HIGH | #681 | Username login still runs `LOWER(username)`, matching no index — a sequential scan on an unauthenticated endpoint | **Fixed** |
| 2 | IMPROVEMENT - MEDIUM | #681 | The PR's stated user-facing symptom is wrong; the real pre-V161 failure was worse | **Recorded** (changelog corrected) |
| 3 | IMPROVEMENT - MEDIUM | #682 | V162 ships with no test at all | **Fixed** |
| 4 | IMPROVEMENT - MEDIUM | #680 | `UrlState` preserves unknown query keys forever, with no way to drop one | **Recorded, deliberately not fixed** |
| 5 | NITPICK | #680 | JS hook never calls `removeHandleEvent`, leaking a callback per remount | **Fixed** |
| 6 | NITPICK | #682 | PR-draft doc filed under a stale directory name that collides with #680's | **Fixed** |
| 7 | IMPROVEMENT - LOW | #682 | An *undeclared* dotted permission key still hits the raise the fix removes | **Recorded** |

---

### 1. IMPROVEMENT - HIGH — username login never uses the unique index (#681)

`lib/phoenix_kit/users/auth.ex`, `get_user_by_email_or_username_and_password/3`:

```elixir
from(u in User,
  where: fragment("LOWER(?)", u.username) == ^String.downcase(email_or_username)
)
|> Repo.one()
```

The whole premise of V161 is that comparison semantics come from the column
type, so one `ALTER` fixes *every* lookup. It does — `Repo.get_by(User,
username: …)` at `auth.ex:113` became case-insensitive for free. But the
login path hand-rolls its own case folding, and a `LOWER(username)`
expression cannot use `phoenix_kit_users_username_uidx`, which is a plain
b-tree on the bare column. There is no functional index on
`lower(username)` anywhere in the chain.

So after V161 this query is both redundant *and* the only username lookup in
the codebase that sequentially scans `phoenix_kit_users` — on the login
endpoint, which is by definition reachable without authenticating. Rate
limiting caps the per-caller rate, not the per-query cost.

Plain equality is correct on a `citext` column and the partial index
(`WHERE username IS NOT NULL`) is usable, because `username = $1` implies
`username IS NOT NULL`.

**Fixed** — the branch now calls the module's own `get_user_by_username/1`.
Behaviour is identical (`Repo.one` and `Repo.get_by` both raise on multiple
matches; after V161 the unique index makes multiple matches impossible),
minus the scan.

### 2. IMPROVEMENT - MEDIUM — the described symptom was not the real one (#681)

The PR body says:

> signing in by username is case-sensitive too, so typing your own name with
> different capitalisation lands you in a *different account*. To the user
> that reads as "my permissions disappeared", with no error anywhere.

That is not what the code did. The login path (finding #1) has always
lowercased both sides and is annotated `# Treat as username - case-insensitive
lookup`, with a doctest pinning `"JohnDoe"` → `{:ok, %User{}}`. Login by
username was already case-insensitive before V161.

What actually happened once `Pavel` and `pavel` both existed is worse, not
milder: that query matches **both** rows, and `Repo.one/1` raises
`Ecto.MultipleResultsError`. Username login for both accounts 500s outright
— a hard failure, not a silent wrong-account. (Email login was unaffected;
`email` has been `citext` since V01.)

This changes nothing about the fix, which is correct either way, but the
severity story matters for anyone reading back why V161 exists, and the
changelog entry should describe the failure that happened. **Recorded**;
the 1.7.231 changelog entry states the `MultipleResultsError` symptom.

### 3. IMPROVEMENT - MEDIUM — V162 has no test (#682)

V161 shipped with `test/phoenix_kit/migrations/v161_test.exs` pinning its
post-migration schema state. V162 shipped with none, so nothing asserts the
column, the FK, or — most importantly — the `ON DELETE SET NULL` action.

That last one is the whole design decision of the migration, and it is
exactly the kind of thing a later refactor erases by reaching for a plain
`references/2` (whose default is `RESTRICT`), turning "deleting a payment
option is an ordinary operator action" into "deleting a used payment option
is impossible" with no test failing.

**Fixed** — added `test/phoenix_kit/migrations/v162_test.exs` in V161Test's
shape: column type/nullability, FK target, `confdeltype = 'n'`, index
presence, version marker.

**Verified while reviewing** (and now recorded in the PR doc): V45 creates
`phoenix_kit_payment_options.uuid` *without* a unique constraint, which
would make V162's `REFERENCES … (uuid)` fail outright. The referenceable
unique index comes from V56 (`@tables_ensure_index` includes
`:phoenix_kit_payment_options`), which runs long before V162. The chain is
safe on both fresh installs and upgrades — but the dependency is implicit
and worth knowing about.

### 4. IMPROVEMENT - MEDIUM — unknown query keys are preserved with no escape hatch (#680)

`UrlState` deliberately carries query keys its spec does not own across
every patch (`extra_params/2` → `encode/3`), so the media selector's
`?return_to=…&mode=single` survives a search. That is the right default and
the motivating case is real.

The gap is that there is no way to *stop* carrying one. A key that means
"do this once" — open a modal, consume a token, apply an invite — becomes
permanent for the life of the LiveView: every subsequent search, filter or
page patch re-emits it, and every `handle_params/3` clause matching it fires
again. `users.ex` has the shape of exactly this
(`handle_params(%{"action" => "add"}, …)` → `assign(:show_add_user_modal,
true)`), and it would reopen on every keystroke pause of a search.

**Deliberately not fixed.** GLM's pre-merge review already established that
this instance is inert — `show_add_user_modal` is assigned in two places and
read nowhere; there is no modal, and nothing in the repo produces
`?action=add`. Adding a `:drop` option to `push_url_state/3` for a hole with
no live consumer is API surface bought on speculation. Recorded here so the
first consumer that *does* hit it finds the diagnosis instead of the
symptom, and so the pre-existing dead `show_add_user_modal` assign is
cleaned up rather than wired to a modal as-is.

### 5. NITPICK — the JS hook leaks a `handleEvent` callback (#680)

`PhoenixKitUrlState.mounted()` registers `this.handleEvent(…)` but
`destroyed()` only removes the `popstate` listener. `handleEvent` registers
on the LiveSocket, not on the element, so each remount of the hook element
leaves another live callback behind and one server push runs the history
write N times. Harmless today — the `if (next === current) return` guard
makes calls 2..N no-ops — but it is the documented reason
`removeHandleEvent` exists.

**Fixed** — the ref is kept and removed in `destroyed()`, mirroring what the
hook already does for `popstate`.

### 6. NITPICK — stale PR-draft directory (#682)

The draft README landed at
`dev_docs/pull_requests/2026/680-v161-payment-option-linkage/`, still
carrying the pre-renumber identity: it is PR **#682**, not #680, and the
migration is **V162**, not V161. Worse, `680-` collides with
`680-url-state-search-persistence/` — two directories for the same PR
number describing unrelated work. The body also still claimed
`add_if_not_exists` / `create_if_not_exists` and a '161' marker, none of
which match the shipped `DO $$`-guarded migration.

**Fixed** — renamed to `682-v162-payment-option-linkage/`, contents
corrected, renumbering noted, and the V45/V56 index dependency from finding
#3 written down.

### 7. IMPROVEMENT - LOW — undeclared dotted keys still hit the raise (#682)

`Registry.auto_register_custom_permission/1` now skips `register_custom_key/2`
when `Permissions.parent_key(perm)` resolves. But `parent_key/1` returns the
base only for a key actually present in `ModuleRegistry.sub_permission_map/0`.
A tab gated on `"shop.manage_settings"` that the module forgot to declare in
`permission_metadata/0` still falls through to `register_custom_key/2`,
still raises on the dot, is still rescued, and still skips the
view → permission caching below — the exact failure the PR fixes, minus the
declaration.

That is arguably correct (it *is* a misconfiguration), but the logged
warning says "Failed to register custom permission" rather than naming the
real cause. **Recorded**, not fixed: the diagnosis belongs in the log
message, and rewording it is better done alongside the other registry
warnings than alone.

Checked and clean: `sub_permission_map/0` recomputes from
`all_permission_metadata/0` on every call rather than reading a populated
cache, so there is no boot-ordering window where a correctly-declared
sub-key looks undeclared.

---

## Verified, no finding

Things that looked like they might be wrong and are not — recorded so the
next reviewer does not re-derive them.

**#680 — the embeddability constraint is real.** Checked against
`deps/phoenix_live_view`: `Static.mount_handle_params/4` and
`Channel.maybe_call_mount_handle_params/4` both branch on
`Lifecycle.stage_info(socket, view, :handle_params, 3).any?`, which is
`callbacks? or exported?`, and take the `Route.live_link_info!` raise path
when `socket.root_pid != self()`. Attaching the `:handle_params` hook is
enough on its own — the injected stub is not what causes it. `mode:
:history` avoiding that stage entirely is the correct workaround, and
`ensure_router!/1` failing early with a nameable message is the right call.

**#680 — redirect-in-mount is safe.** `jobs/index.ex` redirects from
`mount/3` when the module is disabled, without assigning `:per_page`.
`handle_url_state/2` → `load_jobs/1` would crash on those missing assigns,
but both `mount_handle_params` implementations short-circuit on
`mount_redirect` before any hook runs, so the callback never fires.

**#680 — no whitelist drift.** The two `cast: :atom` specs mirror their
sources exactly: `live_sessions`' `sort_by: [:type, :connected_at]` matches
both `parse_sort_by/1` clauses and both `<.sort_header_cell field=…>` in the
template; `media_selector`'s `file_type_filter: [:all, :image, :video]`
matches `parse_filter/1`, the `<.select>` options, and every branch of
`load_files/2`'s `case`. A value outside the list would be silently reset to
the default by `sanitize/2`, so this is the drift that would matter.

**#680 — `mount/3` reading URL state works.** `users.ex` does
`assign(:show_search, socket.assigns.search_query != "")`, which relies on
the `on_mount` hook having run first. It has: `on_mount` callbacks all run
before the view's `mount/3`.

**#681 — V161's failure mode is safe.** With `@disable_ddl_transaction
true`, the guarded `DO $$` block is its own transaction. If the index
rebuild hits a duplicate the pre-check raced past, the `ALTER` rolls back
whole and the migration aborts before `COMMENT ON TABLE … IS '161'`, so the
version marker stays at 160 and a re-run gets the readable pre-check error.
The moduledoc's account of this is accurate.

**#682 — V162 is prefix-safe.** Every existence check is anchored
(`table_schema` on `information_schema.*`, `constraint_schema` on the
`table_constraints`/`key_column_usage` join), the index name is bare on
`CREATE` and qualified on `DROP`, and both `ALTER TABLE` targets and the FK
`REFERENCES` are schema-qualified. Matches the chain's rules.

**#682 — the slug transliteration table is complete.** All 33 Russian
letters plus Ukrainian `ґ є і ї` are present, `String.downcase/1` runs
before `maybe_transliterate/2` so uppercase input is covered through
`slugify/2`, and the NFD-decompose-then-strip-combining-marks pass handles
Latin diacritics. `transliterate/1` called directly on uppercase Cyrillic
returns it unchanged, which its `@doc` states.

---

## Not covered by this review

- Neither migration was executed. No PostgreSQL was reachable in this
  environment, so `mix test` was not run (per project convention, `mix
  precommit` is the gate here); the new `v162_test.exs` is written but
  unexecuted, and V161/V162 correctness rests on reading plus the authors'
  reported live runs.
- The `phoenix_kit_billing` (#15) and `phoenix_kit_ecommerce` (#13) halves
  of the #682 wave were not reviewed — only core's side of the contract.
- `UrlState`'s `on_mount` → hook → host `handle_params/3` ordering remains
  untested, as #680 itself records: `live_isolated/3` mounts without a
  router, which the module refuses by design.
