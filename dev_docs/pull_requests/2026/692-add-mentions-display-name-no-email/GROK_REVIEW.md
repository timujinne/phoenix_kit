# PR #692 Recheck — Mentions, display name, email privacy

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/692
**Author:** Max Don (mdon)
**Merged:** 2026-08-09 (`4deb87ec`)
**Reviewer:** Grok (recheck of Claude's work)
**Date:** 2026-08-09

---

## Verdict

Claude's security review of mentions is sound, and the four applied fixes
(V165 stamp, markdown `]` escape, wrong `use` module, sanitize docs) are still
correct on HEAD. Three items Claude left open were worth closing here.

---

## IMPROVEMENT - HIGH — `@` typeahead ~128 queries/keystroke (Claude left open)

**Was:** over-fetch `limit * 8` rows, then `Scope.for_user/1` per row (roles query
+ permissions query). No deadline on the user path (unlike `#` handlers).

**Fixed:** `Mentions.Users.search/2` evaluates the admin-area rule in SQL —
`EXISTS` Owner/Admin role assignment **or** any `phoenix_kit_role_permissions`
grant — and applies `limit` in the database. One query per keystroke. Matches
`Scope.can_access_admin_area?/1` (Owner/Admin alone is enough; permission-only
custom roles still match).

Dead `Mentions.Users.resolve/1` (path: nil, no callers — real path is
`CommentResources` via ResourceLinks) removed so nobody wires the wrong one.

---

## IMPROVEMENT - MEDIUM — access requests unvalidated / unthrottled (Claude nitpick)

**Was:** `type`/`uuid` from `phx-value-*` stored and Activity-logged verbatim;
partial unique index only bounds the *same* resource.

**Fixed:**

- `resource_type` must be in `ResourceLinks.handlers/0` and ≤ 100 bytes
- `resource_uuid` must cast as UUID
- per-account rate limit via `RateLimiter.check_access_request_rate_limit/1`
  (10 / 10 minutes)

Pinned by unit tests that need no database
(`test/phoenix_kit/mentions/access_requests_validation_test.exs`).

---

## RELEASE BLOCKER — ExpectedSchema blind to V165/V166 (Claude)

**Was:** `chain_hash` stale; manifest body had zero knowledge of
`phoenix_kit_mentions`, `phoenix_kit_access_requests`, or V166 comment columns.
Restamp alone would have greened the gate while leaving repair blind.

**Fixed:** hand-declared post-generation objects for V165 (two tables + columns
+ indexes + checks + FKs) and V166 (four columns + check + partial index),
following the V164 precedent documented in the manifest header. Then restamped
`chain_hash` over the 32 shipped files.

`mix phoenix_kit.release_check` Migration Version Sync is now **PASS**.

**Still open:** `verify.exs --scenario s7,s8` against a real database — this
environment has no PostgreSQL. That run is what *proves* the hand-declared body
matches a live chain install.

---

## Left alone (agree with Claude)

- **`context/2` batching vs per-component `<.mention_text>`** — API design call;
  not patched.
- **`ImageProcessor.sanitize/3` has no core callers** — product decision;
  docs already honest after Claude's pass.
- **Orphan-detection unqualified table names** — pre-existing prefix hazard for
  the whole list.

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit/mentions/users.ex` | SQL-side admin-area filter; remove dead `resolve/1` |
| `lib/phoenix_kit/mentions/access_requests.ex` | type/uuid validation + rate limit |
| `lib/phoenix_kit/users/rate_limiter.ex` | `check_access_request_rate_limit/1` |
| `lib/phoenix_kit/migrations/expected_schema.ex` | V165/V166 objects + restamped `chain_hash` |
| `test/phoenix_kit/mentions/access_requests_validation_test.exs` | new unit tests |
| `CHANGELOG.md` | Fixed bullets for this recheck |

## Gate

- `mix compile --warnings-as-errors` — pass
- Unit subset (mentions, slug, install, release_check) — **130 tests, 0 failures**
- `mix phoenix_kit.release_check` Migration Version Sync — **PASS** (tree dirty only
  until these changes commit)
- Integration / `verify.exs` — not run (no PostgreSQL)
