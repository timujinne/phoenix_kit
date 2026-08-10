# PR #692 Review — Cross-module mentions, one canonical display name, and stop publishing email addresses

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/692
**Author:** Max Don (mdon)
**Merged:** 2026-08-09 (`4deb87ec`, branch `mdon/main` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-09
**Scope:** 42 files, +4507 / −106, 24 commits. 7 new test files, 2 new migrations (V165, V166), 1 new subsystem (`PhoenixKit.Mentions`), +678 lines of JS.

---

## Verdict

Three largely independent pieces landed together: the mentions subsystem, the
`display_name/1` consolidation, and a set of unrelated fixes (accordion rebuild,
change cue, upload sanitizer, orphan detection, `before_user_delete`).

**The security thinking in mentions is genuinely good** — visibility fails
closed for any type that declares no check, the title is re-resolved per viewer
rather than trusted from the text, the notify path refuses to carry a preview it
cannot prove the recipient may read, and the token is built server-side
specifically so a hostile record name cannot be concatenated into a second
token. I checked the load-bearing claims against their sources rather than
taking them on trust:

| Claim | Verified against |
|---|---|
| `update_all` with a query `select` still returns rows under `returning: false` | `ecto/lib/ecto/query/planner.ex` — `ensure_select/2`'s first clause keeps any non-nil select |
| The typeahead menu can't be XSS'd by a record title | `phoenix_kit.js` — every server value goes through `textContent`, never `innerHTML` |
| `display_name/1`'s documented chain starts with the organization name | `User.full_name/1` has the `account_type: "organization"` head |
| `enabled?()` isn't queried for every plain textarea | Elixir `and` short-circuits; `assigns.mentions` is checked first |
| Macro-injected `handle_event` clauses don't warn about grouping | compiled a minimal reproduction — the warning fires for inline clauses and **not** for macro-injected ones |
| The `#`-search "one call per module" dedup is real | `searchable_handlers/0` grouped by module, `Map.put_new(:type, …)` lets a multi-type handler stamp its own |
| Notifications can hold one activity per recipient | `phoenix_kit_notifications_activity_recipient_index` is on `(activity_uuid, recipient_uuid)` |

Five defects found. One is a migration that records the wrong schema version —
in a chain whose own guide exists because of a version-marker incident. One is a
markdown link injection reachable by renaming a record. Two are documentation
that sends a host at something that does not exist or that does nothing yet. One
is a per-keystroke N+1 in the hottest path in the feature. Four are fixed here;
the fifth is reported with a fix sketch and deliberately not applied — see below.

**Verification caveat:** no PostgreSQL is reachable here, so none of the
integration tests — the PR's or my added one — executed. `mix precommit` passes.

---

## BUG - HIGH — V165 stamps the schema version as `163`

**File:** `lib/phoenix_kit/migrations/postgres/v165.ex`

```elixir
execute("COMMENT ON TABLE #{p}phoenix_kit IS '163'")   # in V165's up/1
```

Every other migration in the chain stamps its own number on the way up and
`n - 1` on the way down; I checked V151 through V166 and V165's `up` is the only
one that disagrees. Its `down` is correct (`'164'`), which is what makes the
`up` a slip rather than a scheme.

`migrated_version/1` reads exactly this comment, and `up/1` accepts a `:version`
target, so the damage is not hypothetical:

- **Running to 165 explicitly** leaves the database reporting **163** — *behind*
  where it was before the migration ran. The next `ensure_current/2` re-runs
  V164 and V165.
- **`mix phoenix_kit.status` misreports** an install parked at 165.
- A full run to head happens to end correct, because V166 stamps `'166'`
  immediately after — which is precisely why this would have sat undetected: the
  common path hides it, and the uncommon path silently re-runs a large repair
  migration.

The renumbering story is visible in the tree: V166's moduledoc says its
FK-free columns work "exactly like the mention targets in V163", and V165's
`up/1` still computed a `schema` binding it only used as `_ = schema`. Both are
leftovers from a draft numbered V163/V164.

**Fixed:** the stamp is `'165'`; the V166 moduledoc reference is corrected; the
dead `schema` binding and the now-unused `schema_name/1` are removed from V165.

---

## BUG - MEDIUM — a record's NAME can inject a markdown link

**File:** `lib/phoenix_kit/mentions.ex` (`escape_md/1`, `token_markdown/2`)

`to_markdown/2` splices into link syntax:

```elixir
"[#{prefix(token)}#{escape_md(title)}](#{Routes.path(path)})"
```

and `escape_md/1` escapes `\`, `[` and backtick, with this reasoning:

> `]` and `|` can't occur — the grammar refuses them

That is true, and I confirmed it — `@label` is `[^\]|]{1,120}` and
`Token.to_string/4` refuses both characters. But it is true of **`token.label`**,
and the value on this line is not the label. It is `info[:title]`: the record's
**current** name, re-resolved per viewer from whatever module owns it. Nothing
constrains that. `first_name` on a core user, for instance, is validated for
length and nothing else.

Name a record `Evil](https://evil.example)` and every markdown-rendered mention
of it becomes:

```
[@Evil](https://evil.example)](/admin/users/view/…)
```

— a working link to the attacker's URL, for every reader, produced by a rename
rather than by anything the mention author wrote. Not XSS (the output is
sanitised downstream, so `javascript:` won't survive), but link spoofing inside
trusted chrome is the useful half of a phishing primitive anyway.

The PR's own test suite reasons about this attack carefully — "a crafted record
title cannot forge a second mention" — but only for the token-building path,
which is the half the grammar already protects. The rendering path, where the
unconstrained value actually lands, has no escaping test at all.

**Fixed:** `escape_md/1` escapes `]`; the comment now says which of the two
values the grammar covers and which it does not. The URL side is wrapped in the
CommonMark angle form so a `)` or a space in a handler-supplied path cannot close
it early either. Pinned by a new test that renames a real user to a hostile
string and asserts the `]` arrives escaped and the destination is unchanged.

Both halves verified against the renderer this project actually uses
(`{:mdex, "~> 0.13"}`), not against the spec:

```
[Q3 Launch](</admin/users/view/abc>)        → <a href="/admin/users/view/abc">Q3 Launch</a>
[Evil\](https://evil.example)](</admin/x>)  → <a href="/admin/x">Evil](https://evil.example)</a>
```

The angle form resolves normally (so the fix does not break existing mention
links), and the escaped `]` renders as text inside the correct anchor instead of
terminating it.

---

## IMPROVEMENT - HIGH — the `@` typeahead is ~130 queries per keystroke

**File:** `lib/phoenix_kit/mentions/users.ex`

```elixir
|> limit(^(limit * @overfetch))      # 8 * 8 = 64 rows
|> repo().all()
|> Enum.filter(&pingable?/1)         # Scope.for_user/1 per row
```

The over-fetch is well-reasoned — filtering after `limit` really does return an
empty list whenever the first N happen to be non-admins, and the comment says so.
What it does not account for is what the filter costs. `Scope.for_user/1` calls
`User.get_roles/1` → `Roles.get_user_roles/1`, which queries unconditionally
(it does not consult a preloaded `:roles`), then `Permissions.get_permissions_for_user/1`,
which queries again. **Two queries per candidate, 64 candidates: ~128 round trips
per keystroke**, plus `permissions_table_ready?/0` for admins with no grants.

And unlike the `#` fan-out, this path has no deadline. `search/3` routes `:user`
straight to `search_users/3`, outside the `Task.async_stream` that gives every
resource handler `@search_deadline_ms` (250ms) and `on_timeout: :kill_task`. The
one branch that cannot be slow is the one that is budgeted; the branch that
issues 128 queries is not.

The rule being evaluated is expressible in one query — `can_access_admin_area?/1`
is true iff the user holds Owner or Admin **or** has at least one
`phoenix_kit_role_permissions` row — so the shape of the fix is two `exists`
subqueries in `maybe_match/2`'s `where`, with the `limit` back down to `limit`
and a rescue for the pre-V53 case where the permissions table is absent (which
`get_permissions_for_user/1` currently swallows and raw SQL would not).

**Reported, not fixed.** Rewriting an authorization filter into hand-written SQL
is exactly the change that should not be made without executing the suite, and
no PostgreSQL is reachable in this environment. Getting it subtly wrong changes
who is pingable — in either direction — and neither direction announces itself.
Recorded here with the fix sketched so it is a decision rather than an oversight.

---

## BUG - MEDIUM — the component tells hosts to `use` a module that does not exist

**File:** `lib/phoenix_kit_web/components/core/mention_text.ex`

> ## Wiring the request-access click
> …or get the handler and the dialog for free:
>
>     use PhoenixKit.Mentions.RequestAccess

There is no `PhoenixKit.Mentions.RequestAccess` anywhere in the tree — the only
reference to that name is this doc. The module is `PhoenixKit.Mentions.Live`,
and it is the one place a host learns that the redacted chip's click needs
wiring at all. A host following the instruction gets a compile error; a host
that gives up leaves the feature's whole "there is a next step" premise inert.

The `use` is also only half of it: `Mentions.Live` stages the request in
`@pk_access_request` and the dialog is a separate component the host must render,
or the click sets an assign nothing reads.

**Fixed:** correct module name, plus the `<.access_request_dialog>` line the
`use` depends on.

---

## IMPROVEMENT - MEDIUM — the upload sanitizer has no callers

**File:** `lib/modules/storage/services/image_processor.ex`

`sanitize/3` is good work: it re-encodes rather than inspects, pins the decoder
to a detected-and-allowlisted format, takes frame `[0]` only, applies `-limit`
ceilings locally instead of trusting the host's `policy.xml`, and refuses a
declared pixel count above 40MP before the decoder ever starts. The reasoning in
the comments is right about why each of those is there.

Nothing calls it. `rg ImageProcessor` across `lib/` returns `extract_dimensions`,
`resize`, `resize_and_crop_center`, `get_width`, `get_height` — and `sanitize/3`
only from its own test file. Every upload path in core still stores the
uploader's bytes.

That may well be intentional — the portal-submission path the PR's orphan fix is
about lives in an external package, and re-encoding wholesale would be wrong for
a designer's master PNG. But the commit is titled "Add an upload sanitizer:
re-encode, never re-serve" and the docstring opens "For uploads from people you
do not trust", which together read as protection now in place. It isn't, and
CLAUDE.md's storage TODO already tracks a live unauthenticated upload endpoint
that would be the natural first caller.

**Fixed the documentation half:** the docstring now states outright that no core
path routes through it, that the caller must store the *output* and discard the
original, and why wiring it into `Storage.upload/*` wholesale is not a drop-in.
Actually wiring it is a product decision, not a review fix.

---

## IMPROVEMENT - MEDIUM — `context/2`'s batching claim doesn't survive its own component

**Files:** `lib/phoenix_kit/mentions.ex`, `lib/phoenix_kit_web/components/core/mention_text.ex`

`context/2` documents itself as:

> Batched per type: a page with thirty mentions across three types costs three
> resolve calls and three visibility calls.

True of `context/2`. Not true of the way it is reached. `<.mention_text>` calls
`Mentions.context/2` inside `assign_new(:pieces, …)`, per component — and since
callers never pass `:pieces`, `assign_new` computes every time. A comment list is
one `context/2` per comment (resolve + visibility each), re-run on every
LiveView diff that touches the list, not three calls for the page.

For a 30-comment thread that is 60 calls where the docs promise 6, and it repeats
on each re-render rather than once per navigation. Nothing is wrong per render;
the cost is that the batching the design is proud of is unavailable to the only
consumer, because there is no way to hand the component a context computed once
for the page.

**Not fixed** — the fix is an API addition (an optional `context` attr the parent
computes for the whole list, falling back to today's behaviour), which is a design
call on a brand-new public component rather than a defect to patch.

---

## RELEASE BLOCKER (not a defect in this PR) — the schema manifest needs regenerating

**File:** `lib/phoenix_kit/migrations/expected_schema.ex` (not touched by the PR — correctly so)

> **Correction.** I first filed this as `BUG - HIGH` against #692. That was
> wrong, and `dev_docs/squash/README.md` says so in as many words:
>
> > A migration PR may land with a stale manifest; the `chain_hash` assertion in
> > `release_check` **and** its plain-unit-test twin are the release-time gate —
> > regeneration must happen before publish.
>
> Landing stale is the documented workflow. This is a release-time task for
> whoever publishes, not something the PR author skipped. The rest of the
> section below stands as a description of the blocker.

Found while cutting 1.7.237. `mix phoenix_kit.release_check`:

```
FAIL Migration Version Sync
     PhoenixKit.Migrations.ExpectedSchema.chain_hash/0 is stale — it no longer
     matches a fresh hash over lib/phoenix_kit/migrations/postgres/v*.ex.
```

`chain_hash` is computed over the whole `v*.ex` set, so adding V165 and V166
moved it by construction. The manifest's last touch is `b3ef57b2` (#689). **No
release can be published until this is resolved.**

The important part is that the usual quick fix is not available. There is a
DB-free `dev_docs/squash/restamp_chain_hash.exs`, and the moduledoc shows it
being used twice before — but both times on the explicit finding that the new
versions added **no manifest object**:

> Neither new version adds a manifest OBJECT: upstream's V163 converges databases
> onto shapes this manifest already declares … Established empirically rather
> than by regenerating: s3, s7 and s8 … all pass against this manifest post-merge.

That is not true here. V165 creates `phoenix_kit_mentions` and
`phoenix_kit_access_requests` outright; V166 adds four columns, a CHECK
constraint and a partial index to `phoenix_kit_comments`. `ExpectedSchema`
mentions **none** of them — `rg` returns zero hits for every one of those names.
The restamp script rules itself out for exactly this case:

> It is the right tool ONLY when the change cannot move the schema… When the
> change adds, drops or reshapes anything, regenerate the manifest from a
> pre-squash checkout instead and do not use this script.

Restamping anyway would turn the gate green while leaving the repair engine's
oracle blind to two tables and four columns: `verify` would not report them
missing and `repair` would not create them, on exactly the newest objects most
likely to be absent from a partially-migrated database. The hash exists to catch
this, and restamping would suppress it.

**Not fixed, and deliberately not worked around.** No PostgreSQL is reachable in
this environment (nothing on 5432, no `psql`, no container runtime), so neither
regeneration nor the behavioural backstop can run here.

### The runbook has a gap for post-floor deltas, and V165/V166 fall in it

Worth stating because "just regenerate" does not actually close this. The
README requires regenerating **from a pre-squash checkout**, and the moduledoc
records why: a run on the squashed branch is self-referential and loses
pre-floor bimodal knowledge (observed 2026-08-07 — it dropped the
`phoenix_kit_role_permissions` seed and failed s2/s5/s8/s10).

But a pre-squash checkout's chain **ends at V163**. It cannot see V164, V165 or
V166 at all. That is why V164's effects are carried in the manifest as
hand-written `DECLARED POST-GENERATION CORRECTION` entries despite the
never-hand-merge rule — there is no generator run that can produce them.

So the honest options are:

1. **Regenerate + hand-declare.** Pre-squash regeneration for the V1..V163 body,
   then add V165's two tables and V166's four columns / constraint / index as
   marked post-generation corrections, following the V164 precedent. Validate
   with `verify.exs --scenario s7,s8` against a scratch DB. This is the complete
   fix and it is a real piece of work in a 67k-line generated file.
2. **Restamp only, and file the object gap.** One command. Makes the gate green
   and leaves `verify`/`repair` blind to the V165/V166 objects — repair will not
   recreate them if a database is missing them. Note this is not a new class of
   risk: the README already records the manifest as **known stale since
   2026-08-08** with "no knowledge of `V163`'s objects at all" and regeneration
   "outstanding before the next full verify run can be trusted". Option 2 grows
   an acknowledged debt by two tables rather than introducing one.

Option 2 is defensible for shipping today precisely because the oracle is
already documented as untrustworthy; it is still an explicit decision to take,
not a step to perform quietly, which is why `restamp_chain_hash.exs` makes
writing opt-in.

---

## NITPICK — access requests are unvalidated and unthrottled

**Files:** `lib/phoenix_kit/mentions/live.ex`, `lib/phoenix_kit/mentions/access_requests.ex`

`pk_request_access` takes `type` and `uuid` from `phx-value-*` and stores them
verbatim; `submit/2` passes them straight to `AccessRequests.request/4`. Nothing
checks that the type is a registered resource type, that the record exists, or
that the requester genuinely lacks access. `resource_type` is unvalidated free
text with no length bound.

The partial unique index stops repeat asks for the *same* resource, so the ceiling
is one row per distinct uuid a client cares to invent — each with an
`Activity.log/1` behind it. Low harm, but it is an authenticated write with no
rate limit on a path whose whole job is to be clicked by people who are being
refused something.

---

## NITPICK — `Mentions.Users.resolve/1` is unreachable

`"user"` resolves through `PhoenixKit.Users.CommentResources` (`resource_links.ex:164`),
which is what `resolve_titles/2` calls. `Mentions.Users.resolve/1` implements the
same shape, returns `path: nil` where the real handler returns
`/admin/users/view/:uuid`, and has no callers. Two answers to one question, one
of them wired — worth deleting before someone reads the wrong one.

---

## Verified and left alone

- **Unqualified table names in the new orphan-detection fragment** — `NOT EXISTS (SELECT 1 FROM phoenix_kit_project_portal_submissions …)` is not schema-qualified, but neither is any of the eight `optional_checks` entries it joins. Pre-existing pattern and a real prefix hazard for the whole list; not this PR's defect.
- **`claim_for_delivery/1`'s `{count, nil}` branch** — defensive dead code, not a bug. Ecto's `ensure_select/2` preserves a query-level `select` regardless of `returning: false`, so the claim genuinely returns the won uuids.
- **`fan_out_from_activity/2`** — `%{entry | target_uuid: …}` per recipient is safe against the notifications unique index, which is on `(activity_uuid, recipient_uuid)`.
- **`before_user_delete` hooks running outside the delete transaction** — the tradeoff is stated in the comment and is the right one; `catch kind, reason` (not just `:exit`) correctly covers a throwing hook.
- **`compile_module_user_routes/1` not deduping across modules** — matches `compile_module_admin_routes/0` exactly; the per-module `uniq_by` is the documented "first wins".
- **`phx-hook` without an id** — the multilang textareas carry `id={@input_id}`, and `<.textarea>` derives one from the bound field. Only a raw `name=`/`value=` caller passing `mentions` and no `id` would trip it.
- **`-auto-orient` before `-strip`** — the comment says "strip before anything else" but the order in the args is correct: orientation must be read from EXIF before EXIF is discarded.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit/migrations/postgres/v165.ex` | version stamp `'163'` → `'165'`; dead `schema` binding and `schema_name/1` removed |
| `lib/phoenix_kit/migrations/postgres/v166.ex` | moduledoc "V163" → "V165" |
| `lib/phoenix_kit/mentions.ex` | `escape_md/1` escapes `]`; new `escape_md_url/1`; comment corrected to distinguish label from resolved title |
| `lib/phoenix_kit_web/components/core/mention_text.ex` | `use PhoenixKit.Mentions.Live` (was a nonexistent module) + the dialog it needs |
| `lib/modules/storage/services/image_processor.ex` | `sanitize/3` docs state that nothing calls it and what a caller must do |
| `test/phoenix_kit/mentions_test.exs` | +1 test: a hostile record name cannot inject a markdown link |

## Gate

`mix precommit` — format, `compile --warnings-as-errors`,
`deps.unlock --check-unused`, `credo --strict`, dialyzer, JS tests: **passing**.
Integration tests not executed (no PostgreSQL in this environment).
