# PR #697 Review — Make local dev-mailbox delivery opt-in and stop advertising /dev/mailbox

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/697
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-10 (`0c5f776d`, branch `fix/dev-mailbox-safe-default` → `main`)
**Reviewer:** Claude (Opus 5)
**Date:** 2026-08-10
**Scope:** 16 files, +811 / −70, 9 commits.

---

## Verdict

**Good PR.** It closes items 1 and 4 of issue #687 properly, and replaces the
issue's item 3 (an install-time question) with a runtime opt-in — which is
strictly better, because it also covers the delegation-mode hosts an installer
can never reach. Two findings, both fixed here; neither is in the mailbox work.

### ⚠️ The PR body describes four changes. The merge carries six.

Two commits are not mentioned anywhere in the description:

| Commit | Content |
|---|---|
| `58826b0e` | **`POST /api/upload` and `GET /api/files/:uuid/info` required no authentication** |
| `48b0a456` | Rate-limits the uploader; narrows both storage gates to Owner/Admin |

That is the storage item that has been sitting at the top of CLAUDE.md's TODO
list since 2026-08-07 — arguably a larger security fix than the mailbox work the
PR is named for. Anyone reviewing from the description, or writing release notes
from it, would miss it entirely. Flagged because it is a process problem, not a
code one: the code is good.

---

## What I verified

| Claim | Verified against |
|---|---|
| The new `{:ok, %{suppressed: true}}` return breaks no caller | all three `deliver_email/2` consumers — `email_sending.ex:163` (`{:ok, _result}`), `channels/email.ex:60` (`{:ok, _}`), `user_notifier.ex:47` (`with {:ok, _metadata} <-`, returns its own `email`) |
| Production is unaffected by the new gate | `and` short-circuits, so a non-Local adapter never evaluates `dev_mailbox_enabled?/0` |
| `Scope.system_role?/1` exists and means Owner/Admin only | `scope.ex:637` |
| The upload rate limit keys on the right identity | the authenticated uploader, not the attributed owner — an admin override would otherwise grant a fresh window per victim uuid. Comment says so and the code matches |
| `current_user.uuid` is safe at the rate-limit call | `resolve_upload_user/2`'s only `{:ok, _}` branch requires a `%User{}` |
| The file-info endpoint is no longer an existence oracle | `authorize_file_read/2` returns the same `{:error, :not_found}` for a missing *and* a foreign file |
| No core caller breaks | neither endpoint is called from `lib/` or the shipped JS — they are documented host API (`lib/modules/storage/README.md`) |
| The suppression log can actually recover a token | `email.text_body || email.html_body || ""` — the HTML-only fallback matters, since an overridden `UserNotifier` may send HTML only |

The design instinct on the mailbox gate is right in a way worth naming: the gate
sits **before** the tracking pipeline, so a message never handed to an adapter is
never recorded as sent. The comment even notes the consequence it accepts (the
recipient blocklist is not exercised for suppressed Local sends).

---

## IMPROVEMENT - MEDIUM — the new settings read in the delivery path is unguarded

**File:** `lib/phoenix_kit/mailer.ex`

```elixir
defp dev_mailbox_enabled? do
  PhoenixKit.Settings.get_boolean_setting("dev_mailbox_enabled", false)
end
```

Its sibling is guarded, in the same PR:

```elixir
def mailer_local? do
  match?({:mailer, _, Swoosh.Adapters.Local}, PhoenixKit.Mailer.resolved_send_path())
rescue
  _ -> false
catch
  :exit, _ -> false
end
```

AGENTS.md states the rule and why `rescue` alone is not enough: settings reads
are ETS-cached, so only a cache **miss** touches the database, and an
unreachable one *raises* on an unowned checkout but *exits* on a dead pool. This
read is new to the delivery path — before this PR nothing here could fail that
way — so an auth flow could now die inside `deliver_email/2` on a dev box with a
blipping pool, on the one code path whose whole job is to not lose the token.

Severity is capped by reachability: `and` short-circuits, so only Local-adapter
installs evaluate it at all.

**Fixed:** `rescue`/`catch :exit` → `false`, which is also the fail-**closed**
direction — it suppresses and logs the token rather than handing a message full
of single-use links to an unauthenticated mailbox because a pool blipped.

---

## NITPICK — the dialyzer-ignore comment names the check the code deliberately avoids

**File:** `.dialyzer_ignore.exs`

The new entry reads:

> the storage API controllers build a scope from the authenticated User with
> `Scope.for_user/1` and pass it straight to **`Scope.can_access_admin_area?/1`**
> to gate the upload owner-override and the file-info read.

Both call sites use `Scope.system_role?/1`, and both controllers' own docs
emphasise the distinction in capitals — `can_access_admin_area?/1` is true for
any holder of a single module permission, which is exactly the actor that must
not be able to read every other user's file metadata and signed variant URLs.

Small, but this file is where someone auditing the suppressed warnings looks, and
it is currently the one place that reads as though the weaker check is in use.

**Fixed:** names `system_role?/1` and states why the distinction is load-bearing.

---

## Behaviour changes hosts need to be told about

Neither is a defect; both belong in the release notes and only one is in the PR
body.

1. **An upgraded dev install stops filling `/dev/mailbox`** until the operator
   flips `dev_mailbox_enabled`. The PR names this cost explicitly and the failure
   mode is loud (log line per suppressed send, changed DevNotice copy, banner on
   the settings page). Good.
2. **`GET /api/files/:uuid/info` now requires authentication** and answers only
   for a file the caller owns, or to an Owner/Admin. This is documented host API
   in `lib/modules/storage/README.md`; a host calling it anonymously — a public
   gallery front-end, say — breaks. Intended, and the right call, but it is the
   kind of thing that should not be discovered from a 401.

---

## Still open from #687

Item **2** (router introspection in `install`/`doctor` to detect an
unauthenticated `Plug.Swoosh.MailboxPreview`) remains, as the agreed follow-up.
Item **3** is genuinely superseded: the safe default no longer depends on what
the installer asks.

---

## Changes in this pass

| File | Change |
|---|---|
| `lib/phoenix_kit/mailer.ex` | `dev_mailbox_enabled?/0` guarded with `rescue`/`catch :exit`, failing closed |
| `.dialyzer_ignore.exs` | comment names `system_role?/1`, the check actually used |

## Gate

Reviewed and fixed in an isolated `git worktree` at `origin/main`: the main
working tree has another agent's uncommitted changes to `rate_limiter.ex`, which
this PR also touches, so pulling would have clobbered them.

`compile --warnings-as-errors`, `format`, `credo --strict` (10331 mods/funs) and
`dialyzer` (224 errors, 224 skipped, exit 0) all clean. The PR's own unit tests —
`mailer_resolution_test.exs`, `dev_notice_test.exs` — 6 tests, 0 failures. Its
three integration test files need PostgreSQL and did not run here; the PR reports
them green against a real database (3288 tests, 2 failures, both the pre-existing
stale `chain_hash`).
