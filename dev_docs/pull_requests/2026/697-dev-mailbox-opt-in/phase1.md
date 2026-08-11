# PR #697 Phase 1 Review — Make local dev-mailbox delivery opt-in

**Reviewer:** Pincer
**Date:** 2026-08-10
**PR author:** Tymofii Shapovalov (timujinne)
**Addresses:** Issue #687 items 1 and 4
**Verdict:** Approve (no blockers)

---

## Summary

Addresses the security concern in #687: the local Swoosh mailbox (`/dev/mailbox`) is
unauthenticated by design, but Phoenix Kit was silently delivering single-use auth tokens
(password-reset links, confirmation URLs) to it by default, and linking to it directly from
the auth pages. This PR makes mailbox delivery opt-in and removes the link.

Four concrete changes:

1. **`Config.mailer_local?/0` fixed** — now calls `PhoenixKit.Mailer.resolved_send_path/0`
   instead of a raw config read. Fixes the delegation-mode false-negative (delegating host
   has a real adapter but built-in Local block exists) and the false-positive (installer-written
   Local block coexists with a real delegated mailer).

2. **Mailbox delivery is opt-in** — new setting `dev_mailbox_enabled` (default `"false"`).
   When the resolved adapter is `Swoosh.Adapters.Local` and the switch is off,
   `deliver_via_configured_mailer/2` logs the email (including the token body) and returns
   `{:ok, %{suppressed: true, ...}}` so register/reset flows stay green. The gate runs
   before the tracking pipeline — suppressed mail is not recorded as sent.

3. **Admin UI toggle** — `/admin/settings/email-sending` gains a "Local dev mailbox" section
   (only shown when the resolved transport is Local) with a warning banner and a checkbox.

4. **DevNotice updated** — no longer links to `/dev/mailbox`; instead shows "written to the
   server log" (gate closed) or "check the local mailbox" (gate open). The render condition
   (`mailer_local?/0`) now uses the corrected resolution path.

---

## Diff surface check

| Concern | Verdict |
|---|---|
| Unexpected / unrelated files | None |
| Secrets or credentials | None |
| Suspicious dependency changes in `mix.exs` | No `mix.exs` changes |
| Build artifacts / swap files / crash dumps | None |
| Files that should not be modified | None |

Files changed: `config.ex`, `mailer.ex`, `settings.ex`, `dev_notice.ex`,
`email_sending.ex`, `email_sending.html.heex`, and four test files. All expected for
this scope.

---

## What Works Well

1. **`resolved_send_path/0` is the single source of truth.** Everything that needs to know
   "is mail going to the Local adapter?" now flows through one function. The delegation chain
   (integration → host mailer → built-in) matches what `deliver_email/2` actually does.

2. **`rescue`/`catch :exit` guards on public-page helpers.** Both `mailer_local?/0` and
   `mailbox_enabled?/0` in `dev_notice.ex` degrade to `false` on dead pool rather than
   crashing the auth pages. The comment explains the invariant clearly.

3. **Gate sits before the tracking pipeline.** A suppressed message never reaches the
   adapter or the "sent" ledger — semantically clean.

4. **The `.checkbox` component's hidden-input fallback.** The toggle form uses `phx-change`
   (fires on every checkbox change). An unchecked HTML checkbox normally sends no field value,
   which would crash `handle_event("toggle_dev_mailbox", %{"enabled" => enabled}, ...)`. The
   `.checkbox` component renders `<input type="hidden" name={@name} value="false" />` before
   the real input, so unchecking sends `%{"enabled" => "false"}` and the pattern always
   matches. Not obvious from the LiveView code alone — the component saves it.

5. **Test coverage is thorough.** Four new test modules cover: gate closed by default,
   gate opened via setting, LiveView toggle UI, non-local adapter hiding the section,
   `resolved_send_path/0` delegation cases (false-negative, false-positive, built-in,
   no-adapter), and the `DevNotice` component. All `async: false` with correct env/ETS cache
   cleanup in `on_exit`.

6. **Breaking change is loud, not silent.** The `Logger.warning/1` block logs the full body
   (with token) and explicitly points at the admin toggle URL. A dev who sees no emails will
   immediately find the warning in the server log.

---

## Issues and Observations

1. **`deliver_via_configured_mailer` checks adapter directly, not via `resolved_send_path/0`**
   (`lib/phoenix_kit/mailer.ex`, gate block in `deliver_via_configured_mailer/2`)
   - Severity: Style / minor design
   - `configured_adapter(mailer)` is called directly rather than reusing
     `resolved_send_path/0`. This is actually **correct**: `deliver_via_configured_mailer`
     is only reached when no send integration exists, so the integration branch of
     `resolved_send_path/0` is already excluded. Documenting here for clarity — not a bug,
     but a reader stumbling on this after reading the "always use `resolved_send_path`" doc
     comment might question it.

2. **HTML body logged as fallback for HTML-only mailers**
   (`lib/phoenix_kit/mailer.ex:~273`, `log_suppressed_local_delivery/1`)
   - Severity: Style
   - `body = email.text_body || email.html_body || ""`
   - Logging raw HTML to the server log is functional but messy. The PR description
     acknowledges this is intentional (HTML-only override case). Consider stripping tags
     or logging a "see html_body" note instead. Not a blocker.

3. **`Memory.stop/0` called only if `started_storage` is true, but not checked if `Memory`
   is a named global** (`test/integration/email/dev_mailbox_gate_test.exs`)
   - Severity: Style / test hygiene
   - The test correctly avoids double-stopping the global storage, but `Memory.stop/0` is
     called in `on_exit` only when this test started it. If Swoosh's global storage is
     started by a different test module and this test ran its cleanup unconditionally it
     could kill a shared resource. The conditional is correct; just flagging the logic is
     load-bearing and should not be refactored away carelessly.

4. **No issues found with security, correctness, breaking-change surface, or file
   composition.** The PR is narrow, well-scoped, and addresses a genuine security concern.

---

## Verdict

**Approve.** No blockers. The PR is correct, well-tested, and solves a real security problem
(unauthenticated `/dev/mailbox` surfaced on auth pages that emit single-use tokens). The
`mailer_local?/0` fix is an important correctness improvement for delegation-mode installs.
The two style observations above are not worth blocking the merge.

Recommend merging as-is.
