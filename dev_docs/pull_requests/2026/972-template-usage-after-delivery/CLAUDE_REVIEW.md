# PR #972 — Count email template usage only after the message is delivered

**Author:** timujinne · **Merged:** 2026-10-23 (3d3eb3649) · **Reviewer:** Claude

## Summary

`track_usage/1` ran before `deliver_email/2`, so a refused, blocked or dev-suppressed send still counted as a use. `Mailer.track_usage_after_delivery/2`
now counts after `{:ok, _}` (not for `suppressed: true`; `queued: true` counts), never changes the result, and swallows a failing provider (rescue +
exit). The four call sites (`send_from_template`, magic link, notification email channel, `UserNotifier.deliver_built/1`) use it; `UserNotifier` carries the
template in `email.private[:phoenix_kit_db_template]` from `build_templated/5` to `deliver_built/1`, so the welcome worker (build, then send later) is
covered too.

Verdict: correct. Checked every `db_template` / `track_usage` reference in `lib/`: no caller is left that counts before sending, and no path builds a
templated message without going through `deliver_built/1` (`deliver_welcome/1`, `WelcomeEmailWorker`, all `deliver_templated/5` users). `mailer_test` (252 new
lines) green.

## Findings

- **NITPICK (not changed):** the template struct now rides in `email.private`. Core never serializes `private`, but a sibling module that logs or stores the
  whole `%Swoosh.Email{}` would carry the struct along. Worth knowing if an emails sibling ever persists the struct.
- **Process note:** behaviour change (counts drop for failed/suppressed sends) with no CHANGELOG entry; belongs in the release entry.
