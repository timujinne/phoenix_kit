# PR #956 — Opt-in address policy for personal SMTP integrations

**Author:** timujinne · **Merged:** 2026-10-21 (5e75fd8ae) · **Reviewer:** Claude

## Summary

`SmtpEndpointPolicy` (`config :phoenix_kit, :personal_smtp_policy, :restricted`, any value other than `nil`/`false`/`:open` is on)
refuses a personal SMTP connection whose port is not 25/465/587/2525 or whose host is internal, unresolvable, or resolves to any
non-public address (`PublicAddress.public?/1`, every address must pass). It runs inside Test Connection (`Validators.smtp/2`, bounded
by `Probe`) and in `Mailer.swoosh_config_for/1` before every send, and pins the relay to the checked address (SNI kept on the typed
name) so a rebinding name has no second lookup.

Verdict: well built. Failure modes fail closed (typo values turn it on; no owner means the strict policy; a raising resolver reads as
"no addresses"; both families are asked at once, each bounded by the connection timeout, which `SmtpTransport` already holds in ms).
Host refusals share one reason so the server's internal DNS cannot be enumerated.

## Findings

- **NITPICK (not changed):** `validate_credentials/3` defaults `owner:` to `:system`, so a caller that forgets to pass the owner for
  a personal Test Connection gets no check. This is the existing convention (AGENTS.md: "a connection validator needs the owner")
  and the saved-row path is safe because the row carries `owner_uuid`.
- **NITPICK (not changed):** nothing here was run against a live relay; the pinned-IP + SNI + `verify_peer` combination is
  covered by option-level tests only. Worth one manual STARTTLS and one implicit-TLS send against a real relay before the first
  host turns the policy on.
- Tests: `smtp_endpoint_policy_test.exs`, `validators_test.exs`, `mailer_test.exs`, `personal_smtp_policy_test.exs` — green.
