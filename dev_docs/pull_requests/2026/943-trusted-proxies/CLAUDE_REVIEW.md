# PR #943 — Add :trusted_proxies to restrict which peers may set the client IP

**Author:** timujinne · **Merged:** 2026-10-19 (7aa395832) · **Reviewer:** Claude

## Summary

`config :phoenix_kit, :trusted_proxies` (CIDR text list) decides which peers' `X-Forwarded-For` / `X-Real-IP` are believed in
`IpAddress.client_address/1` and `client_address_from_socket/1`. Unset keeps the loopback/private rule and logs one warning per VM
the first time it relies on it; `[]` trusts nobody; a non-list trusts nobody and warns; bad entries in a list match nothing.

Verdict: sound and fail-closed. `CIDR.allowed?([], _)` is `false` (not "allow all" like an empty API-key allow-list), an
IPv4-mapped peer is unmapped before matching, the rule is evaluated per request (so `runtime.exs` values work), and the
`X-Forwarded-Proto` / `SessionFingerprint.proxy_rebind_address/3` checks deliberately stay on the default rule (documented; a
rebind needs a stored private address, which a public trusted proxy never produces).

## Findings

- **BUG - MEDIUM (fixed):** the "`:trusted_proxies` is invalid" warning used `inspect(invalid, limit: 5)`. `limit` counts nested terms,
  so a first entry that is a tuple (or any multi-element term) used up the budget and the warning read
  `[{172, 18, 0, 7}, ...]` — the one message that exists to tell the operator WHICH entries are bad dropped the second one. The
  PR's own test `an unreadable entry matches nothing, the rest still works, and it warns` failed on Elixir 1.19 for exactly that
  reason. The warning now takes the first five whole entries (`inspect_invalid/1`, `limit: :infinity`, `printable_limit: 80`).
- **NITPICK (not changed):** with a valid list, `warn_invalid/1` re-runs `CIDR.normalize_all/1` on every request (the "warned" flag
  is only set for an invalid value) and `CIDR.allowed?/2` parses the entries again. A few CIDRs cost microseconds, and caching the
  "checked" term would fight the tests that erase the warning flags; left as is.
