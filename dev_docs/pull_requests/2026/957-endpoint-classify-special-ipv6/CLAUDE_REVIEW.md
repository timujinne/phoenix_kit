# PR #957 — Storage.Endpoint: classify IPv6 forms that carry or reach non-public addresses

**Author:** timujinne · **Merged:** 2026-10-21 (304043f82) · **Reviewer:** Claude

## Summary

`Endpoint.classify/1` now reads IPv4-compatible (`::a.b.c.d`) and 6to4 (`2002::/16`) as the IPv4 inside, local-use NAT64
(`64:ff9b:1::/48`) and site-local (`fec0::/10`) as `:unique_local`, and Teredo (`2001::/32`) and documentation (`2001:db8::/32`) as
`:reserved`.

Verdict: correct; clause order is right (`::` and `::1` before the compatible form, `64:ff9b::/96` before the `/48`, `fe80` before `fec0`).

## Findings

- **BUG - MEDIUM (fixed):** the second documentation range `3fff::/20` (RFC 9637) was still `:public` here, while
  `PublicAddress` already lists it. Added `classify({0x3FFF, second, ...}) when second <= 0x0FFF -> :reserved` and a test with the
  boundaries (`3fff:0fff::` reserved, `3fff:1000::` and `3ffe::` public).
- **NITPICK (not changed):** `Endpoint.classify/1` and `PublicAddress.public?/1` are two lists of the same thing and `PublicAddress`
  is stricter (everything outside `2000::/3` is refused, every embedded-IPv4 form is refused rather than judged by the IPv4). That
  is why the drift above happened; merging them would change what the storage form accepts, so it is not done here.
