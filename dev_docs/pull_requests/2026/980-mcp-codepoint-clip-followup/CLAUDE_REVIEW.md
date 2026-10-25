# PR #980 — Clip approval reasons by code points; pin the 422 cause of a keyed no-replay call (follow-up to #963)

**Author:** timujinne · **Merged:** 2026-10-23 (01c93d57d) · **Reviewer:** Claude

## Summary

Closes the NITPICK left open in the #963 review: `Approvals.View.cap/1` cut client-supplied reasons with `String.length`/`String.slice`, which count
graphemes, so one letter plus 200 000 combining marks was a single grapheme and was shown whole. It now goes through `LogSafe.take_codepoints/2`. The
second change asserts the cause of the 422 for a keyed call to the `replay: false` tool (`path: "idempotency_key"`), not just the status.

Verdict: correct.

## Verified

- `take_codepoints/2` walks at most `limit` code points, so a 200 000 code point input costs O(160), not O(n).
- Boundary: a text of exactly 160 code points comes back equal to itself and is kept whole; 161 is cut to 159 code points + `…` = 160. Both tests assert
  the length by `String.to_charlist/1`, which is the property the fix is about.
- No other `String.slice`/`String.length` of request-derived text remains under `lib/phoenix_kit/api`. The two other `String.slice` hits are an id
  suffix and `keys.ex` `last_used_ip`, whose value has already been through `:inet.parse_address/1` (`IpAddress.parse/1`), so it is an address, not client
  text.

## Findings

- **NITPICK (not changed):** cutting by code point can leave a combining mark detached from its base at the cut. For a 160-code-point display line
  that is cosmetic, and it is the price of the bound; a grapheme-safe cut would need the unbounded walk this PR removes.
