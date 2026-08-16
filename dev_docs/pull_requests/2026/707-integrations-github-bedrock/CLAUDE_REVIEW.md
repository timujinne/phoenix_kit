# PR #707 — GitHub and Amazon Bedrock integration providers

**Reviewed:** 2026-08-13 · **Author:** @timujinne · **Verdict:** merged unchanged.

## Summary

Two built-in providers, a new `:amazon_bedrock` validation strategy, enrichment
of the `aws_ses` pass verdict with account identity and per-service permissions,
instruction blocks for the SES and Bedrock cards, and `variant="zebra"` on the
connections table.

## Dispatch wiring — checked, correct

The two providers validate by different routes and both land where they should:

- **Bedrock** declares `validation: %{strategy: :amazon_bedrock}` and the new
  `do_validate/2` clause is inserted *above* the generic
  `auth_type in [:api_key, :bot_token]` clause in `integrations.ex`. Clause order
  matters here and it is right — below it, the generic branch would have sent a
  plain Bearer GET at a `validation` map with no `:url` key and raised.
- **GitHub** declares no strategy, so it falls through to that generic clause,
  which reads `v.url` / `v.auth_header` / `v.auth_prefix`. All three are present
  on the provider map. `https://api.github.com/rate_limit` answers 200/401 as the
  branch expects, and Req sends a default `user-agent`, which the GitHub REST API
  requires and 403s without.

`capabilities: [:github_api]` has no consumer in core — `with_capability/1` is a
plain filter over a free-form list, so a capability nothing reads yet is inert,
not broken. Both provider maps carry every key the `@type provider` requires, and
`instructions` / `validation` are already declared `optional(...)`, so the
`aws_ses` gaining an `instructions` block does not violate the type.

## The enrichment cannot downgrade the verdict — traced, holds

This is the part with a real failure mode, and the code gets it right. The claim
is that `CredentialsVerifier` failing can never turn a pass into a fail. Tracing
`ok_with_note/3` → `enrich_note/3`:

- probe raises / exits / times out → `_ -> quota_note`, the original note survives;
- probe returns `{:ok, note}` → the enriched note, which **includes** `quota_note`
  because `aws_note/3` joins it in;
- probe returns `:ok` → `nil` → a bare `:ok`. Reachable only when identity,
  services *and* `quota_note` are all nil, i.e. there was genuinely nothing to
  say. It cannot silently drop a quota note, because a non-nil `quota_note` makes
  `aws_note/3` non-nil by construction.

The verdict is the send-quota probe in every branch. Correct.

## Region guard

`~r/^[a-z]{2,4}(-[a-z]+)+-\d{1,2}$/` accepts `us-east-1`, `us-gov-west-1` and the
4-letter sovereign `eusc-de-east-1`, and rejects `bedrock.evil.example/` before it
becomes a hostname — which is the point, since the region is interpolated into
the probe URL. `bedrock_host/1` splitting the China partition onto
`.amazonaws.com.cn` is right; the global host does not resolve there and the
failure would have surfaced as an unhelpful "could not reach Bedrock".

Distinguishing 403 from 401 is worth calling out as good judgement: the most
likely 403 is a key missing `bedrock:CallWithBearerToken`, and reporting that as
"invalid credentials" would send an operator off to reissue a perfectly good key.

`retry: false` on the Req call with the outer `Probe` deadline as the only clock
is the correct pairing — Req's default transient retries would sleep through most
of the probe budget.

## NITPICK — not changed

`aws_note/3` places `is_map(perms)` as a filter inside the comprehension, so it
is re-evaluated per service rather than hoisted. Three iterations; no practical
cost, and moving it would not read better.

## Not changed

No findings requiring a fix. The provider list ordering (`amazon_bedrock` before
`aws_ses`, `github` last) affects only display order in the settings UI.
