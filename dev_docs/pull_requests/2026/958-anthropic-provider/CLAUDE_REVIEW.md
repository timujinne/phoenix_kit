# PR #958 — Add the Anthropic provider to integrations

**Author:** timujinne · **Merged:** 2026-10-21 (5c47116ea) · **Reviewer:** Claude

## Summary

Registers `anthropic` (`:api_key`, system + personal, `:ai_completions`). `base_url` is Anthropic's OpenAI-compatibility layer so AI
consumers need no change; the key check uses the native `GET /v1/models` with `x-api-key` plus `anthropic-version`, which needs a new
optional `validation.extra_headers` (documented in `Providers` and the integrations guide). A test seam,
`:integrations_check_req_options` (`Keyword.take([:plug, :retry])`), routes the generic check through `Req.Test`.

Verdict: correct and self-contained. The check URL is a constant, so a personal connection cannot steer the request (no SSRF
surface); extra headers are appended after the auth header and default to `[]`, so every other provider sends exactly what it did.
All nine `.po` files carry the entries, with a translation test; no fuzzy entries in any locale.

## Findings

- **NITPICK (not changed):** `check_req_options/0` reads application env on the production path. Only `:plug` and `:retry` get
  through and the key is unset in production, but anyone who can write the app env could swap the check's transport; a
  compile-time `Mix.env()` gate would be stricter. Acceptable for a test seam.
- Not verified here: Anthropic's live behaviour (workspace-scoped key requirement, `/v1/models` answers). Those statements come from
  the PR's comments and guide, not from a call.
- Tests: `anthropic_provider_test.exs`, `anthropic_provider_translations_test.exs` — green.
