# PR #967 — Add the Z.ai provider to integrations

**Author:** timujinne · **Merged:** 2026-10-23 (8b4620e09) · **Reviewer:** Claude

## Summary

A built-in `zai` provider (`:ai_completions`, site-wide and personal) on the general OpenAI-compatible endpoint `https://api.z.ai/api/paas/v4`, generic
Bearer key check against `/models`, setup instructions, nine locales, guide entry. The GLM Coding Plan endpoint is deliberately not used.

Verdict: matches the shape of the other API-key providers (no `extra_headers`, `auth_prefix: "Bearer "`), registered in `builtin_providers`, all new msgids
translated in every `.po` (`zai_provider_translations_test` passes), guide updated. `zai_provider_test` + translations test: green.

## Findings

- **NITPICK (not changed, already on record in the code and guide):** `GET /models` is not in Z.ai's published reference. Until it is confirmed with a real
  key, a valid key could still be reported as failing validation. The PR says so in the provider comment and the guide; nothing to add.
- **NITPICK (not changed):** the placeholder `xxxxxxxx.xxxxxxxx` is not translated (it is a format sample, like the other providers').
