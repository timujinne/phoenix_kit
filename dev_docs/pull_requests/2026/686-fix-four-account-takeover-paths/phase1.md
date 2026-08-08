# Phase 1 Review — phoenix_kit #686

**Title:** Fix four account-takeover paths found by a security review  
**Author:** Tymofii Shapovalov (timujinne)  
**Created:** 2026-08-07T09:54 UTC  
**Reviewer:** Pincer  
**Date:** 2026-08-07

---

## Scope

10 source files modified, 3 new test files added. No migrations, no version bump, no dependency changes.

## Files Changed

| File | Nature |
|------|--------|
| `AGENTS.md` | Documentation only — records unauthenticated `POST /api/upload` as a known open issue (not fixed here) |
| `lib/phoenix_kit/users/auth.ex` | Session revocation on deactivation + `can_manage_user_credentials?/2` |
| `lib/phoenix_kit/users/oauth.ex` | OAuth email verification requirement |
| `lib/phoenix_kit/utils/css_value.ex` | New — CSS value allowlist (XSS prevention) |
| `lib/phoenix_kit_web/components/auth_page_wrapper.ex` | Uses `CssValue` on all CSS fields |
| `lib/phoenix_kit_web/live/settings/authorization.ex` | Validates background color on write |
| `lib/phoenix_kit_web/users/multi_session.ex` | Root user resolved through active-user filter |
| `lib/phoenix_kit_web/users/user_form.ex` | Rank-based credential authority, drops fields from update |
| `lib/phoenix_kit_web/users/user_form.html.heex` | UI respects credential authority |
| `test/integration/users/oauth_email_verification_test.exs` | New — OAuth path tests |
| `test/integration/users/security_authority_test.exs` | New — credential authority + deactivation tests |
| `test/phoenix_kit/utils/css_value_test.exs` | New — CssValue unit tests |

## Red Flag Check

- **Unexpected files:** None
- **Build artifacts / swap / crash files:** None
- **Secrets or credentials:** None
- **Suspicious dependency changes in mix.exs:** None (mix.exs not touched)
- **Unrelated changes:** AGENTS.md addition is documentation for a still-open issue (upload auth), not a code fix — appropriate housekeeping

## Four Paths Fixed

1. **OAuth email takeover** — `PhoenixKit.Users.OAuth` previously merged provider email match to existing local accounts unconditionally. Now requires a provider assertion that the address is verified (`email_verified`, GitHub's per-address `verified` flag, Facebook's `verified`, or the operator explicitly setting `oauth_require_verified_email: false`). Unrecognised provider shape defaults to refused, not open. Correct defensive default.

2. **Credential management rank bypass** — `user_form.ex` previously gated password/reset/email actions on `can_access_admin_area?/1`, which is true for any holder of a single permission. New `can_manage_user_credentials?/2` checks role AND rank: Owner manages anyone, Admin manages plain users only, plain users manage themselves only. Server-side enforcement drops `password` and `email` from the update map if the actor lacks authority — hiding the UI field was presentation, not a control.

3. **Deactivation revokes sessions** — `Auth.update_user_status/2` now calls `delete_all_user_session_tokens/1` when `is_active` flips to `false`. Tokens previously survived for their full 60-day life; a deactivated account could still resolve at any entry point that skipped the `ensure_active_user` filter.

4. **Multi-session root via deactivated token** — `root_user_from_token/1` pipes through `Auth.ensure_active_user/1`. Defence in depth: even if a token was minted before fix #3, or a database-direct `is_active` flip bypasses token revocation, the multi-session root resolution still refuses a deactivated account.

   **CSS stored XSS** is effectively a fifth fix (title says four — this may be the one the title groups differently, or the PR author counts the deactivation + multi-session pair as one). Operator-settable auth background colour reached a `<style>` element as raw character data; `CssValue.color/1` is an allowlist, not a sanitiser, and drops anything it does not recognise to `""`. Applied on read and re-applied at assembly; rejected on write with a user-visible error.

## Assessment

All changes are appropriate and well-scoped. Documentation is unusually thorough and explains the rationale directly. Test coverage is strong — OAuth tests cover the linking path, the verified/unverified branches, GitHub's per-address structure, malformed `raw_info`, and a pre-existing link bypassing email checks. Security authority tests cover the role matrix and defence-in-depth (database-direct flip). `CssValue` tests include the actual stored-XSS payload that motivated the fix.

No concerns.

## Verdict

✅ **RECOMMEND MERGE** — no blockers, no red flags.
