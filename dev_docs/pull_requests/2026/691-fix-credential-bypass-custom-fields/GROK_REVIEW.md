# PR #691 Recheck — Credential rank rule bypassable via custom_fields

**PR:** https://github.com/BeamLabEU/phoenix_kit/pull/691
**Author:** Tymofii Shapovalov (timujinne)
**Merged:** 2026-08-09 (`2eadb6e9`)
**Reviewer:** Grok (recheck of Claude's work)
**Date:** 2026-08-09

---

## Verdict

**Vulnerability closed and Claude's five follow-ups still hold.**

| Check | Result |
|---|---|
| Form drops schema identity fields from `custom_fields` | Reads `Auth.updatable_profile_fields/0` — single source of truth |
| Context rank rule on `admin_update_user_password/3` | Present; malformed actor/target fail closed without crash |
| Dropped keys logged | Present |
| `update_user_fields/2` docs warn no auth / credentials | Present |
| Partial profile-then-password write on disagreement | Still present — Claude deliberately left it; still the right call |

No new findings in this pass. Integration tests still need PostgreSQL.
