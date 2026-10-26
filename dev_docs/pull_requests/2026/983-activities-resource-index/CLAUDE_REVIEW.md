# PR #983 — V224 activities resource index; translated notification types

**Author:** mdon · **Reviewer:** Claude · **Verdict:** approve, one incomplete rollout fixed

## Findings

### IMPROVEMENT - HIGH — `Types.translate/2` was wired into two of the four label surfaces (fixed)
The PR translates the notification-type labels in `user_settings.ex` and the Telegram card,
but not in the page that is the primary consumer, `Live.Notifications.Settings` ("My Settings"
matrix): type/sub-type label and description, the aggregation dialog title and `leaves/1`
(which feeds the cadence modal) still rendered the raw English `label`. The page therefore
stayed English for et/ru while the PR's own moduledoc said the settings pages translate.
**Fix:** every render site goes through `Types.translate/2`. `leaves(type) == [%{key, label}]`
compared against the untranslated label, so it would have broken once `leaves` translated; it is
now `type.sub_types == []`, the same condition.

### IMPROVEMENT - MEDIUM — digest text kept an English type label (fixed)
`DigestWorker.type_label/1` runs inside `RecipientLocale.in_locale/2` but read `type.label`
raw; its comment ("`%{label}` stays English: runtime registry data") was made stale by this PR.
**Fix:** translate there; comment updated; test added (`et` recipient, `security` → "turvalisus").

### NITPICK — migration
V224 is sound: bare index name on CREATE, no CONCURRENTLY with the reasoning on record,
`RESET lock_timeout` as V163 does, `ExpectedSchema` entry catalog-exact and chain hash restamped,
down drops the index. No action.

## Verification
`mix precommit` after the changes (see the commit).
