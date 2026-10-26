# PR #984 — follow-up

- `Permissions.get_permissions_for_role/1`, `get_permissions_for_roles/1` and `roles_with_permission/1` still rescue to `[]` for existing callers; any new authorization or backfill code should use the `fetch_*` variants (AGENTS.md says so).
- A disabled module's settings page is refused by the admin gate before mount, Owner included; re-enabling goes through the Modules page, which needs `modules`. Unchanged, noted because several modules' docs now say it.
