# Registered profile settings tabs — Codex review

Reviewed commit `f19d6a7df21ecc3038c29db6a5874546b7f69921` (direct commit on
`main`, no associated PR), including the registry, route generation, tab strip,
public contract and tests.

## Findings and fixes

### BUG - MEDIUM: disabling a module could change a duplicate tab's identity without changing its route

The router deduplicated declarations from all modules, but the runtime registry
filtered disabled modules before deduplicating. If the first declaring module
was disabled and a later enabled module reused its id, the strip displayed the
later module's tab while the compiled URL still opened the first module's page.

The registry now resolves duplicate ids before checking enablement, using the
same deduplication function as the router. A disabled winner stays hidden;
another module cannot take its URL. A regression test reproduced the mismatch
before the fix and now verifies that the strip agrees with the route owner.

### BUG - MEDIUM: permission checks bypassed base permissions and live enablement

The tab's `permission:` used `Scope.has_module_access?/2`, a cached membership
check. An orphaned dotted permission could offer a tab without its base, and a
host tab could remain visible for a feature that had been disabled since the
scope was loaded.

The check now uses `Scope.can?/2` and catches exceptions, throws and exits around
the permission evaluation, keeping the advertised fail-closed behavior when a
feature-enablement check fails. Tests cover the missing base, a valid base/sub
pair, a disabled feature and an exiting feature check. The missing-base test
failed against the original implementation.

### IMPROVEMENT - MEDIUM: verify compiled routes instead of only quoted code

The original routing test inspected `Macro.to_string/1`, which could not detect
an incorrectly scoped route, a missing authentication hook or a route swallowed
by `/profile/settings/:tab`.

A new test compiles a host router through `phoenix_kit_routes/0` and verifies
the registered LiveView and action in both prefixed and locale-prefixed URLs,
the authenticated live session and its authentication hook, and the config
change recompilation predicate. Compilation happens in the synchronous test
phase to avoid racing other router fixtures' application configuration.

## Access contract

The existing contract deliberately gates the tab strip only. A custom page
still checks its own access, including its module's `enabled?/0`, when mounted;
authentication is supplied by the generated route. This remains explicit in
`PhoenixKit.ProfileSettingsTab` and `PhoenixKit.Module.profile_settings_tabs/0`.
Hiding a tab is not authorization for its page or its writes.

## Validation

- Focused suite: **145 tests, 0 failures**, with PostgreSQL reachable and the
  integration tests executed. Covers registered tabs, module registry, scopes,
  sub-permissions, profile settings pages and registered-tab navigation.
- Both original regression reproductions failed before their fixes and pass
  afterward.
- `mix precommit`: **passed**, including compile with warnings as errors,
  unused-lock check, test compilation, format, strict Credo, Dialyzer and
  **473 JavaScript tests**.

No migration, version bump or release is part of this review.
