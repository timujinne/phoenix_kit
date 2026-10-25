# PR #976 — Settings → API built from the kit's components

**Author:** timujinne · **Merged:** 2026-10-23 (cbd36d6c0) · **Reviewer:** Claude

## Summary

The Settings → API template is rebuilt from `form_section`, `checkbox`, `input`, `select`, `textarea`, `modal`, `status_badge`, `accordion`. To get there the
components gain `hint` (linked with `aria-describedby`, new `FormFieldHint`), `wrap_label`, `checkbox` `value` / `unchecked_value` (a `name[]` group submits
only the ticked boxes), `form_section` `wrap_actions`, `modal` `actions_class`, a `"ending"` badge status. Each module's row lists its admin tools with
availability (`Executor.tool_availability/1`, refreshed after the module switch, the "Agent may act" box and the hidden-tools limit), and a module's name is
translated by the gettext backend it declares.

Verdict: correct. Checked: every `<form phx-change>` has an id; `key[scopes][]` / `key_scopes[scopes][]` groups use `unchecked_value={nil}` and the handlers
read `string_list(params["scopes"])`, so an empty group is fine; the edit-scopes form keeps its `present` marker; the "Agent may act" box is a `phx-click`
control, not a form field, so the "disabled checkbox still submits its hidden `false`" landmine does not apply; `status_class(:ending)` moved into the
badge. Component and LiveView tests green.

## Findings

- **IMPROVEMENT - MEDIUM (fixed):** `module_label/1` resolved the module's gettext backend through `ModuleRegistry.permission_gettext/0`, which asks every
  registered module for its `permission_metadata/0` (and logs a warning per misdeclared backend), and the template called it five times per module row, so
  one render did O(modules²) metadata calls and a bad backend logged on every render. The label is now computed once per module in `api_modules/0`
  (`:label`), the template reads `mod.label`, and `module_label/1` returns a carried label (still resolves a bare `%{key, name}`, so the flash messages and
  the existing label tests are unchanged). Test added.
- **NITPICK (not changed):** `tool_availability/1` runs on every `assign_state` (mount, each switch, the limits save). Its doc says to call it once per page;
  that holds, but each event reads the settings again.
