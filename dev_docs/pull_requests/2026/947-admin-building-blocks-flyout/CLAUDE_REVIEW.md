# PR #947 — Document core's admin building blocks; fix the flyout's third level

**Author:** mdon · **Reviewer:** Claude · **State at review:** open, clean (merged with `--no-ff`, no conflicts)

## Code change: `AdminSidebar` flyout

The compact-mode flyout drew each subtab with `subtab.active` and its own path, so a subtab with
`redirect_to_first_subtab: true` (the middle level of a three-level section) linked to a page of its
own, and stayed lit while one of its children was open — the inline list already did both correctly.
The PR lifts the inline list's logic into one private `subtab_link/2` (`{link_tab, active?}`) and uses
it in both places, which is the right shape: the two drawings can no longer drift.

Checked: `@all_tabs` is a required attr of the flyout's component; `subtab_link/2` recomputes
`get_subtabs_for/2` and `any_descendant_active?/3` (depth-capped, cycle-safe) once per subtab per render,
the same work the inline list already did, so the flyout adds one extra pass over a handful of tabs.
The new `admin_sidebar_three_levels_test.exs` (3 tests) asserts both drawings of the middle entry —
the list and the flyout, two anchors — link to the first child and are not lit while a child is open;
105 dashboard tests, 0 failures.

## `usage-rules.md`

A new "Admin Pages: Navigation and Components" section. I checked the claims against the tree: every file
named in the table exists under `components/core/`, and every `<.component>` it names is defined
(`bulk_select_*` stands for `bulk_select_scope`/`_header_cell`/`_cell`). The `Tab` example matches the
fields the sidebar reads (`parent`, `match`, `redirect_to_first_subtab`, `highlight_with_subtabs`,
`subtab_display`). The dashboard README note now points at it.

- **NITPICK** — the example's literal-before-parameterised route advice is true of declaration order
  only; two modules registering the same prefix are ordered by priority/discovery, not by this file.

No fixes needed.
