# PR #673 — Bring the admin UI onto the framework's own components, full width and one header per page

**Author:** Timujeen · **Merged:** 2026-07-29 (`331e17c4`) · **Reviewed:** 2026-07-29

52 files, 11 commits. Three separate sweeps landed together:

1. **Headers** — every page-local `<header>` / `<.admin_page_header>` folded into
   the `LayoutWrapper` breadcrumb (`page_section`, `page_section_path`,
   `page_subtitle`, `page_action`), and `container mx-auto` width caps stripped.
2. **Form controls** — hand-rolled `<input>` / `<select>` / `<textarea>` /
   checkbox markup replaced with `<.input>` / `<.select>` / `<.textarea>` /
   `<.checkbox>`.
3. **List UI** — `<.table_default>`, `<.empty_state>`, `<.pagination>`,
   `<.search_toolbar>`, `<.nav_tabs>` adopted, plus a new `<.row_link>`
   whole-row-clickable component.

**Verdict: the sweep is right, and the two hardest calls in it are correct.** The
`row_link` moduledoc's `transform-gpu` analysis (WebKit ignores `position:
relative` on `<tr>`, so without a containing block every row's overlay collapses
onto the last one) is a real, well-diagnosed bug that most reviewers would never
catch, and the explicit *"do not depend on a custom class such as
`row-link-host`"* warning is exactly the right instinct for a library shipping
into hosts it does not control. The refusal to convert the role-sync checkboxes
(`sync_user_roles` diffs `Map.values(params["roles"])`, so a component hardcoding
`"true"` would strip every role a user holds — and `render_submit` injects params
so no test would catch it) is a genuinely subtle save.

What did not hold up is mostly **parity between the four form components** the
sweep now depends on. `<.input>` gained a required marker; `<.select>` and
`<.textarea>` did not, so converting a required control to either one silently
drops the marker its hand-rolled markup carried. And the one place the
`row-link-host` warning applies, the code does the thing the warning forbids.

---

## BUG - MEDIUM — `<.select>` and `<.textarea>` silently drop the required marker `<.input>` renders

`lib/phoenix_kit_web/components/core/input.ex:87` ·
`lib/phoenix_kit_web/live/settings/organization.html.heex:28`

The PR added a required marker to `<.input>` and, correctly, deleted the
hand-rolled `<span class="text-error">*</span>` from every label it converted:

```diff
-<span class="label-text">{gettext("Country")} <span class="text-error">*</span></span>
-<select name="company_country" required>
+<.select name="company_country" required label={gettext("Country")} ... />
```

But the marker was only added to `<.input>`. `<.select>` renders its label
through `FormFieldLabel` and never looks at `@rest[:required]`, so **Country** on
`/admin/settings/organization` lost its red asterisk while Company Name, Street
Address, City and VAT Number — all `<.input>` — kept theirs. The one required
field in that form that reads as optional is the one that gates the EU-VAT
branch below it.

The same gap exists on `<.textarea>`, and it will bite the next required
textarea conversion the same way.

**Fixed.** Both components now render the identical marker off `@rest[:required]`.
`select_test.exs` / `textarea_test.exs` pin the marker present-when-required and
absent-when-not.

## BUG - MEDIUM — a field-bound `<.textarea>` never renders its validation errors

`lib/phoenix_kit_web/components/core/textarea.ex:27-33` ·
`lib/phoenix_kit_web/live/users/user_details.html.heex:487`

`<.input>` and `<.select>` both map the field's errors in their `FormField`
clause:

```elixir
|> assign(:errors, Enum.map(field.errors, &translate_error(&1)))
```

`<.textarea>` does not — it maps `id`, `name` and `value` and stops. So a
field-bound textarea renders **no error text and no `textarea-error` border**
however the changeset fails. To the user the form simply refuses to save with no
explanation.

Pre-existing (`roles.html.heex`, `send_profile_form.html.heex` already bound
fields), but this PR both edited `textarea.ex` and added a fourth call site — the
admin-note box on the user detail page, whose `content` is `required` and is the
single realistic way to trip it.

**Fixed.** The field clause now maps `field.errors` like its two siblings.
`textarea_test.exs` covers errors-rendered and no-errors-stays-clean.

## BUG - MEDIUM — the organization-members table uses `row-link-host`, the class `row_link`'s own docs forbid

`lib/phoenix_kit_web/live/users/user_details.html.heex:617`

```heex
<.table_default_row class="row-link-host relative cursor-pointer">
```

Every other `row_link` host in the PR uses `class="relative transform-gpu
cursor-pointer"`. This one uses `row-link-host` — which is precisely what the
component's moduledoc calls out by name:

> Do **not** depend on a custom class such as `row-link-host` for this: that rule
> lives in one host app's `app.css` and is absent from every other consumer,
> where the failure is invisible in source and only shows up on an iOS device.

`row-link-host` is defined nowhere in this repo (`rg` finds it only in that
warning and in this one call site). So on Safari/iOS the `<tr>` gets no
containing block, all eight members' overlays collapse onto the last row, and
tapping any member opens the last one. Invisible on desktop Chrome, invisible in
tests, and it is the exact failure the moduledoc was written to prevent.

**Fixed.** Swapped to `relative transform-gpu cursor-pointer`.

## BUG - MEDIUM — the users list row is clickable only while the removable "email" column is shown

`lib/phoenix_kit_web/live/users/users.html.heex:366-380`

The row got `cursor-pointer` unconditionally, but the `<.row_link>` that makes it
clickable was rendered inside `cond do column_id == "email"`. The users table has
a column picker backed by `PhoenixKit.Users.TableColumns`, and `"email"` is
`required: false` (`lib/phoenix_kit/users/table_columns.ex:219-224`) —
`remove_column` does not consult `column_required?/1` either. Drop Email from the
picker and every row still says "click me" and does nothing.

`"actions"` can't host the overlay instead: that cell carries `relative z-10`,
which would float the overlay above its own row menu and swallow the buttons.

**Fixed.** The host cell is now the first visible non-`actions` column, computed
once per render, and `cursor-pointer` is applied only when such a column exists.

## IMPROVEMENT - MEDIUM — the "add option" input lost its `flex-1`

`lib/phoenix_kit_web/live/settings/users.html.heex:678`

```diff
-<input class="input input-bordered input-sm flex-1" ... />
+<.input ... class="input-sm flex-1" />
```

`class` merges onto the `<input>`, but `<.input>` wraps it in a
`<div phx-feedback-for>` — and *that* div is now the flex item. `flex-1` on the
inner input does nothing; the wrapper is content-sized, so the field collapses
next to the "Add" button instead of filling the row. The PR already knows the
fix and uses it twice (`wrapper_class="contents"` on the media-selector search
and the tax-rate join) — it was just missed here.

**Fixed.** Added `wrapper_class="contents"`.

## IMPROVEMENT - HIGH — the new translatable strings were never extracted

The PR wrapped a batch of bare strings in `gettext/1` — page titles in
`bucket_form.ex`, `dimension_form.ex`, `user_form.ex`, and the header text in
`user_form.html.heex` / `media_detail.html.heex` — without touching the
catalogs. None of them existed in `default.pot`, so **ru and et — the two
locales kept at 100% — rendered them in English.**

Ten msgids are attributable to #673:

```
Add Storage Bucket        Create User                 Media Detail
Edit Storage Bucket       Edit User
Add Storage Dimension     Create a new user account
Edit Storage Dimension    Edit user information
Update Dimension
```

(The `page_section` crumbs — `"Media"`, `"Modules"`, `"Dimensions"`,
`"Integrations"` — and `"Select Media"`, `"Add Image Dimension"`,
`"Add Video Dimension"` already had entries.)

**Fixed**, by hand-append rather than merge. A full `mix gettext.extract --merge`
reports `246 new / 12 removed / 53 reworded (fuzzy)` across 28k lines in 9 files
— the `.pot` is stale by ~25× this PR's contribution, a repo-wide backlog #673
did not cause, and the 53 fuzzy re-marks would knock ru and et **off** 100%
rather than toward it. So the ten stanzas above were appended to
`default.pot` + `ru` + `et` with translations, and the extract churn reverted;
`mix compile` (the pure-Elixir gettext compiler) validates PO syntax, duplicate
msgids and `%{}` binding mismatches.

The remaining ~236-msgid backlog is still open and still wants its own commit.
`mix precommit` does not run gettext extraction, so nothing catches this drift
automatically.

---

## Verified, not bugs

Things that looked wrong on first read and are not:

- **`transform-gpu` on rows vs. `position: fixed` row menus.** A transformed
  ancestor normally breaks `position: fixed` descendants, which would have
  mispositioned every `<.table_row_menu>` in the PR. It doesn't: the `RowMenu`
  hook portals the `<ul>` to `<body>` while open
  (`document.body.appendChild(this.menu)` in `priv/static/assets/phoenix_kit.js`),
  so the menu never has the transformed `<tr>` as an ancestor.

- **`<.select value={@config.schedule_interval_hours}>` with integer values and
  string options.** `options_for_select/2` compares `html_escape/1` of both
  sides, so `24` matches `"24"`. Same for the atom `:all` against `"all"` in the
  media selector. Pinned by a test so it stays true.

- **`<.checkbox>`'s hidden `value="false"` on the storage settings form.** Those
  checkboxes sit inside `phx-change="update_storage_form"`, which reads only
  `form_redundancy` and `form_max_upload_size_mb`; the checkbox state is owned by
  the `toggle_form_*` `phx-click` handlers. The extra param is inert. Same story
  for the `perm_*` checkboxes in the roles modal — they are not inside a form at
  all.

- **`name="search_query"` added to the languages search box.** Not inside a form,
  and `phx-keyup` payloads carry `value`, not the input's name — the handler
  still matches `%{"value" => query}`.

- **`Enum.with_index()` as select options in the custom-fields form.**
  `{element, index}` reads as `{label, value}`, which is what the hand-rolled
  markup did (`<option value={index}>{option}</option>`).

## Nitpicks

- `dev_docs`-worthy comments referencing an **external commit message** and a
  person by name ("see RowLink's commit message — Andi's own `row_link/1` import
  would become ambiguous"), copy-pasted into six LiveViews. Neither is
  discoverable from the repo. **Fixed:** the rationale now lives in the RowLink
  moduledoc under an `## Import` heading, and the six comments state it directly.
- `RowLink`'s moduledoc example used `~p"/orders/123"`. This project never uses
  the verified-routes sigil — it uses `Routes.path/1` (CLAUDE.md: *"NEVER
  hardcode PhoenixKit paths"*). **Fixed.**
- `require Logger` left behind in `lib/modules/storage/web/dimensions.ex` after
  its two `Logger.info` calls were deleted. Harmless (no warning) but dead.
  **Fixed.**
- The PR dropped daisyUI 4's dead `label-text` class from `<.input>`'s label but
  `FormFieldLabel` — used by `<.select>` and `<.textarea>` — still emits it, as
  do 121 other spots. It's a no-op under daisyUI 5 so nothing renders
  differently; left alone rather than churning 27 files mid-review.
- `<.pagination>` / `<.pagination_info>` hardcode English (`"« Prev"`,
  `"Showing … results"`, `"No results"`). Pre-existing, and now on more pages
  because the PR adopted the component in `/admin/activity`.

---

## Gate

`mix format` + `mix precommit` (compile `--warnings-as-errors --all-warnings`,
`deps.unlock --check-unused`, `format --check-formatted`, `credo --strict`,
`dialyzer`, JS tests) — clean.

New component tests: `test/phoenix_kit_web/components/core/select_test.exs`,
`test/phoenix_kit_web/components/core/textarea_test.exs` (7 tests, no DB
required). Closes two of the four bullets CLAUDE.md's TODO tracks under
*"Component test coverage for `phoenix_kit_web/components/core/`"*.
