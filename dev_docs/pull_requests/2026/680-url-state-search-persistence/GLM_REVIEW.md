# PR #680 — `UrlState` review log

Two `ask-glm` (`elixir-review`) rounds. `ask-kimi` was skipped: the account is at
its rate limit.

## Round 1 — before the PR was opened

**Verdict: APPROVE with findings.** The reviewer independently confirmed the
parts most likely to be wrong: no atom is created from user input, the
change-detection guard neither skips a needed reload nor fires a spurious one,
the page-reset rule holds for every converted handler, declared and unknown key
spaces never overlap, and the patched path cannot become an open redirect
because `push_patch` cannot leave the current route.

### Fixed in `d186b395`

| Severity | Finding | Fix |
|---|---|---|
| IMPROVEMENT | **Unbounded integer → 500.** Page params declared `min: 1` but no `:max`. `?page=999999999999999999999999` parses, reaches Ecto as `OFFSET`, and overflows PostgreSQL's `bigint` on all five converted screens. Not a regression — the previous `String.to_integer/1` shipped the same value — but the codec is now the single validation chokepoint and bounded only one end. | Integer params get a default ceiling of 1,000,000, overridable per param. Applied in the module rather than per-LiveView, so the remaining ~20 conversions inherit it instead of each having to remember. |
| IMPROVEMENT | **`dead_render: :skip` docs were wrong.** They promised "an empty first paint". But every conversion moved list loading out of `mount/3`, so with `:skip` the callback's assigns do not exist on the dead render and a template iterating them raises. Nothing ships broken — no conversion uses `:skip` — but the next adopter following the doc would have hit it. | Moduledoc now states the requirement: the template must tolerate the missing assign, or mount must seed a placeholder. |
| NITPICK | **The motivating example was inert.** `show_add_user_modal` in `users.ex` is assigned by `handle_params/3` but read nowhere, and nothing patches `?action=add`. The module's comments leaned on it to justify the change-detection guard and unknown-key preservation. | Comments now cite the media selector's `?return_to=…&mode=single`, which is a live round-trip. The dead assign itself is pre-existing and left alone — out of scope for this PR. |

### Accepted as a known gap

**LiveView-level tests are missing.** The design doc promised `live_isolated/3`
coverage of the `on_mount` → hook → host `handle_params/3` ordering; it was not
delivered, because `live_isolated/3` mounts without a router and this module
refuses that by design. Building a test router and endpoint is real work and
belongs in its own change rather than smuggled into this one.

Partially closed instead: `reload?/3` — the single branch deciding whether a
shared link, a Back press or a filter change reloads — was made public
specifically so it could be pinned without a router, and `url_state_path/2`
already accepted a bare assigns map, so path capture, fallbacks, page reset and
unknown-key preservation are all now tested. 41 tests, no PostgreSQL.

The gap is recorded in the design doc rather than papered over.

## Round 2 — against the published PR

Aimed at what a first pass usually misses: the five conversions rather than the
module, assigns that `mount/3` stopped setting, and handlers that push a URL
identical to the current one (where the change-detection guard would correctly
skip the callback and leave the screen stale).

**Verdict: NEEDS-WORK, on a single finding — which does not reproduce.**

### BUG-HIGH `live_sessions.ex:109` — not a defect

The reviewer reported that `toggle_sort` passes `dir:` — a URL key rather than
an assign name — and would therefore crash on `validate_changes!` on every
column-header click.

The committed line is:

```elixir
%{by: sort_by, dir: sort_dir} = toggle_sort(socket.assigns.sort, parse_sort_by(by))

{:noreply, push_url_state(socket, sort_by: sort_by, sort_dir: sort_dir)}
```

Both keys are declared params. The `dir:` the reviewer saw belongs to the
destructuring pattern on the line above — `toggle_sort/2` returns the compound
`%{by:, dir:}` map the template consumes — not to the keyword list. No change
made.

Worth noting the guard being cited is the one added in round 1 for exactly this
mistake, so a real instance would have been loud rather than silent.

### Verified clean

- **Identical-URL pushes.** `media_selector`'s upload and save paths reload in
  place when already on page 1 and patch otherwise, so the guard cannot leave
  the grid stale. The other four screens route every data mutation through a
  direct `load_*` rather than the URL, so none depend on the guard for
  correctness.
- **Dropped assigns.** The one compound assign moved out of `mount/3` — `:sort`
  in `live_sessions` — is set by `handle_url_state/2`, which runs on the dead
  render too (`@loaded` is false, and `dead_render: :call` is the default), so
  it exists before first paint.
- **`reset_url_state/1`.** Clears every declared param, interacts correctly with
  the page reset, and preserves unknown keys.
- **The `.heex` changes.** The new `phx-change="search"` matches the nested
  `%{"search" => %{"query" => …}}` clause, and `url_state_path(assigns, …)` in
  the pagination links resolves because the private assigns are present at
  render.
