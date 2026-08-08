# URL-backed list state (search / filter / sort / page)

**Status:** design approved, implementation not started
**Branch:** `feature/url-state-search` (worktree `/www/phoenix_kit_search`, cut from `upstream/main` @ 918fa1b7)

## Problem

Typing in a list's search box filters the table but leaves the address bar
untouched on most screens in the workspace. The result cannot be shared, does
not survive a reload, and browser Back walks out of the page instead of back to
the previous query.

A workspace-wide audit found **26 LiveViews** with this defect, and — more
importantly — **seven independent implementations** of the fix on the screens
that do work:

| Implementation | Shape |
|---|---|
| `MediaBrowser.Embed` (core) | `attach_hook` + path from `uri`; the only non-trivial one |
| `Activity.Index` (core) | hand-rolled `maybe_put` + `URI.encode_query` |
| `phoenix_kit_comments` | nested form params, `maybe_put`, dual clear events |
| `phoenix_kit_billing` | flat params, `Enum.reject`, `build_url_params/2` |
| `phoenix_kit_crm` | per-LV `contacts_path/2` / `companies_path/2` / `members_path/2` |
| `phoenix_kit_emails` | `build_url_params/2` |
| `phoenix_kit_ecommerce` | `FilterHelpers.build_query_string/2` + local `Carts.build_url/2` |

They differ only cosmetically. Six of the seven share a real defect: they
rebuild the path from a hardcoded string (`Routes.path("/admin/comments?…")`),
so an LV reachable at more than one route — a sub-tab such as
`/orders/:id/edit/files` — patches itself to the wrong page. Only
`MediaBrowser.Embed` derives the path from the live `uri` and appends only the
query.

### Audit result

| Repo | Search surfaces | Broken |
|---|---|---|
| core (`phoenix_kit`) | 12 | **5** — `users`, `sessions`, `live_sessions`, `jobs/index`, `media_selector` (page only) |
| Andi (`/www/app`) | 2 | **2** — orders, sub-orders |
| `phoenix_kit_warehouse` | 7 | **7** |
| `phoenix_kit_catalogue` | 4 | **3** |
| `phoenix_kit_projects` | 3 | **3** (blocked — see Constraint) |
| `phoenix_kit_ecommerce` | 6 | **2** (`products` reads `?search=` but never writes it) |
| `phoenix_kit_manufacturing` | 1 | **1** |
| `phoenix_kit_emails` | 5 | **1** (`blocklist`) |
| `phoenix_kit_staff` | 1 | **1** |
| `phoenix_kit_billing` | 5 | **1** (`subscriptions` — `phx-submit` instead of `phx-change`) |
| `phoenix_kit_crm` | 4 | 0 |
| `comments`, `ai`, `document_creator`, `entities`, `hello_world`, `locations` | — | 0 |

## Goals

Search, filters, sort and page live in the query string. Every list state has a
unique URL that can be pasted to a colleague or reloaded and reproduces exactly
what the sender saw. One implementation in core replaces the seven.

## Non-goals

- Migrating the already-correct screens (`crm`, `comments`, `billing`, `emails`,
  `document_creator`, `entities`, the `ecommerce` storefront). They are not
  broken; folding them into `UrlState` is a later cleanup, kept out of this work
  so a refactor does not ride along with a fix.
- Moving `view_mode` (table/card) out of the database. See "view mode" below.
- Server-side full-text search behaviour. Only the transport of the state
  changes; each LV keeps its own query logic.

## Constraint: `push_patch` and embeddability are mutually exclusive

This was verified against `phoenix_live_view` source, not assumed, and it
changes the plan for `phoenix_kit_projects`.

1. `Lifecycle.attach_hook/4` **raises** for a `:handle_params` hook when
   `socket.router == nil` (`lifecycle.ex:44`).
2. `maybe_call_mount_handle_params/4` computes
   `lifecycle.any? = callbacks? or exported?`. When an LV is embedded via
   `live_render` (`socket.root_pid != self()`), `any? == true` takes the branch
   that calls `Route.live_link_info!(%{socket | router: nil}, …)` — a guaranteed
   raise (`channel.ex:611-617`). Exporting `handle_params/3` is therefore enough
   to make an LV un-embeddable, whatever its body does.
3. A `push_patch` from a root LV lands in
   `sync_handle_params_with_live_redirect/5`, which calls
   `Utils.call_handle_params!(socket, socket.view, params, uri)` — the 4-arity
   form, so `exported?` defaults to **true** and `view.handle_params/3` is
   invoked unconditionally (`channel.ex:995-1002`, `utils.ex:457`). `push_patch`
   therefore *requires* the export.

(3) requires what (2) forbids. **An LV cannot both `push_patch` and be
embeddable via `live_render`.**

Consequences:

- `use PhoenixKitWeb.Live.UrlState` marks an LV **router-only**. This is a
  documented part of the contract, not an accident.
- `phoenix_kit_projects` deliberately removed `handle_params/3` from all 10 of
  its LVs so Andi can embed them (`dev_docs/embedding_audit.md`, pinned by 43
  `live_isolated/3` tests). Its 3 search surfaces are **out of scope** here.
  Giving them URL state needs a different mechanism — a JS `history.pushState`
  + `popstate` hook, which is what the module already does for tab state via
  `ProjectTabsUrl`. Deferred to its own design; not speculatively seamed into
  this one.
- The same constraint already applies, undocumented, to
  `MediaBrowser.Embed, url_sync: true` — its `__before_compile__` stub makes the
  host LV un-embeddable. The moduledoc must say so.

## Design

### `PhoenixKitWeb.Live.UrlState`

One module in core. Declarative spec replaces the seven `build_url_params`
variants:

```elixir
use PhoenixKitWeb.Live.UrlState,
  params: [
    search_query:        [default: "", url_key: "q", alias: "search"],
    filter_role:         [default: "all", url_key: "role"],
    filter_account_type: [default: "all", url_key: "account_type"],
    page:                [default: 1, cast: :integer, min: 1]
  ]
```

- **Param key = assign name**, with `url_key:` naming the query-string key
  separately. The real `users.ex` forced this apart: its assign is
  `:search_query` while the URL must read `?q=`. Keeping the assign name means
  the template is untouched by the conversion — the 700-line
  `users.html.heex` needed no edit at all.
- **Defaults are not always `nil`/`""`.** `filter_role` defaults to `"all"`, so
  `"all"` is what gets omitted from the URL.
- **`alias:`** is decoded but never encoded. `comments`, `billing`, `crm` and
  `catalogue` have already published links carrying `?search=`; MediaBrowser
  publishes `?q=`. The alias lets everything converge on `q` as the canonical
  key while old links keep resolving.
- **`cast:` / `in:` / `min:`** whitelist the value; anything else falls back to
  the default. No `String.to_existing_atom` on user input — the hazard already
  recorded for `ReorderModal` in `CLAUDE.md`.

### One callback instead of `handle_params/3`

```elixir
@impl PhoenixKitWeb.Live.UrlState
def handle_url_state(%{q: q, status: status, page: page}, socket) do
  assign(socket, :users, Users.list(search: q, status: status, page: page))
end
```

Invoked from `on_mount` and from the `:handle_params` hook on every change. The
adopting LV writes no `handle_params/3` of its own; the macro injects the stub
that (3) above requires.

### Writing state

```elixir
def handle_event("search", %{"q" => q}, socket),
  do: {:noreply, push_url_state(socket, [q: q], replace: true)}

def handle_event("filter_status", %{"status" => s}, socket),
  do: {:noreply, push_url_state(socket, status: s)}
```

`push_url_state/3`:

1. merges the changes into the current state;
2. resets `page` to its default when anything other than `page` changed;
3. drops every value equal to its default, so an unfiltered list is
   `/admin/users`, not `/admin/users?q=&status=&page=1`;
4. `push_patch`es to **the path captured from `uri` by the hook**, query
   appended — preserving the locale segment and any parent-resource ids. This is
   the defect the six hand-rolled versions share.

**History granularity.** `replace: true` is passed for continuous input (the
debounced search box) so a 20-character query leaves one history entry rather
than six; discrete actions — filter select, sort, page — push a real entry.
Every current implementation gets this wrong: Back walks the search box
backwards a few characters at a time.

For `<.pagination>` and `<.link patch=…>`: `url_state_path(socket, page: n)`.

### Dead render

`dead_render: :call` is the default. A `mount/3` that loads its data already
runs on the disconnected render, so calling the callback there preserves
exactly what the screen does today — adoption changes no behaviour and needs no
placeholder assigns. `:skip` defers the callback until the socket connects,
trading an empty first paint for one query per load instead of two; it is what
`comments` does by hand, and it is wrong for the public `ecommerce` storefront,
which must serve content to crawlers.

### The callback fires only on a real change

The `:handle_params` hook runs on every navigation in the LiveView, not only the
ones this module caused. `users.ex` patches `?action=add` to open its add-user
modal; without a guard that patch would re-run the whole user query. The
callback therefore fires only when the decoded state differs from the last one
(or has never run) — the same guard `MediaBrowser.Embed` applies before its
`send_update`.

### No `@impl` annotation

`handle_url_state/2` is declared through `@behaviour` but must **not** be
annotated `@impl`. A single `@impl` anywhere in a module makes Elixir demand it
on every other callback, and core's LiveViews annotate none of their
`mount`/`handle_event`/`handle_params`/`handle_info` — one annotation turns into
four warnings, which `mix precommit` compiles as errors.

### Unknown query keys survive

Keys the spec does not declare are carried across patches verbatim, so an open
modal's `?action=add` is not dropped the moment a filter changes.

### View mode

`view_mode` stays in `user.custom_fields`. An LV may declare it as a param, and
when the URL key is absent the stored value supplies the default — the URL
overrides, the database seeds. A full link stays full without a second source of
truth overwriting the user's personal preference.

### Debounce

300 ms becomes the standard for list search inputs and the default of
`<.search_toolbar>`; selects fire immediately. Current spread to be normalised:
200 ms (`catalogue/pdf_library`), 150 ms (`languages`), 100 ms
(`SearchableSelect`), and none at all in `entities/data_navigator` — which
patches the URL on every keystroke.

## Testing

Everything that decides a URL is a pure function over maps, so the contract is
pinned without PostgreSQL — which matters, because core's integration suite
needs a database this environment does not have. 41 tests cover default-
dropping, alias decode, cast and whitelist rejection, the integer ceiling, page
reset, unknown-key preservation, path capture and its fallbacks, rejection of a
change keyed by URL key instead of assign name, and `reload?/3` — the single
branch deciding whether a shared link, a Back press or a filter change reloads,
made public precisely so it could be tested without a router.

**Not covered, and deliberately so:** the `on_mount` → `:handle_params` hook →
host `handle_params/3` ordering. `live_isolated/3` mounts without a router,
which this module refuses by design, so exercising it needs a test router and
endpoint that core's test support does not currently have. Building that is
worth doing, but as its own piece of work rather than smuggled into this one.
Until then the ordering is verified by hand against the running Andi app over
Tidewave, together with the converted screens.

## First package — three repos

1. **core** — `UrlState`; convert `users`, `sessions`, `live_sessions`,
   `jobs/index`, `media_selector`. PR to `BeamLabEU/phoenix_kit`, then release.

   `MediaBrowser.Embed` is **not** re-based onto the shared layer. Its URL sync
   works, and rebasing it would mean bending an LiveView-level abstraction
   around a LiveComponent-level one — the browser drives navigation by sending
   `{:navigate, …}` to its parent, not by handling events on the LiveView. That
   is the same "don't refactor working code inside a fix" line drawn for the
   other modules. What it does get is the missing sentence in its moduledoc:
   `url_sync: true` makes the host LiveView un-embeddable, for the reason set
   out under Constraint.
2. **Andi** — orders and sub-orders (`handle_params` there exists but ignores
   its params). Path dep, so available immediately.
3. **`phoenix_kit_warehouse`** — 7 LVs, every one broken, all sharing the
   `ColumnManagement` macro, so one integration point covers them. Developed
   against local core via `PHOENIX_KIT_PATH=../phoenix_kit_search`; the PR
   cannot merge until core is released.

Verification of the package on the live app, plus an `ask-glm` review pass,
before the PRs. (`ask-kimi` is skipped — the account is at its rate limit.)

## Remaining work, after the first package lands

`catalogue` ×3, `ecommerce` ×2, `manufacturing` ×1, `emails/blocklist` ×1 (all
path deps, need the core bump); `staff` ×1 and the one-line
`billing/subscriptions` template fix (Hex, separate upstream PRs + version
bumps); `projects` ×3 pending its own `history.pushState` design.

## Open questions

- Whether the already-correct seven migrate to `UrlState` later, or keep their
  own code and only inherit the `alias`-based `q` convergence.
- Whether `projects` gets the JS-history mode, or a router-mounted wrapper LV
  that owns URL state and `live_render`s the embeddable inner LV.
