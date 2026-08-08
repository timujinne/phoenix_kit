# PR #678 — Locale route precedence, and the regex sanitizer replaced with a parsed allowlist

**Author:** Max Don (`mdon`)
**Merge commit:** `121d2dc6`
**Reviewed:** 2026-08-04, post-merge, against the merged state.
**Scope:** 6 files, +675 / −196 (8 commits, including three self-review fix passes).

The PR does three things, and the first two are right:

1. **Routing.** It discovers that `scope "…/:locale", locale: ~r/…/` is dead code
   — `Phoenix.Router.Scope.push/2` honours only `:path, :alias, :as, :host,
   :private, :assigns, :log, :trailing_slash` and silently discards the rest —
   deletes the regex, and reorders emission so literal-rooted surfaces (admin,
   authenticated) precede `/:locale`-rooted ones. I verified the claim against
   the real router: the reorder is correct, both new invariant tests hold, and
   nothing in the 166-route table is shadowed.
2. **Compile-time route-module references**, closing the `module_hash/0` blind
   spot where editing an existing module's `admin_routes/0` left the host router
   stale.
3. **The sanitizer**, swapped from hand-rolled regexes to `MDEx.safe_html/2`.
   The security argument is unarguable — `<img/src=x/onerror=alert(1)>` walked
   straight through the old patterns. But the swap silently changed the
   *attribute* allowlist, and that part shipped undocumented and untested.

Three findings. All fixed here. Nothing found in the routing reorder itself.

---

## BUG - MEDIUM — every locale redirect drops the query string, and one of them documents the opposite

**Where:** `lib/phoenix_kit_web/users/auth.ex` — `process_as_default_locale/1`,
`redirect_default_locale_to_clean_url/2`, `redirect_to_base_locale/2`

All three rebuild a **path**. `conn.request_path` and `conn.path_info` both stop
at the `?`, so the query never made it onto the `Location` header. The PR did not
introduce this, but it rewrote all three functions and their docs and left the
false claim standing — `redirect_to_base_locale/2`'s `@doc` says, under a
heading called **Preservation**:

```
- Query parameters preserved
- URL fragments preserved
```

with a worked example, `/phoenix_kit/es-MX/users?page=2 → /phoenix_kit/es/users?page=2`,
that has never once happened.

On this surface that is not cosmetic. `Routes.return_to_query/1` threads
`return_to` through exactly these URLs — that is the documented mechanism for
carrying a destination across login / register / magic-link / QR / OAuth. A
visitor who follows a bookmarked dialect URL to
`/<prefix>/en-US/users/log-in?return_to=/admin/users` is redirected to
`/<prefix>/en/users/log-in`, loses `return_to`, and lands on the post-login
default instead of where they were going. Same for paging state on any
canonicalised public URL.

**Fixed:** one shared `with_query_string/2` helper, applied at all three call
sites. It declines rather than raises when the query contains something
`Phoenix.Controller.redirect/2` refuses (`"\\"`, `"/\t"`, `"/%09"` — a client can
send a raw backslash in a query value, and a 500 would be strictly worse than
the truncation that ships today). The `@doc` now states what actually happens,
including that fragments *cannot* be preserved: a fragment never leaves the
browser, so the server has nothing to copy — the client re-applies its own to
whatever `Location` it follows.

Four tests in `test/phoenix_kit_web/users/auth_test.exs` (no DB — this function
is pure string work): query survives, dialect-at-end-of-path survives, no query
means no stray `?`, and the unsafe-query fallback truncates instead of raising.
The two settings-gated siblings are covered in
`test/integration/users/auth_locale_test.exs`.

## BUG - MEDIUM — the sanitizer rewrite silently narrows the attribute allowlist

**Where:** `lib/phoenix_kit/utils/html_sanitizer.ex`

The old implementation was a blacklist: it removed script/style blocks, `on*`
handlers, a fixed list of dangerous tags, and unsafe URL schemes, and **passed
every other attribute through untouched**. The module documented that contract
explicitly:

```
#   a: href title target rel
#   img: src alt title width height
#   td/th: colspan rowspan
#   all: class id
```

The rewrite deletes that comment and inherits ammonia's default set instead,
which keeps `class` on only `code`, `div`, `pre` and `span`, and drops `target`
and `id` everywhere. Verified against the real NIF, not the docs:

| Input | Merged behaviour |
|---|---|
| `<p class="text-center">Hi</p>` | `<p>Hi</p>` |
| `<img src="/a.png" class="rounded">` | `<img src="/a.png">` |
| `<a href="https://x.com" target="_blank">t</a>` | `target` gone |
| `<h2 id="section">H</h2>` | `<h2>H</h2>` |

Nothing in the PR mentions this. The new moduledoc's "Output is normalised"
section lists only cosmetic differences (quoting, `<tbody>`, `rel`), which reads
as reassurance that nothing was lost — and the section above it advertises that
"anchor … URLs are preserved" while every `id` an anchor could point at is being
deleted. `sanitize_rich_text_fields/2` is the entity rich-text path, so this
restyles stored content in every host on upgrade, silently and irreversibly at
render time.

**Fixed** by making the allowlist say what the module has always promised,
rather than inheriting a default and describing it wrongly:

- **`class` restored on every tag** via `add_generic_attributes`. It grants no
  capability that is not already granted — ammonia's defaults keep `style` on
  `div`/`span`, so arbitrary presentation was reachable regardless.
- **`target` restored on `<a>`** via `add_tag_attributes`. Safe here
  specifically because ammonia's `link_rel` default stamps
  `rel="noopener noreferrer"` onto every link it emits, so the reverse-tabnabbing
  that normally makes `target` risky cannot apply. That stamping *overwrites* an
  author-supplied `rel`, which is why `rel` itself is deliberately not added
  back — allowing it would be theatre.
- `add_*` rather than a rewritten allowlist, so an MDEx upgrade that tightens
  the defaults still reaches us.

**`id` deliberately NOT restored**, despite the old implementation passing it.
Sanitized output is spliced into a LiveView-managed DOM through `raw/1`, and
LiveView patches by element id — a stored `id` colliding with a component's is a
rendering bug an author can trigger by accident, on top of the usual
DOM-clobbering surface. In-page anchors therefore only reach ids the application
itself rendered; `href="#…"` survives untouched. `id_prefix` is the knob if
author-supplied anchors are ever wanted. The moduledoc now states this, along
with the other real losses the PR did not mention (`rel`, `<input>` — so
Markdown task-list checkboxes vanish — and `<tfoot>`).

Five tests added, including two that pin the *security* side of the additions:
`class` does not smuggle a handler back in, and `target` does not rescue a
`javascript:` href.

## NITPICK — `admin_request?/1` compares encoded path segments

**Where:** `lib/phoenix_kit_web/users/auth.ex`

The PR's headline fix here is right — `String.contains?(request_path, "/admin")`
classified `/shop/product/admin-tools` as an admin request, and `"admin" in
conn.path_info` fixes that. But it compares against the **raw** segments, and
`strip_locale_segment/2` — added in the same commit range — carries a careful
comment explaining exactly why that is wrong: Phoenix matches routes against a
decoded copy of the path and leaves `conn.path_info` encoded. So
`/<prefix>/en/%61dmin/users` reaches the admin route while `admin_request?/1`
reports "not admin" and hands it to the default-locale canonicaliser, which
redirects a URL that is already where it belongs.

Low impact — it needs `default_language_no_prefix` ON and a deliberately encoded
URL, and the result is one wasted redirect, not a wrong page. Fixed anyway
(`Enum.any?(conn.path_info, &(URI.decode(&1) == "admin"))`), because the
reasoning was already written down two functions away. `URI.decode/1` does not
raise on malformed input (`"%zz"` round-trips), so no guard is needed.

---

## Verified, not changed

- **The route reorder is correct.** Dumped all 166 routes from the real router
  in declaration order. Admin (34–123) and authenticated (124–131) precede every
  `/:locale`-rooted block; the localized auth endpoints (132–143) and the public
  surface (144–165) follow. No literal route resolves to anything but itself,
  and the `/:locale/admin/…` shapes cannot swallow public routes (they need
  `admin` as their second segment, and no public route has one).
- **`status: 307` / `status: 301` were dead.** Confirmed in
  `deps/phoenix/lib/phoenix/controller.ex:496`: `redirect/2` sends
  `conn.status || 302` and never reads `:status`. The PR's fix (`put_status/2`
  first) and its decision to leave the other two as the 302 they always were are
  both right.
- **The dialyzer ignore entry is real.** `MDEx.safe_html/2`'s spec declares
  `escape: [atom()]` while the implementation reads it as a keyword list
  (`opt(options, [:escape, :content], true)`, `deps/mdex/lib/mdex.ex:1240`), and
  MDEx's own doctests pass the keyword form. The spec contradicts its code.
- **`escape: [content: false]` is required, not cosmetic** — with content
  escaping on, the sanitizer returns `&lt;p&gt;Hello&lt;/p&gt;`.
- **The shop-admin dedup** (`PhoenixKitEcommerce.Web.Routes in
  all_route_modules()`) is consistent with the fallback it guards:
  `all_route_modules/0` returning `[]` is exactly the discovery-failed case the
  hardcoded call exists for.

## Not verified

The four tests added to `test/integration/users/auth_locale_test.exs` are
`:integration`-tagged and need PostgreSQL, which this environment does not have.
Their conn-construction assumptions were checked directly against
`Plug.Test.conn/4` and `PhoenixKit.Config.get_url_prefix/0` (path_info stays
percent-encoded; prefix resolves to `/phoenix_kit`), and the file compiles, but
they have not been executed. The eight no-DB tests in `auth_test.exs` and
`html_sanitizer_test.exs` all pass.

## Gate

`mix precommit` — compile `--warnings-as-errors`, `deps.unlock --check-unused`,
`format --check-formatted`, `credo --strict`, `dialyzer`, `test.js`.
