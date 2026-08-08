# Core-owned redirect destinations

**Date:** 2026-08-06
**Repo:** phoenix_kit (core)
**Status:** design, approved for planning

## Problem

Core sends users "home" by calling `Routes.path("/")`. That function prefixes
the active locale, so the redirect arrives as `/en`. The route that would serve
it belongs to the host application, and core has no way to know whether the host
declared one. When it hasn't, every such redirect 404s.

Measured in andi before the host-side workaround: `/` answered 200 while `/en`,
`/et` and `/ru` all returned 404.

This is not one bug in one flow. `Routes.path("/")` is hardcoded at **nine**
call sites across five files:

| Site | Anonymous possible? |
|---|---|
| `maintenance_page_live.ex:54,65,87` (3) | yes |
| `oauth.ex:260` | yes — the root session can expire mid-flow |
| `oauth.ex:354` | no |
| `session.ex:110` (logout → account switch) | no |
| `session.ex:132` (multi-session gate refusal) | yes |
| `session.ex:140` | no |
| `qr_login_confirm.ex:33` | no |

A **tenth** site behaves the same way with a literal string: `auth.ex:683`, the
admin-area guard, which ejects a non-admin to `"/"` with the flash "You do not
have permission to access this section". An **eleventh**, `auth.ex:321`, is full
logout, also hardcoding `"/"` — so the two logout branches send users to
differently-shaped URLs for the same logical destination.

Scope of exposure: any PhoenixKit application with the Languages module enabled.
With `default_language_no_prefix` off — core's default — the prefix is applied to
*every* locale including the default, so all of them break. With it on, only the
non-default locales break. A single-language install never notices.

The requirement is not documented anywhere a host author would look: not in the
installer, not in `doctor`, only in a CHANGELOG entry for 1.7.150 which states
"the parent app declares a `/:locale` landing".

## What core already owns

Core's own routing is locale-complete — 272 admin paths and 272 locale-prefixed
twins, verified by enumerating the router. `/dashboard`, `/admin` and
`/users/log-in` each have a `/:locale` twin. The single asymmetry in the whole
system is `/`, which belongs to the host and which core cannot declare: the home
*page* is host-owned, and claiming the path would overwrite it.

`/users/log-in` answers 200 in every locale, so redirecting there preserves the
visitor's language instead of switching it, and it exists in every install.

Core also already has the resolver. `Routes.post_auth_path/1` takes ordered
candidates and returns the first that is `local_path?/1` and not `auth_page?/1`,
falling back to the `after_login_path` setting. Its open-redirect guard rejects
protocol-relative URLs, absolute URLs and control-character tricks. **None of the
eleven sites calls it**, it is role-agnostic, and its final fallback is `"/"` —
the unowned path.

## Design

### One resolver

`Routes.safe_destination/2` replaces every hardcoded destination. No call site
decides where to send anyone.

Authenticated:

1. explicit `return_to`, when local and not an auth page
2. `/admin` when `Scope.can_access_admin_area?/1`
3. `/dashboard` otherwise
4. the `after_login_path` setting

Anonymous:

1. the configured site main page, when set and still resolvable
2. `/users/log-in`

Every link is core-owned and locale-complete. **The chain never terminates at
`/`.** That is the invariant the work exists to establish.

The `/admin` versus `/dashboard` fork uses core's own vocabulary and needs no
knowledge of a host's domain. Verified against live accounts: Owner and Admin
reach `/admin`; a Client also passes `can_access_admin_area?` because they hold
`client_portal`, and the host redirects them onward from `/admin` to their own
area; a plain `User` fails the predicate and gets no usable admin page, which is
why the `/dashboard` branch is required rather than decorative.

`auth.ex:683` is the one exception: it must skip step 2, or rejecting a user from
`/admin` would send them back to `/admin`.

### Candidate validation

A candidate is used only when it is (a) a local path, (b) not an auth page, and
(c) **actually routable**. Every call site holds a `conn` or `socket`, and the
router module is available on both (`conn.private.phoenix_router`), so
`Phoenix.Router.route_info/4` can confirm a route exists before anyone is sent
there.

This is what lets `/` stay a legitimate candidate — it is simply not selected
where it does not exist — and it is what makes the configurable main page safe:
if the chosen page is renamed, the stored path stops resolving and the chain
falls through instead of serving a broken link.

### Configurable main page

A new setting, `main_page_path`, in core's **general site settings** — beside
Project Title and Site Address. Not in the Sitemap section.

It is a validated free-text path, following `after_login_path` exactly: a field
on the `SettingsForm` embedded schema, a `get_defaults/0` entry, and a
`validate_local_path` call reusing the existing open-redirect guard.

A page-picker sourced from `sitemap_sources` was considered and **rejected**.
That registry is the only cross-module list of public URLs, and its per-locale
grouping by `canonical_path` is the right shape — but it exposes no stable
identifier, only path strings recomputed from live data, so a renamed page
silently breaks the reference; `collect/1` is uncached and hits the database per
source; and the Sitemap module is *disabled* in the very application this work
is for, which would leave the picker empty exactly where it is needed. A typed
path plus routability validation gives the same safety with none of that.

### Locale canonicalisation

`Routes.path("/", locale: L)` is the authority on whether a prefixed root is a
distinct URL. When core would emit `/` for a locale — the default language when
configured prefixless, or any locale with the Languages module disabled — the
prefixed form is a duplicate of `/` and must redirect to it rather than serve.

Locale comparison is by **base code on both sides**, via
`DialectMapper.extract_base/1`. This is load-bearing: with the Languages module
disabled, `enabled_locale_codes/0` falls back to the dialect `"en-US"` while
`Routes.path/1` emits the base `"en"`, and a raw string comparison rejects core's
own redirect. Normalising also makes `/en-GB` and `/EN` behave like every other
PhoenixKit surface instead of 404ing.

### Host affordance

Core should stop leaving each host to rediscover the "declare the wildcard last,
then validate the segment" invariant. Two options, to be decided during planning:

- a macro that emits the validated `/:locale` → host-home route with the correct
  ordering held inside core; the host passes its `{Controller, :action}`
- `config :phoenix_kit, home_path: {Mod, :fun}`, resolved at runtime by the
  redirect sites

The second is preferred: it removes the assumption rather than packaging it.

Independently of the resolver, `doctor` should warn when a host has more than one
language enabled and no locale-prefixed root route.

## Testing

None of the eleven sites has any test coverage today, which is why this survived
to production.

1. **Resolver unit tests** — a table of (who, what is configured) → destination.
   Anonymous with and without a main page; a main page pointing at a
   non-resolving path; Owner, Admin, Client, plain User; an external URL and a
   control-character path, asserting the open-redirect guard holds.
2. **The invariant** — for every one of the eleven sites, under every input,
   the result is never `"/"` and never a path outside core. This is the point of
   the work and must be asserted, not assumed.
3. **Locale matrix** — each enabled locale × `default_language_no_prefix` on/off
   × Languages module on/off, asserting serve versus canonical-redirect versus
   404, and that the emitted path always resolves in the router.
4. **Integration** — logout with an account switch, and a non-admin reaching
   `/admin`, both walked through their full redirect chains.

## Out of scope

- The role→path mapping table considered earlier. The host does its own
  role-specific routing from the core-owned landing page, so core needs no such
  table.
- Removing `page_action`/`:action` from `LayoutWrapper`, now unused.
- The fail-open audit wrapper around `Activity.log/1`.

## Follow-up: one universal dashboard, and why it closes the class

> **⚠️ Superseded by what shipped in #685 — read this section as history, not as
> a description of the code.** The idea below is right; the page it picked is
> not the page that landed. Everything here names `/dashboard` as the guaranteed
> landing. During implementation the landing became **`/admin`**
> (`PhoenixKitWeb.Live.Dashboard`), exempted from the admin-area and per-view
> permission checks by `PhoenixKitWeb.Users.Auth.landing_view?/1`, because
> `/admin` is declared unconditionally while `/dashboard` is still compiled out
> by `user_dashboard_enabled: false` — the conditional compilation this section
> proposed removing was left in place. Consequently, in the shipped code:
>
> - `home_or_core_landing(nil, _opts)` returns `path("/admin")`, not
>   `path("/dashboard")`;
> - `/dashboard` is an ordinary probed **candidate**, not a terminal;
> - the terminal probe was not deleted — `terminal/2` keeps it as a diagnostic
>   that names a misconfigured install in the log (`unreachable_terminal/3`);
> - the gating half of this section DID ship, on `/admin`:
>   `PhoenixKitWeb.Live.Dashboard.Overview` derives every card gate from
>   `Auth.can_access_admin_view?/2` and gates the statistics on
>   `Scope.holds_all_enabled_permissions?/1`, exactly as argued below.
>
> `PhoenixKit.Utils.Routes.safe_destination/2`'s moduledoc is the current
> source of truth for the chain.


Everything above probes destinations because core cannot guarantee any of them exists.
Remove that premise and most of the machinery becomes unnecessary.

**The decision.** Core owns exactly two landings that ALWAYS exist:

- `/dashboard` — every authenticated user, whoever they are. Greets them in their own
  language; shows the current dashboard content additionally when the visitor holds
  admin or owner rights.
- `/users/log-in` — every anonymous visitor. Already unconditional and locale-complete.

**Two facts that make this smaller than it sounds**, both verified in 1.7.232:

1. `/dashboard` is *already* permission-free — its `live_session` gates on
   `:phoenix_kit_ensure_authenticated_scope` alone (`integration.ex:760-764`), no
   permission key involved. The "unrevocable right for every registered user" the idea
   calls for is already the behaviour.
2. The only thing that removes it is **conditional compilation**:
   `if unquote(PhoenixKit.Config.user_dashboard_enabled?())` wraps both the route block
   (`integration.ex:597`) and the `live_session` (`:760`). So the setting decides whether
   the ROUTE exists, when it should only decide what the PAGE shows.

**What it lets us delete.** Once `/dashboard` is guaranteed:

- the terminal needs no probe and cannot loop — it is a path core declares and permits,
  so the `no_reachable_destination` log branch becomes unreachable rather than a
  documented degenerate case;
- `home_or_core_landing(nil, _opts)` can return `path("/dashboard")` instead of `"/"`.
  That closes the context-less callers (confirmation, referral gate, confirmation
  instructions) **structurally** — a caller that forgets to thread a context still gets a
  safe answer, instead of synthesizing a bare `"/"`. Threading the context stays worth
  doing, but stops being load-bearing;
- the invariant stops being "every candidate was probed" and becomes "the chain ends at a
  path core declares unconditionally" — provable by construction, which is what the
  design asked for and never achieved.

**The one real cost.** A host that set `user_dashboard_enabled: false` gets a route back
that it had switched off. That has to be deliberate: the setting keeps its name and
starts meaning "show the dashboard's modules", not "remove the page". Worth an entry in
the release notes rather than a silent change.

### What the page shows today, and to whom

`lib/phoenix_kit_web/live/dashboard.html.heex`, 373 lines, contains **zero permission
checks** — measured, not assumed (`grep -cE 'can_access|has_module_access|holds_all|owner\?|Scope\.'`
returns 0). Every card and both statistics sections render for anyone who reaches the
page. That is survivable only while the page is de-facto admin-only; the moment it
becomes the guaranteed landing for *every* authenticated user, it is an
information-disclosure surface. **Gating is therefore a precondition of the idea, not a
polish item.**

| Card / section | Target | Line |
|---|---|---|
| Users | `/admin/users` | 26 |
| Roles | `/admin/users/roles` | 41 |
| Sessions | `/admin/users/sessions` | 56 |
| Live Activity | `/admin/users/live_sessions` | 71 |
| Add User | `/admin/users/new` | 86 |
| Email | `/admin/emails` | — |
| Platform Statistics (System Owners, Total Users) | — | 126 |
| Active Sessions | — | 170 |
| System Information | — | 335 |

### The gating rule: derive it, don't restate it

A card is visible **iff the visitor can open what it links to**. Core already owns that
answer as a public function — `PhoenixKitWeb.Users.Auth.permission_key_for_admin_view/1`
(`auth.ex:1556`), the same lookup `enforce_admin_view_permission/2` uses to admit or
deny the destination itself:

```elixir
key = Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Users.Users)
Scope.has_module_access?(scope, key)
```

Verified live against the four real role shapes in this install: all five user-management
cards resolve to the single key `"users"`, held by Owner and Admin, and **not** by the
Client (whose scope is `["client_portal", "notifications"]`) nor by a plain User (empty).
So the rule reproduces the intended visibility exactly, with no second list to maintain.

This matters more than it looks. A hand-written table of card→role would drift from the
gate the same way the role badge and the account list drifted this week; deriving from
`permission_key_for_admin_view/1` makes drift impossible by construction — if the
destination's gate changes, the card follows automatically.

Two sections have no destination LiveView and need an explicit rule instead: **Platform
Statistics** and **System Information** are operator data, so Admin/Owner only —
`Scope.holds_all_enabled_permissions?/1` rather than a role name, matching the
role-agnostic policy the unmapped-view fallback already sets (`auth.ex`, "no role is
special for feature access").

### The welcome half

Above the gated cards, visible to everyone, in the visitor's own language. A plain
employee and a client then see a page that greets them and nothing else — which is
precisely what makes the page safe to hand to every authenticated user, and what makes it
a legitimate terminal for the resolver.

⚠️ Its strings must be extracted at compile time. Runtime `Gettext.dgettext(Backend, …)`
escapes extraction and silently renders English — the defect already found and fixed
across the fork modules. Use `use Gettext` + the macro form.

### Consequences for the work already merged on this branch

- `home_or_core_landing(nil, _opts)` returns `path("/dashboard")` instead of the bare
  `"/"` (`routes.ex:132`) — this is the structural close of GLM's Finding 1. The three
  context-less callers (`confirmation.ex:25`, `referral_gate.ex:39`,
  `confirmation_instructions.ex:120`) stop being a live 404 on the default
  email-confirmation flow even if nobody threads a context.
- Threading the context into those three callers stays worth doing — it yields a better
  destination, not merely a safe one — but drops from blocking to ordinary.
- `terminal/3` loses its probe: `/dashboard` is declared unconditionally and permitted
  unconditionally, so `Enum.find(&routable?/2)` has a guaranteed answer.
- `no_reachable_destination/2` becomes unreachable on any router that mounts
  `phoenix_kit_routes()`. Keep it as a fail-closed guard, drop it from the documented
  behaviour.
- The invariant test stops needing to prove a negative by regex — GLM's Finding 2. It
  becomes "the chain terminates at `/dashboard`", assertable behaviourally against a
  router that declares no `/`.

### Order of work

Gating must land **with** the route becoming unconditional, not after it. Making
`/dashboard` universal while the template still shows System Information to everyone
would ship the disclosure. One change, two halves.
