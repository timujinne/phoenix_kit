# PhoenixKit Integration Guide

**For developers using PhoenixKit as a Hex dependency in their Phoenix application.**

This guide is designed to help both developers and AI assistants (Claude, Cursor, Copilot, Tidewave MCP, etc.) understand how to integrate and use PhoenixKit effectively.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Configuration Reference](#configuration-reference)
4. [Authentication Integration](#authentication-integration)
5. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Verify database is prepared
mix ecto.migrations

# 2. Install PhoenixKit (adds dep, fetches, configures, generates migrations)
mix igniter.install phoenix_kit

# 3. Create database if needed
mix ecto.create

# 4. Run migrations
mix ecto.migrate

# 5. Start your server
mix phx.server
# Visit /phoenix_kit/admin
```

> Requires the `igniter_new` archive — install once with `mix archive.install hex igniter_new`. If you'd rather not, see the [two-step fallback](#step-2-install) below.

---

## Installation

### Step 1: Run the Installer

```bash
mix igniter.install phoenix_kit
```

The installer will:
- Add `{:phoenix_kit, "~> 1.7"}` to your `mix.exs` and fetch deps
- Detect your Repo automatically (or use `--repo` to specify)
- Add configuration to `config/config.exs`
- Generate migrations
- Set up mailer integration

> Requires the `igniter_new` archive — `mix archive.install hex igniter_new` if you don't already have it.

### Step 2: Install (two-step fallback)

If you can't or don't want to use the `igniter_new` archive, add the deps manually and run the installer directly. Declare **both** — PhoenixKit marks `:igniter` `optional: true`, and Mix does not resolve optional deps transitively, so a project that never declared igniter itself won't get it from PhoenixKit:

```elixir
# mix.exs
defp deps do
  [
    {:phoenix_kit, "~> 1.7"},
    {:igniter, "~> 0.7", only: [:dev, :test]}
  ]
end
```

```bash
mix deps.get
mix phoenix_kit.install
```

**Why optional?** A stock `mix phx.new` app declares `{:igniter, "~> 0.6", only: [:dev, :test]}`. A non-optional dep in PhoenixKit resolves for all environments and Mix refuses to converge the two (`the :only option for dependency igniter must include at least the environments of its parent`), which broke `mix igniter.install phoenix_kit` on every freshly generated project.

**Dev-only.** `only: [:dev, :test]` is deliberate — igniter is build-time tooling that never reaches production. Every reference to it in PhoenixKit is inside the `mix phoenix_kit.*` tasks and their installer helpers; nothing in the supervision tree or request path touches it, and Mix tasks aren't part of a release.

If `:igniter` is missing, `mix phoenix_kit.install` and `mix phoenix_kit.update` print setup instructions rather than running. Everything that doesn't patch code — `mix phoenix_kit.status`, `mix phoenix_kit.gen.migration`, `mix phoenix_kit.assets.rebuild` — is unaffected.

### Step 3: Configure

The installer adds this to your config. Customize as needed:

```elixir
# config/config.exs
config :phoenix_kit,
  parent_app_name: :my_app,
  parent_module: MyApp,
  url_prefix: "/phoenix_kit",
  repo: MyApp.Repo,
  mailer: MyApp.Mailer,
  layouts_module: MyApp.Layouts,
  phoenix_version_strategy: :modern
```

### Step 4: Add Routes

The installer adds something like this to your router.ex. Customize as needed:

```elixir
# lib/my_app_web/router.ex
import PhoenixKitWeb.Integration

scope "/" do
  pipe_through :browser
  phoenix_kit_routes()
end
```

### Step 5: Run Migrations

```bash
mix ecto.migrate
```

---

## Configuration Reference

### Core Settings

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `repo` | module | auto-detected | Your Ecto Repo module |
| `mailer` | module | nil | Your Swoosh Mailer module |
| `url_prefix` | string | "/phoenix_kit" | URL prefix for all routes |
| `admin_path` | string | "/admin" | Top-level segment of the admin area, inside `url_prefix` |
| `layout` | tuple | PhoenixKit default | `{LayoutModule, :template}` |
| `root_layout` | tuple | PhoenixKit default | Root layout for pages |

### Renaming the admin area

`url_prefix` names the mount; `admin_path` names the admin segment inside it.
They are independent:

```elixir
config :phoenix_kit,
  url_prefix: "/phoenix_kit",
  admin_path: "/backoffice"

# admin area now at /phoenix_kit/backoffice/users
# everything else is untouched: /phoenix_kit/users/log-in, /phoenix_kit/profile/settings
```

Useful when a signed-in end user would otherwise see a URL that reads as
somebody else's admin panel. The admin index admits **every** authenticated
visitor by design — one holding no permissions is greeted and shown nothing
else — so the URL is the only part that looks administrative.

- **Compile-time.** Put it in `config/config.exs`, never `runtime.exs`. The
  host router folds it into `__mix_recompile__?/0`, so changing it re-expands
  your router rather than leaving it serving the old segment.
- **Validated.** Exactly one lowercase path segment, and not one PhoenixKit
  already declares (`users`, `profile`, `dashboard`, `api`, …). A bad value
  raises at compile time instead of producing a router that 404s.
- **Nothing else changes.** The default (`"/admin"`) produces a byte-identical
  route table, and every PhoenixKit module package follows the rename with no
  changes of its own.

In **your own code**, keep writing `/admin` — `Routes.path("/admin/users")`
and `<.pk_link navigate="/admin/users">` apply the configured segment for you.
Never hardcode the renamed value.

### Authentication Settings

```elixir
config :phoenix_kit, :password_requirements,
  min_length: 8,
  max_length: 72,
  require_uppercase: false,
  require_lowercase: false,
  require_digit: false,
  require_special: false
```

### Rate Limiting

```elixir
# Hammer 7.x uses ETS backend via PhoenixKit.Users.RateLimiter.Backend
# No additional :hammer config needed

config :phoenix_kit, PhoenixKit.Users.RateLimiter,
  login_limit: 5,                      # Max login attempts per window
  login_window_ms: 60_000,             # 1 minute window
  magic_link_limit: 3,                 # Max magic link requests per window
  magic_link_window_ms: 300_000,       # 5 minute window
  password_reset_limit: 3,             # Max password reset requests per window
  password_reset_window_ms: 300_000,   # 5 minute window
  registration_limit: 3,               # Max registration attempts per window
  registration_window_ms: 3_600_000,   # 1 hour window
  registration_ip_limit: 10,           # Max registrations per IP per window
  registration_ip_window_ms: 3_600_000 # 1 hour window
```

---

## Authentication Integration

### Access Current User

```elixir
# In a LiveView
def mount(_params, _session, socket) do
  current_user = socket.assigns[:current_user]
  {:ok, socket}
end

# In a Controller
def index(conn, _params) do
  current_user = conn.assigns[:current_user]
  render(conn, :index)
end
```

### Require Authentication

```elixir
# In your router
import PhoenixKitWeb.Users.Auth

scope "/", MyAppWeb do
  pipe_through [:browser, :require_authenticated_user]

  live "/dashboard", DashboardLive
end
```

### Check User Roles

```elixir
# Check if user has a role
PhoenixKit.Users.Roles.user_has_role?(user, "Admin")
PhoenixKit.Users.Roles.user_has_role?(user, "Owner")

# Get user's roles
roles = PhoenixKit.Users.Roles.get_user_roles(user)

# Check in templates
<%= if PhoenixKit.Users.Roles.user_has_role?(@current_user, "Admin") do %>
  <.link navigate="/admin">Admin Panel</.link>
<% end %>
```

### Check Module-Level Permissions

PhoenixKit V53+ includes granular permissions that control which admin sections each role can access.

```elixir
# In a LiveView, use the scope from assigns
scope = socket.assigns.phoenix_kit_current_scope

# Check single permission
Scope.has_module_access?(scope, "billing")        # true/false

# Check multiple permissions
Scope.has_any_module_access?(scope, ["billing", "shop"])  # any granted?
Scope.has_all_module_access?(scope, ["billing", "shop"])  # all granted?

# Check system role (Owner or Admin, not custom roles)
Scope.system_role?(scope)

# Get all granted keys
Scope.accessible_modules(scope)  # MapSet of granted permission keys
```

**Route enforcement**: PhoenixKit's `phoenix_kit_ensure_admin` and `phoenix_kit_ensure_module_access` on_mount hooks automatically enforce permissions on admin routes. Sidebar navigation is gated per-user.

### Edit link on public pages

When an admin is viewing a public page — a host LiveView, or a module's own
public controller/LiveView — you can offer them a one-click "Edit" link into
that page's admin counterpart.

Declare the edit target from `handle_params`/`mount` (or a controller action)
with `PhoenixKitWeb.AdminEditHelper.assign_admin_edit/3`:

```elixir
def handle_params(%{"slug" => slug}, _uri, socket) do
  post = Blog.get_post_by_slug!(slug)

  socket =
    PhoenixKitWeb.AdminEditHelper.assign_admin_edit(socket, "/admin/posts/#{post.id}/edit")

  {:noreply, assign(socket, :post, post)}
end
```

The third argument accepts a plain string label (used as-is) or a keyword
list — `label:` (default: gettext "Edit") and `permission:` (a module
permission key, e.g. `"publishing"`, checked with
`Scope.has_module_access?/2`):

```elixir
PhoenixKitWeb.AdminEditHelper.assign_admin_edit(
  socket,
  "/admin/publishing/posts/#{post.id}/edit",
  label: "Edit Post",
  permission: "publishing"
)
```

The link is only assigned when the current scope can access the admin area
at all and — when `permission:` is given — holds that specific module's
access. Otherwise nothing is assigned, so the render side never sees a URL
it shouldn't.

Then drop the renderer into your public layout once:

```heex
<.admin_edit_link url={assigns[:admin_edit_url]} label={assigns[:admin_edit_label]} />
```

`PhoenixKitWeb.Components.Core.AdminEditLink.admin_edit_link/1` renders
nothing when there is no URL, so this line is safe to leave in every public
layout unconditionally. Pass `variant={:menu_item}` to render it as a
daisyUI `menu` `<li>` instead of a standalone button, for dropping into an
existing dropdown menu.

### User Registration

```elixir
# Register a new user
{:ok, user} = PhoenixKit.Users.Auth.register_user(%{
  email: "user@example.com",
  password: "securepassword123"
})

# First user automatically becomes Owner
```

---

## Troubleshooting

### "Repo not configured"

```elixir
# Ensure config is set
config :phoenix_kit, repo: MyApp.Repo
```

### "Routes not found"

```elixir
# Ensure you imported and called the macro
import PhoenixKitWeb.Integration
phoenix_kit_routes()
```

### "Mailer not sending emails"

```elixir
# Check your mailer is configured
config :my_app, MyApp.Mailer,
  adapter: Swoosh.Adapters.SMTP,
  # ... your SMTP settings

# And PhoenixKit knows about it
config :phoenix_kit, mailer: MyApp.Mailer
```

### "Rate limiting not working"

PhoenixKit uses Hammer 7.x with ETS backend via `PhoenixKit.Users.RateLimiter.Backend`. No additional Hammer configuration is required. If you need to adjust rate limits:

```elixir
config :phoenix_kit, PhoenixKit.Users.RateLimiter,
  login_limit: 5,
  login_window_ms: 60_000
```

### `mix phoenix_kit.install` / `mix phoenix_kit.update` needs `:igniter`

Both tasks patch your code, so both require igniter — which PhoenixKit declares
`optional: true` and therefore does **not** hand down transitively. If it's
missing, the task prints setup instructions instead of running. Add it and
re-run:

```elixir
{:igniter, "~> 0.7", only: [:dev, :test]}
```

`mix deps.get` is enough — PhoenixKit tracks whether igniter was available when
it last compiled and recompiles itself when that changes, so the tasks appear
without a manual `mix deps.compile phoenix_kit --force`.

This bites most often on upgrade: a project that never declared igniter was
getting it transitively from an older PhoenixKit, and the switch to `optional:
true` drops it.

### `mix igniter.install` crashes with `Igniter.CopiedTasks is not available`

Not a PhoenixKit failure. When your `mix.exs` has no `{:igniter, ...}` line, the
`igniter_new` archive temporarily injects one, shells out to `mix deps.get`,
then removes it on exit. If that `deps.get` fails, the archive's cleanup handler
crashes on top of the original error because igniter was never loaded — burying
the real message. Read the `mix deps.get failed with exit code ...` output above
that stack trace, and check `mix.exs` for a stray `{:igniter, "~> 0.6", only:
[:dev, :test]}` line the crashed cleanup left behind.

Declaring igniter permanently (see above) avoids the inject/cleanup dance
entirely — `igniter_new` skips it when the dep is already present.

---

## Further Reading

- **[Custom Admin Pages](custom-admin-pages.md)** - Add pages to the admin sidebar
- **[Admin Dashboard Reference](dashboard/ADMIN_README.md)** - Admin navigation and tabs system
- **[Dashboard Components](dashboard/README.md)** - Tabs, subtabs, badges, and more

---

## For AI Assistants

When helping a developer with PhoenixKit:

1. **PhoenixKit is a Hex dependency** - Code lives in `deps/phoenix_kit/`
2. **Don't modify PhoenixKit files** - Create code in the user's app that calls PhoenixKit APIs
3. **Entity names are snake_case** - e.g., `"contact_form"`, not `"Contact Form"`
4. **Field keys are snake_case** - e.g., `"full_name"`, not `"Full Name"`
5. **First user is Owner** - First registered user gets the Owner role automatically
6. **Routes are prefixed** - Default is `/phoenix_kit/`, configurable via `url_prefix`; the admin segment is separately configurable via `admin_path`. Write `/admin` in code either way and let `Routes.path/1` apply both
7. **Permissions are cached in Scope** - Use `Scope.has_module_access?/2` not raw DB queries
8. **Owner bypasses all permission checks** - No DB rows needed for Owner access
9. **Entities use `created_by_uuid`** - The field is `created_by_uuid`, not `created_by`
10. **Always use `entity.uuid`** - Never use `entity.id` for entity operations

---

**Last Updated**: 2026-03-02
