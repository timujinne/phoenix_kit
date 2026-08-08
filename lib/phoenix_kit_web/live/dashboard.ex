defmodule PhoenixKitWeb.Live.Dashboard do
  @moduledoc """
  The `/admin` landing page.

  It is built to be the page ANY authenticated visitor can safely be sent to,
  whatever their permissions. Two halves:

    * a **welcome block**, rendered for everyone, greeting the visitor by name;
    * the **operator overview** (`PhoenixKitWeb.Components.Core.DashboardOverview`),
      every block of which is permission-gated by
      `PhoenixKitWeb.Live.Dashboard.Overview`.

  A visitor holding no permissions sees the welcome block and nothing else —
  no statistics, no System Information, no cards, and (because the overview
  decides before it queries) not one operator query or PubSub subscription on
  their behalf. That is what makes the page safe as a universal landing.

  Reaching it is not the same as being allowed to see all of it. The route sits
  in the ordinary admin `live_session`, alongside every other `/admin/*` page,
  so admin navigation to and from it stays a live patch rather than a full page
  reload. What admits a permission-less visitor is the GATE:
  `:phoenix_kit_ensure_admin` recognises this view via
  `PhoenixKitWeb.Users.Auth.landing_view?/1` and skips the admin-area and
  per-view permission checks for it alone — authentication, the account gate
  and the locale hook still run. The overview's own gates are what keep the
  operator blocks away from whoever gets in.

  Because nobody is ever evicted from this page, it has to survive a permission
  change in place: `PhoenixKitWeb.Users.Auth`'s scope-refresh hook skips its
  eviction for the landing view and instead calls
  `phoenix_kit_scope_changed/1`, which re-runs
  `PhoenixKitWeb.Live.Dashboard.Overview.assign_scope_gates/1`. A demoted
  operator watches the cards and statistics disappear (and the subscriptions
  behind them close) without leaving the page or reloading it.

  `/dashboard` is a SEPARATE page (`PhoenixKitWeb.Live.Dashboard.Index`),
  deprecated since 2026-07-27 and sharing nothing with this one.
  """
  use PhoenixKitWeb, :live_view
  use Gettext, backend: PhoenixKitWeb.Gettext
  use PhoenixKitWeb.Live.Dashboard.Overview

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes
  alias PhoenixKit.Utils.Values
  alias PhoenixKitWeb.Live.Dashboard.Overview

  @impl true
  def mount(_params, session, socket) do
    socket =
      socket
      |> assign(:project_title, Settings.get_project_title())
      |> assign(:page_title, "Dashboard")
      # Every scope-derived assign on this page — `:can_access_admin_area?`
      # included — comes from `Overview.assign_scope_gates/1`, and from nowhere
      # else. That is what lets a mid-session permission change recompute all of
      # them at once: the scope-refresh hook calls the same function through the
      # `phoenix_kit_scope_changed/1` callback `use Overview` injects.
      |> Overview.assign_overview(session, Routes.path("/admin"))

    {:ok, socket}
  end

  attr :scope, :any,
    required: true,
    doc: "the visitor's `PhoenixKit.Users.Auth.Scope`, or `nil`"

  @doc """
  The welcome half of `/admin` — the part with no permission gate at all, and
  therefore the whole page for a visitor holding nothing.

  Deliberately an `<h2>`, not an `<h1>`: the page's one header is the
  `LayoutWrapper` breadcrumb, and this sits at the same level as the operator
  overview's own section headings.

  The greeting reuses the EXISTING `"Welcome back"` msgid (it is
  `lib/phoenix_kit_web/users/login.html.heex`'s), so it arrives already
  translated in every shipped locale. The name is appended in markup rather
  than interpolated into a new `"Welcome back, %{name}"` msgid, which would
  ship untranslated everywhere. It is a function component rather than mount
  assigns so that `gettext` runs at RENDER time: a locale switch that only
  patches params (`handle_params`, after mount) still reaches it.
  """
  def welcome_block(assigns) do
    name = welcome_name(assigns.scope)

    assigns =
      assigns
      |> assign(:welcome_name, name)
      |> assign(:welcome_email, welcome_email(assigns.scope, name))

    ~H"""
    <div class="card bg-base-100 shadow-sm">
      <div class="card-body">
        <h2 class="card-title text-2xl">
          {gettext("Welcome back")}<span :if={@welcome_name}>, {@welcome_name}</span>
        </h2>
        <p :if={@welcome_email} class="text-sm text-base-content/60">{@welcome_email}</p>
      </div>
    </div>
    """
  end

  # Who to greet. `Scope.user_full_name/1` is `nil` for anyone who never filled
  # in a name — most plain users — and `User.full_name/1` can still hand back a
  # blank string (an organization row whose `organization_name` was cleared, or
  # a first name of `" "`), hence `presence/1` rather than a `nil` test.
  #
  # The fallback is the email: every account has one and it is the identifier a
  # brand-new user recognises. A scope with no user yields `nil`, and the
  # greeting then renders without a name rather than with a dangling comma.
  defp welcome_name(scope) do
    Values.presence(Scope.user_full_name(scope)) || Values.presence(Scope.user_email(scope))
  end

  # The email is the page's only statement of WHICH account the visitor is
  # signed in as — core ships a multi-account switcher, so that is a real
  # question. Suppressed when the greeting already fell back to the email, so
  # it is never printed twice.
  defp welcome_email(scope, welcome_name) do
    case Values.presence(Scope.user_email(scope)) do
      ^welcome_name -> nil
      email -> email
    end
  end
end
