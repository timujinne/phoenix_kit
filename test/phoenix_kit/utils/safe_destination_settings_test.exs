defmodule PhoenixKit.Utils.SafeDestinationSettingsTest do
  @moduledoc """
  The two candidate slots that read a **setting** — `main_page_path` and
  `after_login_path` — exercised for real.

  `safe_destination_test.exs` cannot reach them. With no database,
  `test_helper.exs` puts `:update_mode` on, which short-circuits every
  `PhoenixKit.Settings` read to `nil`; the settings cache is not started in the
  suite either, so even a cached read falls through to the same `nil`. Every
  assertion over there therefore runs against "no settings configured", and a
  claim about what happens when one IS configured would be vacuous.

  So this file starts the settings cache and primes it. `get_setting_cached/2`
  consults the cache BEFORE the update-mode short-circuit, so a primed key is
  read exactly as it would be from a live database — no PostgreSQL involved.

  `async: false` and a cache torn down per test: the cache is a globally named
  process, and a primed `main_page_path` visible to a concurrently running test
  would change that test's answer.
  """
  use ExUnit.Case, async: false

  # `EmptyRouter` cannot match core's own landing, which is the one case the
  # resolver logs as a misconfiguration. Expected here, so it is captured
  # rather than printed over the run.
  @moduletag :capture_log

  alias Ecto.Adapters.SQL.Sandbox
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Utils.Routes

  defmodule FakeController do
    def init(opts), do: opts
    def call(conn, _opts), do: conn
  end

  defmodule HostRouter do
    use Phoenix.Router

    get "/", PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController, :home
    get "/shop", PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController, :shop
  end

  defmodule EmptyRouter do
    use Phoenix.Router
  end

  # A host that compiled the user dashboard out — `config :phoenix_kit,
  # user_dashboard_enabled: false`, documented at `integration.ex:76` — while
  # still mounting the core admin area. Declares BOTH URL shapes core emits for
  # each admin page (prefixless-primary and locale-prefixed) and nothing else:
  # no `/dashboard`, no `/`. That is what leaves `after_login_path` as the first
  # candidate still standing on the rejection path.
  defmodule NoDashboardRouter do
    use Phoenix.Router

    get "/phoenix_kit/admin",
        PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController,
        :admin

    get "/phoenix_kit/:locale/admin",
        PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController,
        :admin_locale

    get "/phoenix_kit/admin/users",
        PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController,
        :admin_users

    get "/phoenix_kit/:locale/admin/users",
        PhoenixKit.Utils.SafeDestinationSettingsTest.FakeController,
        :admin_users_locale
  end

  @core PhoenixKitWeb.Router

  setup do
    # A cache MISS still falls through to `PhoenixKit.Settings`, and what happens
    # next depends on the environment: with no database `test_helper.exs` turns
    # `:update_mode` on and the read short-circuits to nil, but when a database
    # IS reachable it becomes a real query from a process that owns no sandbox
    # connection — an OwnershipError, not a miss. Checking out here makes the
    # file behave the same either way. Written without a database and green;
    # the first run against one failed exactly here.
    if Application.get_env(:phoenix_kit, :test_repo_available, false) do
      :ok = Sandbox.checkout(PhoenixKit.Test.Repo)
    end

    start_supervised!({PhoenixKit.Cache.Registry, []})
    # No warmer: warming would query the database this file exists to avoid.
    start_supervised!({PhoenixKit.Cache, name: :settings})
    :ok
  end

  defp put_setting(key, value), do: PhoenixKit.Cache.put(:settings, key, value)

  defp conn_for(router), do: %Plug.Conn{private: %{phoenix_router: router}, host: "localhost"}

  defp plain_user do
    %Scope{
      user: nil,
      authenticated?: true,
      cached_roles: ["User"],
      cached_permissions: MapSet.new()
    }
  end

  describe "main_page_path (anonymous chain)" do
    test "is used when it resolves in the host's router" do
      put_setting("main_page_path", "/shop")

      assert Routes.main_page_path() == "/shop"
      assert Routes.safe_destination(conn_for(HostRouter), scope: nil) == "/shop"
    end

    test "is skipped when the page it names no longer exists" do
      put_setting("main_page_path", "/renamed-away")

      assert Routes.safe_destination(conn_for(HostRouter), scope: nil) == "/"
      assert Routes.safe_destination(conn_for(@core), scope: nil) == Routes.path("/users/log-in")
    end

    test "a hostile stored value never survives the read" do
      for hostile <- ["https://evil.example", "//evil.example", "/\t/evil", "/users/log-out"] do
        put_setting("main_page_path", hostile)

        assert Routes.main_page_path() == nil
        refute Routes.safe_destination(conn_for(HostRouter), scope: nil) == hostile
      end
    end
  end

  describe "after_login_path (authenticated chain)" do
    test "\"/\" — the SHIPPED DEFAULT, written back into the row on any settings save" do
      put_setting("after_login_path", "/")

      # On a host that serves its home page this is simply correct...
      assert Routes.safe_destination(conn_for(HostRouter), scope: plain_user()) == "/"

      # ...and on one that does not, the probe rejects it. This is the case the
      # invariant is about: the value is core's default, not an administrator's
      # choice, so it must not be trusted merely because it is present.
      #
      # `EmptyRouter` declares nothing at all, so every candidate — the setting
      # included — is skipped and the chain reaches its terminal.
      #
      # That terminal is `/admin`, the landing core declares unconditionally and
      # admits every authenticated visitor to. It is not `/dashboard`, which the
      # host can still compile out with `user_dashboard_enabled: false`; an
      # earlier version of this assertion demanded exactly that and pinned the
      # 404 it caused.
      assert Routes.safe_destination(conn_for(EmptyRouter), scope: plain_user()) ==
               Routes.path("/admin")
    end

    test "is ranked below the role landing, not above it" do
      put_setting("after_login_path", "/shop")

      # `/dashboard` resolves in core's router, so it wins — the setting is the
      # fallback for visitors core has no page for, not an override.
      assert Routes.safe_destination(conn_for(@core), scope: plain_user()) ==
               Routes.path("/dashboard")

      assert Routes.safe_destination(conn_for(HostRouter), scope: plain_user()) == "/shop"
    end
  end

  describe "after_login_path pointing INTO the admin area" do
    # The loop a live-app review found, with its real inputs: `/dashboard`
    # compiled out, "After login path" set to /admin/users, and an authenticated
    # visitor holding zero permissions who requests a gated admin page.
    #
    # `:phoenix_kit_ensure_admin` denies them, `deny_admin_area/2` resolves with
    # `skip_admin: true`, and `skip_admin` used to suppress only the `/admin`
    # CANDIDATE. `/dashboard` did not resolve, so the setting was next — and it
    # IS routable, so it won, and the visitor was handed back the same kind of
    # page they had just been refused. The gate then ran the identical
    # computation: ERR_TOO_MANY_REDIRECTS, with the terminal never reached
    # because a candidate always won.
    setup do
      put_setting("after_login_path", Routes.path("/admin/users"))
      %{ctx: conn_for(NoDashboardRouter), target: Routes.path("/admin/users")}
    end

    test "the preconditions really are the reviewer's scenario", %{ctx: ctx, target: target} do
      # Without these the test would pass for the wrong reason — an unroutable
      # setting is skipped by the routability probe alone.
      refute Routes.routable?(ctx, Routes.path("/dashboard"))
      refute Routes.routable?(ctx, "/")
      assert Routes.routable?(ctx, target)
      refute Scope.can_access_admin_area?(plain_user())
    end

    test "is not handed back to a visitor just refused the admin area", %{
      ctx: ctx,
      target: target
    } do
      result = Routes.safe_destination(ctx, scope: plain_user(), skip_admin: true)

      refute result == target

      # The terminal — the /admin INDEX, which the gate admits every
      # authenticated visitor to. `skip_admin` filters CANDIDATES, never the
      # terminal; a chain with no admin path at either end would have nowhere
      # left to go.
      assert result == Routes.path("/admin")
    end

    test "the bounce settles instead of looping", %{ctx: ctx} do
      scope = plain_user()
      first = Routes.safe_destination(ctx, scope: scope, skip_admin: true)

      assert follow(ctx, scope, first) == {:rendered, Routes.path("/admin")}

      # A fixed point, not a slow walk: re-resolving yields the same terminal.
      assert Routes.safe_destination(ctx, scope: scope, skip_admin: true) == first
    end

    test "still wins where the caller is NOT rejecting anyone", %{ctx: ctx, target: target} do
      # No `skip_admin`, so nobody has been refused anything and an operator's
      # explicit choice is honoured exactly as before — the fix touches the
      # rejection path only. If this visitor cannot open the page the gate
      # bounces them ONCE, into the case above, which now terminates.
      assert Routes.safe_destination(ctx, scope: plain_user()) == target
    end
  end

  # `:phoenix_kit_ensure_admin` reduced to the two facts this models: the /admin
  # INDEX admits every authenticated visitor (`landing_view?/1` is consulted
  # before the admin-area gate), while any deeper admin page denies a scope
  # holding no permission — and that denial re-enters the resolver with exactly
  # these arguments (`deny_admin_area/2`). A non-admin destination is not this
  # hook's business and simply renders.
  #
  # Bounded, because "does not terminate" is the defect: exhausting the fuel is
  # the failure, reported as `{:looping, path}` so the assertion names the page
  # the visitor was stuck on.
  defp follow(ctx, scope, destination, fuel \\ 4)

  defp follow(_ctx, _scope, destination, 0), do: {:looping, destination}

  defp follow(ctx, scope, destination, fuel) do
    if destination != Routes.path("/admin") and String.contains?(destination, "/admin") do
      follow(ctx, scope, Routes.safe_destination(ctx, scope: scope, skip_admin: true), fuel - 1)
    else
      {:rendered, destination}
    end
  end

  describe "post_auth_path/2 — the return leg" do
    test "without a context: the setting, else the landing core guarantees" do
      # This used to assert `"/"` — the host's home page, which core does not
      # declare and many hosts never route. With no context there is nothing to
      # probe, so the tail is now `/admin` outright: scope-blind on purpose,
      # since core declares it unconditionally and admits every authenticated
      # visitor. (Resolving it through `safe_destination(nil, …)` instead would
      # run the anonymous chain and return the log-in page, which bounces an
      # authenticated visitor straight back through here.)
      assert Routes.post_auth_path() == Routes.path("/admin")
      refute Routes.auth_page?(Routes.post_auth_path())

      put_setting("after_login_path", "/shop")
      assert Routes.post_auth_path() == "/shop"
      assert Routes.post_auth_path(["/checkout"]) == "/checkout"
    end

    test "with a context, an unroutable tail is resolved instead of emitted" do
      # This is the drain the authenticated terminal used to empty into: the
      # log-in page bounces an authenticated visitor through here, and a bare
      # "/" fallback would 404 them on a host that declares no root route.
      assert Routes.post_auth_path([], context: conn_for(@core), scope: plain_user()) ==
               Routes.path("/dashboard")
    end

    test "after_login_path of \"/\" does not bypass the routability probe" do
      # "/" is the synthesised core default written back into the DB row on every
      # settings save — not a deliberate administrator choice. Before the fix,
      # `after_login_setting/0` returned "/" as a truthy value, causing
      # `home_after_auth/1` to return it immediately without passing through
      # `home_or_core_landing/2`, the only place that probes routability.
      #
      # On a host with no root route (core router), post_auth_path would then
      # emit "/" and produce a 404 — exactly the defect this branch was built to
      # prevent. The fix: `after_login_setting/0` returns nil for "/" so the
      # chain falls through to `home_or_core_landing/2`.
      put_setting("after_login_path", "/")

      # @core has no root route: falls through to safe_destination, which picks
      # /dashboard for an authenticated plain_user.
      assert Routes.post_auth_path([], context: conn_for(@core), scope: plain_user()) ==
               Routes.path("/dashboard")

      # HostRouter DOES declare "/": routable? returns true, so "/" is used.
      assert Routes.post_auth_path([], context: conn_for(HostRouter), scope: plain_user()) == "/"
    end

    test "an administrator's explicit setting is still honoured verbatim" do
      # Only the synthesized `"/"` is probed. `after_login_path` names a page in
      # the HOST's application; refusing it because this router cannot see that
      # page would break the setting rather than protect it.
      put_setting("after_login_path", "/welcome")

      assert Routes.post_auth_path([], context: conn_for(@core), scope: plain_user()) ==
               "/welcome"
    end

    test ~s|with a context, a host that really serves "/" still gets "/"| do
      assert Routes.post_auth_path([], context: conn_for(HostRouter), scope: plain_user()) == "/"
    end
  end
end
