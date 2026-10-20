defmodule PhoenixKitWeb.Users.AuthTest do
  use ExUnit.Case, async: false

  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Utils.Routes
  alias PhoenixKitWeb.Users.Auth

  # `permission_key_for_admin_view/1` is exposed as `@doc false def` so this
  # test can exercise the static map, the custom-tabs lookup, the
  # `PhoenixKit.Modules.*` namespace branch, and the registered-plugin
  # branch added for external modules (PhoenixKitEntities, PhoenixKitBilling, …).

  # Fixture module created with an explicit top-level name. `defmodule X` inside
  # a test gets auto-nested under the test module's namespace, which would make
  # `Module.split/1` return the wrong head segment — Module.create/3 dodges that.
  setup_all do
    Module.create(
      PhoenixKitFakePluginFixture,
      quote do
        def module_key, do: "fake_plugin"
      end,
      Macro.Env.location(__ENV__)
    )

    :ok
  end

  describe "permission_key_for_admin_view/1 and /2" do
    # Two tabs naming the SAME module on different actions (#844) — a landing
    # redirector on one action, the real page on another.
    @tabbed_view PhoenixKitFakeTabbedViewFixture
    @legacy_view PhoenixKitFakeLegacyViewFixture

    setup do
      on_exit(fn -> Permissions.clear_custom_keys() end)
      :ok
    end

    test "resolves per-action keys independently (#844)" do
      Permissions.cache_custom_view_permission({@tabbed_view, :index}, "reports_view")
      Permissions.cache_custom_view_permission({@tabbed_view, :edit}, "reports_manage")

      assert Auth.permission_key_for_admin_view(@tabbed_view, :index) == "reports_view"
      assert Auth.permission_key_for_admin_view(@tabbed_view, :edit) == "reports_manage"
    end

    test "the 1-arity call sees a module's sole tab permission, and nothing when its tabs disagree" do
      Permissions.cache_custom_view_permission({@tabbed_view, :index}, "reports_view")

      # One tab, one permission: an action-less lookup is guarded by it, as
      # an untabbed action of the same module (`:show` of an `:index` tab)
      # must be — otherwise a partial role holding the tab's key could open
      # the list and none of the records in it (review of #850).
      assert Auth.permission_key_for_admin_view(@tabbed_view) == "reports_view"

      Permissions.cache_custom_view_permission({@tabbed_view, :edit}, "reports_manage")

      # Two tabs gated differently (#844): a module-only lookup has no safe
      # answer. Every reader that gates a real route must pass the route's
      # action — `Session.reachable_return_to?/3` does.
      assert Auth.permission_key_for_admin_view(@tabbed_view) == nil
    end

    test "falls back to the module-only entry when no per-action key matches" do
      Permissions.cache_custom_view_permission(@legacy_view, "legacy_perm")

      assert Auth.permission_key_for_admin_view(@legacy_view, :index) == "legacy_perm"
      assert Auth.permission_key_for_admin_view(@legacy_view, :whatever) == "legacy_perm"
      assert Auth.permission_key_for_admin_view(@legacy_view) == "legacy_perm"
    end

    test "returns key from static @admin_view_permissions map" do
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Dashboard) ==
               "dashboard"

      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Users.Users) ==
               "users"
    end

    test "maps Settings -> API to the api permission, not to settings" do
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Settings.Api) == "api"
    end

    test "maps Approvals, and the old Settings -> API -> approvals redirect, to the api permission too" do
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Approvals) == "api"
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Settings.ApiApprovals) == "api"
    end

    test "maps Settings -> API -> Guide to the api permission too" do
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Settings.ApiGuide) == "api"
    end

    test "infers key from PhoenixKit.Modules.<Name>.Web.* namespace" do
      assert Auth.permission_key_for_admin_view(PhoenixKit.Modules.Tickets.Web.Index) ==
               "tickets"

      assert Auth.permission_key_for_admin_view(PhoenixKit.Modules.NewsLetters.Web.Show) ==
               "news_letters"
    end

    test "resolves external plugin namespace via ModuleRegistry" do
      ModuleRegistry.register(PhoenixKitFakePluginFixture)
      on_exit(fn -> ModuleRegistry.unregister(PhoenixKitFakePluginFixture) end)

      assert Auth.permission_key_for_admin_view(PhoenixKitFakePluginFixture.Web.Index) ==
               "fake_plugin"

      assert Auth.permission_key_for_admin_view(PhoenixKitFakePluginFixture.Web.Edit.Form) ==
               "fake_plugin"
    end

    test "returns nil for unknown views (preserves fail-closed default)" do
      assert Auth.permission_key_for_admin_view(SomeRandomUnregisteredModule) == nil
    end
  end

  # `can_access_admin_view?/2` is the ONE predicate behind both the on_mount
  # enforcement and any "should I render this card/link?" decision. These tests
  # pin all four of its branches so the two callers cannot drift apart.
  #
  # DB-free: every scope is built as a literal struct, and every permission key
  # used here is either a core section key (always enabled, no module toggle) or
  # comes from a fake module registered in the in-memory `ModuleRegistry`.
  describe "can_access_admin_view?/2 and /3" do
    defmodule FakeViewCalendar do
      def module_key, do: "fake_view_calendar"
      def module_name, do: "Fake View Calendar"
      def enabled?, do: true

      def permission_metadata do
        %{
          key: "fake_view_calendar",
          label: "Fake View Calendar",
          icon: "hero-calendar-days",
          description: "Fake enabled module with a sub-permission",
          sub_permissions: [
            %{key: "view_others", label: "View others' calendars", description: "Read-only"}
          ]
        }
      end
    end

    defmodule FakeViewDisabled do
      def module_key, do: "fake_view_disabled"
      def module_name, do: "Fake View Disabled"
      def enabled?, do: false

      def permission_metadata do
        %{
          key: "fake_view_disabled",
          label: "Fake View Disabled",
          icon: "hero-no-symbol",
          description: "Fake module that is switched off"
        }
      end
    end

    # Views. None of these modules need to exist — resolution is by name.
    @mapped_view PhoenixKitWeb.Live.Users.Users
    @personal_view PhoenixKitWeb.Live.Notifications.Inbox
    @unmapped_view PhoenixKitWeb.Live.SomeHostCustomAdminPageFixture
    @disabled_module_view PhoenixKit.Modules.FakeViewDisabled.Web.Index
    @sub_permission_view PhoenixKitFakeSubPermissionViewFixture

    setup do
      ModuleRegistry.register(FakeViewCalendar)
      ModuleRegistry.register(FakeViewDisabled)

      # The only way a view resolves to a DOTTED sub-permission key is the
      # custom-tab cache, so prime it directly.
      Permissions.cache_custom_view_permission(
        @sub_permission_view,
        "fake_view_calendar.view_others"
      )

      on_exit(fn ->
        ModuleRegistry.unregister(FakeViewCalendar)
        ModuleRegistry.unregister(FakeViewDisabled)
        Permissions.clear_custom_keys()
      end)

      :ok
    end

    defp scope(roles, permissions) do
      %Scope{
        user: %User{uuid: "0193a5e4-0000-7000-8000-000000000001", email: "gate@example.com"},
        authenticated?: true,
        cached_roles: roles,
        cached_permissions: MapSet.new(permissions)
      }
    end

    # Mirrors `Scope.for_user/1`: an Owner caches every key that exists.
    defp owner_scope, do: scope(["Owner"], Permissions.all_module_keys())

    # A default Admin holds the operator baseline as real rows — every
    # grantable key except the opt-in/opt-out extras it is never auto-granted.
    defp admin_scope do
      baseline =
        MapSet.difference(
          Permissions.enabled_module_keys(),
          MapSet.new(Permissions.admin_baseline_exclusions())
        )

      scope(["Admin"], baseline)
    end

    # A portal client: authenticated, holds a couple of narrow keys, no
    # operator keys at all.
    defp client_scope, do: scope(["Client"], ["client_portal", "notifications"])

    # A plain user with no permission rows whatsoever.
    defp plain_user_scope, do: scope(["User"], [])

    test "branch 1: the admin-area gate hides every view from a permission-less scope" do
      for view <- [@mapped_view, @personal_view, @unmapped_view, @sub_permission_view] do
        refute Auth.can_access_admin_view?(plain_user_scope(), view)
        refute Auth.can_access_admin_view?(nil, view)
      end
    end

    test "branch 1: a nil scope is refused even for a core view" do
      refute Auth.can_access_admin_view?(nil, @mapped_view)
    end

    test "branch 2: a personal admin view needs only admin-area access" do
      assert Auth.can_access_admin_view?(owner_scope(), @personal_view)
      assert Auth.can_access_admin_view?(admin_scope(), @personal_view)
      # A client holds SOME permission, so the coarse gate lets it in — and
      # reading your own inbox is not an administrative capability.
      assert Auth.can_access_admin_view?(client_scope(), @personal_view)
      refute Auth.can_access_admin_view?(plain_user_scope(), @personal_view)
    end

    test "branch 3: a mapped key is granted to holders and refused to everyone else" do
      assert Auth.can_access_admin_view?(owner_scope(), @mapped_view)
      assert Auth.can_access_admin_view?(admin_scope(), @mapped_view)
      # The client holds `client_portal`/`notifications`, never `users`.
      refute Auth.can_access_admin_view?(client_scope(), @mapped_view)
      refute Auth.can_access_admin_view?(scope(["Editor"], ["media"]), @mapped_view)
      assert Auth.can_access_admin_view?(scope(["Editor"], ["users"]), @mapped_view)
    end

    test "branch 3: the `\"*\"` superadmin key reaches a mapped view" do
      assert Auth.can_access_admin_view?(scope(["Support"], ["*"]), @mapped_view)
    end

    test "branch 3: a DISABLED module is refused to everyone, Owner included" do
      # This is the branch a bare `has_module_access?/2` card check would get
      # wrong: Owner holds `fake_view_disabled` (it holds every key), so a
      # permission-only check would render a card whose destination redirects
      # to /admin/modules with "module is not enabled".
      assert Scope.has_module_access?(owner_scope(), "fake_view_disabled")
      refute Auth.can_access_admin_view?(owner_scope(), @disabled_module_view)
      refute Auth.can_access_admin_view?(admin_scope(), @disabled_module_view)

      refute Auth.can_access_admin_view?(
               scope(["Editor"], ["fake_view_disabled"]),
               @disabled_module_view
             )
    end

    test "branch 3: a dotted SUB-permission key routes through can?/2, not a raw lookup" do
      base = "fake_view_calendar"
      sub = "fake_view_calendar.view_others"

      # Held with its base — the legitimate holder sees the card.
      assert Auth.can_access_admin_view?(scope(["Editor"], [base, sub]), @sub_permission_view)
      assert Auth.can_access_admin_view?(owner_scope(), @sub_permission_view)

      # Base only: the sub-permission was never granted.
      refute Auth.can_access_admin_view?(scope(["Editor"], [base]), @sub_permission_view)

      # ORPHAN sub — the row outlived its base. A raw `has_module_access?/2`
      # would say yes here; `can?/2` (and therefore this predicate, and
      # therefore the mount gate) says no.
      orphan = scope(["Editor"], [sub])
      assert Scope.has_module_access?(orphan, sub)
      refute Auth.can_access_admin_view?(orphan, @sub_permission_view)
    end

    test "branch 4: an UNMAPPED view is open only to a full-access scope" do
      assert Auth.permission_key_for_admin_view(@unmapped_view) == nil

      # Owner and a grant-everything role pass...
      assert Auth.can_access_admin_view?(owner_scope(), @unmapped_view)
      assert Auth.can_access_admin_view?(admin_scope(), @unmapped_view)
      assert Auth.can_access_admin_view?(scope(["Support"], ["*"]), @unmapped_view)

      # ...everyone partial fails CLOSED.
      refute Auth.can_access_admin_view?(client_scope(), @unmapped_view)
      refute Auth.can_access_admin_view?(scope(["Editor"], ["users", "media"]), @unmapped_view)

      # Including a named Admin whose keys an Owner partially revoked.
      stripped =
        MapSet.delete(
          MapSet.difference(
            Permissions.enabled_module_keys(),
            MapSet.new(Permissions.admin_baseline_exclusions())
          ),
          "users"
        )

      refute Auth.can_access_admin_view?(scope(["Admin"], stripped), @unmapped_view)
    end

    # #844: two tabs naming the SAME module, gated on different actions, must
    # be enforced independently — a permission held for one action must not
    # leak access to the other, and vice versa.
    @tabbed_view PhoenixKitFakeTabbedAdminViewFixture

    test "the optional 3rd arg distinguishes two actions of the same module (#844)" do
      # `feature_enabled?/1` (the first gate in `admin_view_permission_check/2`)
      # requires the key to be registered, not just cached against a view —
      # `auto_grant_admin: false` skips the Admin auto-grant DB round trip,
      # which this DB-free-by-convention test has no sandbox checkout for.
      Permissions.register_custom_key("reports_view", auto_grant_admin: false)
      Permissions.register_custom_key("reports_manage", auto_grant_admin: false)
      Permissions.cache_custom_view_permission({@tabbed_view, :index}, "reports_view")
      Permissions.cache_custom_view_permission({@tabbed_view, :edit}, "reports_manage")

      viewer = scope(["Editor"], ["reports_view"])
      manager = scope(["Editor"], ["reports_manage"])

      assert Auth.can_access_admin_view?(viewer, @tabbed_view, :index)
      refute Auth.can_access_admin_view?(viewer, @tabbed_view, :edit)

      refute Auth.can_access_admin_view?(manager, @tabbed_view, :index)
      assert Auth.can_access_admin_view?(manager, @tabbed_view, :edit)
    end

    test "omitting the action treats the view as unmapped when the module's tabs disagree" do
      Permissions.cache_custom_view_permission({@tabbed_view, :index}, "reports_view")
      Permissions.cache_custom_view_permission({@tabbed_view, :edit}, "reports_manage")

      # No module-only entry was cached, and the per-action keys disagree, so
      # the 2-arity call (no action) cannot pick one. An unmapped view fails
      # closed for a partial scope, exactly like branch 4 above...
      refute Auth.can_access_admin_view?(scope(["Editor"], ["reports_view"]), @tabbed_view)

      # ...and stays open only to a full-access scope.
      assert Auth.can_access_admin_view?(owner_scope(), @tabbed_view)
    end
  end

  # `/admin` is the terminal of `PhoenixKit.Utils.Routes.safe_destination/2` —
  # the page core promises EVERY signed-in visitor can be redirected to. A
  # terminal that bounces its own visitor is an infinite redirect, not a
  # fallback, so `:phoenix_kit_ensure_admin` admits any authenticated visitor to
  # that one view.
  #
  # It is admitted by the GATE, not by the router: the route stays in
  # `live_session :phoenix_kit_admin` with the rest of the admin surface (pinned
  # in `test/phoenix_kit_web/route_precedence_test.exs`), because LiveView
  # cannot live-navigate across live_sessions and a landing in its own session
  # makes every click into and out of the admin area a full page reload.
  #
  # `admin_gate_decision/2` is the pure core of that gate, exposed as
  # `@doc false def` so these tests can drive every branch with literal scopes
  # and no database. The scope builders are the ones defined for
  # `can_access_admin_view?/2` above.
  describe "admin_gate_decision/2" do
    @other_admin_view PhoenixKitWeb.Live.Users.Users

    test "the landing view is open to every authenticated visitor" do
      # Owner, Admin, a portal client holding two narrow keys, and a user
      # holding nothing at all: the guaranteed landing takes them all.
      for s <- [owner_scope(), admin_scope(), client_scope(), plain_user_scope()] do
        assert Auth.admin_gate_decision(s, PhoenixKitWeb.Live.Dashboard) == :landing
      end
    end

    test "an Owner is unaffected on every other admin view" do
      assert Auth.admin_gate_decision(owner_scope(), @other_admin_view) == :enforce_view
      assert Auth.admin_gate_decision(admin_scope(), @other_admin_view) == :enforce_view
    end

    test "every other admin view still runs the admin-area gate, then the per-view one" do
      # A holder of ANY permission clears the admin area and is handed to
      # `enforce_admin_view_permission/2` — the per-view check, unchanged.
      # `can_access_admin_view?/2` (tested exhaustively above) is what that
      # check consults, and it refuses this client the users page.
      assert Auth.admin_gate_decision(client_scope(), @other_admin_view) == :enforce_view
      refute Auth.can_access_admin_view?(client_scope(), @other_admin_view)

      # No permissions at all: refused before any view question is asked.
      assert Auth.admin_gate_decision(plain_user_scope(), @other_admin_view) == :deny
      assert Auth.admin_gate_decision(nil, @other_admin_view) == :deny
    end

    test "the landing is asked FIRST — reversing the branches would deny a client" do
      # The load-bearing ordering, made executable. This client clears
      # `can_access_admin_area?/1` (it holds two permissions), so an
      # admin-area-first gate would route it to `:enforce_view`...
      client = client_scope()
      assert Scope.can_access_admin_area?(client)

      # ...where the landing view's own permission key would refuse it,
      # bouncing the visitor off the page the resolver had just guaranteed.
      refute Auth.can_access_admin_view?(client, PhoenixKitWeb.Live.Dashboard)

      # Landing first, so it does not happen.
      assert Auth.admin_gate_decision(client, PhoenixKitWeb.Live.Dashboard) == :landing
    end

    test "`:landing` is the only decision that skips the per-view assign and check" do
      # `enforce_admin_view_permission/2` is what assigns
      # `:phoenix_kit_current_module_key`, and its only reader
      # (`handle_scope_refresh/2`) uses it to push a user off a page whose
      # permission they just lost. On the guaranteed landing that must never
      # happen — which is exactly what "`:landing` does not reach the
      # enforcement" means. Stated here as the decision itself, since the
      # enforcement's side effects need a mounted socket.
      assert Auth.admin_gate_decision(owner_scope(), PhoenixKitWeb.Live.Dashboard) == :landing
      assert Auth.admin_gate_decision(owner_scope(), @other_admin_view) == :enforce_view
    end
  end

  # The mirror image of the mount gate: what a permission change does to the
  # page a visitor is ALREADY on. `handle_scope_refresh/2` needs the database to
  # re-read the user, so the decision is factored out pure and driven here.
  describe "scope_refresh_decision/4" do
    @landing PhoenixKitWeb.Live.Dashboard
    @other_view PhoenixKitWeb.Live.Users.Users

    test "a demoted visitor is NOT evicted from the guaranteed landing" do
      # The bounce the resolver asserts cannot happen. `/admin` is the terminal
      # of `safe_destination/2` and the gate admits every authenticated visitor
      # to it, so throwing a just-demoted user off it would push them toward a
      # destination whose terminal is the page they were thrown off.
      assert Auth.scope_refresh_decision(true, plain_user_scope(), @landing, nil) == :stay
      assert Auth.scope_refresh_decision(true, plain_user_scope(), @landing, "dashboard") == :stay
    end

    test "every other admin page still evicts a demoted visitor" do
      assert Auth.scope_refresh_decision(true, plain_user_scope(), @other_view, "users") ==
               :evict_admin_area

      assert Auth.scope_refresh_decision(true, plain_user_scope(), @other_view, nil) ==
               :evict_admin_area

      # Including the deprecated /dashboard page, which is NOT the landing.
      assert Auth.scope_refresh_decision(
               true,
               plain_user_scope(),
               PhoenixKitWeb.Live.Dashboard.Index,
               nil
             ) == :evict_admin_area
    end

    test "the landing exemption is not an AUTHENTICATION exemption" do
      # The scope came back unauthenticated: the user row went away under the
      # socket. The gate would not admit them to `/admin` on a fresh mount
      # either — `require_authenticated_live/2` runs before the landing is ever
      # considered — so nothing here should keep them on it.
      gone = %Scope{authenticated?: false, cached_roles: [], cached_permissions: MapSet.new()}

      assert Auth.scope_refresh_decision(true, gone, @landing, nil) == :evict_admin_area
      assert Auth.scope_refresh_decision(true, nil, @landing, nil) == :evict_admin_area
    end

    test "a visitor who never had admin access is not evicted by the first branch" do
      # `was_admin?` false: nothing was lost, so there is nothing to evict from.
      assert Auth.scope_refresh_decision(false, plain_user_scope(), @other_view, "users") == :stay
    end

    test "losing one module's permission still evicts from that module's page" do
      # Still in the admin area (holds `client_portal`), but no longer holds the
      # key the current view resolved to.
      assert Auth.scope_refresh_decision(true, client_scope(), @other_view, "users") ==
               :evict_module

      # ...and holding it is `:stay`.
      assert Auth.scope_refresh_decision(true, client_scope(), @other_view, "client_portal") ==
               :stay
    end

    test "an unresolved module key is never a reason to evict" do
      # The landing skips `enforce_admin_view_permission/2`, so it never assigns
      # `:phoenix_kit_current_module_key` — `nil` must not read as "lost it".
      assert Auth.scope_refresh_decision(true, owner_scope(), @landing, nil) == :stay
      assert Auth.scope_refresh_decision(true, client_scope(), @other_view, nil) == :stay
    end

    test "an unchanged Owner stays wherever they are" do
      for view <- [@landing, @other_view] do
        assert Auth.scope_refresh_decision(true, owner_scope(), view, "users") == :stay
      end
    end
  end

  # The scope-refresh hook re-derives the page's own scope-dependent assigns
  # before it decides anything, so a page nobody is evicted from does not sit on
  # gates that predate the change. A LiveView opts in by exporting
  # `phoenix_kit_scope_changed/1`.
  describe "refresh_view_scope_assigns/1" do
    alias Phoenix.LiveView.Socket

    defp gated_socket(view, scope, extra \\ %{}) do
      assigns =
        Map.merge(
          %{__changed__: %{}, phoenix_kit_current_scope: scope},
          extra
        )

      %Socket{view: view, assigns: assigns}
    end

    test "the landing recomputes every gate through the dashboard's callback" do
      # Stale gates from a mount that happened while the visitor was an
      # operator, and a scope that now holds nothing.
      stale = %{
        can_access_admin_area?: true,
        show_statistics: true,
        show_users_card: true,
        stats: %{total_users: 7}
      }

      socket =
        Auth.refresh_view_scope_assigns(
          gated_socket(PhoenixKitWeb.Live.Dashboard, plain_user_scope(), stale)
        )

      refute socket.assigns.can_access_admin_area?
      refute socket.assigns.show_statistics
      refute socket.assigns.show_users_card
      assert socket.assigns.stats == nil
    end

    test "a view that exports no callback is returned untouched" do
      socket = gated_socket(@other_view, plain_user_scope(), %{show_users_card: true})

      assert Auth.refresh_view_scope_assigns(socket) == socket
    end

    test "a socket with no view at all is returned untouched" do
      socket = gated_socket(nil, plain_user_scope())

      assert Auth.refresh_view_scope_assigns(socket) == socket
    end
  end

  describe "landing_view?/1" do
    test "names exactly one view" do
      assert Auth.landing_view?(PhoenixKitWeb.Live.Dashboard)

      for other <- [
            PhoenixKitWeb.Live.Users.Users,
            PhoenixKitWeb.Live.Modules,
            PhoenixKitWeb.Live.Notifications.Inbox,
            PhoenixKitWeb.Live.Settings,
            nil
          ] do
        refute Auth.landing_view?(other)
      end
    end

    test "the deprecated /dashboard page is NOT the landing" do
      # `PhoenixKitWeb.Live.Dashboard.Index` serves `/dashboard`, a separate
      # deprecated page compiled out by `user_dashboard_enabled: false`. Sharing
      # a name prefix with the landing is the whole risk here.
      refute Auth.landing_view?(PhoenixKitWeb.Live.Dashboard.Index)
    end
  end

  # The one arm of `:phoenix_kit_ensure_admin` reachable without a database: an
  # anonymous visitor never gets as far as `Scope.for_user/1`, so the real hook
  # can be driven end to end here. Everything past this point needs a user row.
  describe "on_mount(:phoenix_kit_ensure_admin) for an anonymous visitor" do
    alias Phoenix.LiveView.Lifecycle
    alias Phoenix.LiveView.Socket

    defp anonymous_socket(view, path) do
      %Socket{
        view: view,
        assigns: %{__changed__: %{}, flash: %{}},
        private: %{
          connect_params: %{},
          connect_info: %{uri: URI.parse("http://localhost" <> path)},
          lifecycle: %Lifecycle{},
          live_temp: %{}
        },
        router: PhoenixKitWeb.Router
      }
    end

    test "the landing view bounces them to log-in, carrying return_to" do
      # The landing exemption is NOT an authentication exemption:
      # `require_authenticated_live/2` runs before `admin_gate_decision/2` is
      # consulted, so this halts exactly as it did before the exemption existed.
      path = Routes.path("/admin")

      {:halt, socket} =
        Auth.on_mount(
          :phoenix_kit_ensure_admin,
          %{},
          %{},
          anonymous_socket(PhoenixKitWeb.Live.Dashboard, path)
        )

      assert {:redirect, %{to: to}} = socket.redirected
      assert to =~ "/users/log-in"
      assert to =~ "return_to=" <> URI.encode_www_form(path)
      assert socket.assigns.flash["error"] =~ "log in"
    end

    test "any other admin view bounces them identically" do
      path = Routes.path("/admin/users")

      {:halt, socket} =
        Auth.on_mount(
          :phoenix_kit_ensure_admin,
          %{},
          %{},
          anonymous_socket(PhoenixKitWeb.Live.Users.Users, path)
        )

      assert {:redirect, %{to: to}} = socket.redirected
      assert to =~ "/users/log-in"
      assert to =~ "return_to=" <> URI.encode_www_form(path)
    end
  end

  describe "redirect_to_base_locale/2 carries the query string" do
    # Every locale redirect in this module rebuilds a PATH, and both
    # `conn.request_path` and `conn.path_info` stop at the "?" — so the
    # query was silently dropped while the docstring promised the
    # opposite. On this surface that costs `return_to`, which
    # `Routes.return_to_query/1` threads through exactly these URLs.
    #
    # This function is DB-free (base-code extraction is pure string work),
    # so it pins the behaviour in the no-DB unit suite; the settings-gated
    # siblings are covered in `test/integration/users/auth_locale_test.exs`.

    import Phoenix.ConnTest, only: [build_conn: 3]

    defp dialect_conn(path) do
      build_conn(:get, path, nil) |> Plug.Conn.fetch_query_params()
    end

    defp location(conn), do: Plug.Conn.get_resp_header(conn, "location") |> List.first()

    test "query parameters survive the dialect → base rewrite" do
      conn =
        "/phoenix_kit/en-US/users/log-in?return_to=%2Fadmin%2Fusers&page=2"
        |> dialect_conn()
        |> Auth.redirect_to_base_locale("en-US")

      assert conn.halted
      assert location(conn) == "/phoenix_kit/en/users/log-in?return_to=%2Fadmin%2Fusers&page=2"
    end

    test "a dialect at the end of the path keeps its query too" do
      conn =
        "/phoenix_kit/es-MX?page=2"
        |> dialect_conn()
        |> Auth.redirect_to_base_locale("es-MX")

      assert location(conn) == "/phoenix_kit/es?page=2"
    end

    test "no query string means no stray '?'" do
      conn =
        "/phoenix_kit/en-US/users/log-in"
        |> dialect_conn()
        |> Auth.redirect_to_base_locale("en-US")

      assert location(conn) == "/phoenix_kit/en/users/log-in"
    end

    test "a query Phoenix would refuse is dropped, not raised on" do
      # `Phoenix.Controller.redirect/2` raises ArgumentError on "\\",
      # "/\t" and "/%09" anywhere in the target, and a query string is
      # arbitrary client input. Truncating to the path matches what
      # shipped before; a 500 would be strictly worse.
      conn =
        "/phoenix_kit/en-US/search?q=C:%5Cwindows"
        |> dialect_conn()
        |> Map.put(:query_string, "q=C:\\windows")
        |> Auth.redirect_to_base_locale("en-US")

      assert location(conn) == "/phoenix_kit/en/search"
    end

    test "a percent-encoded dialect segment does not redirect to itself" do
      # `conn.request_path`/`path_info` stay percent-encoded, but
      # `full_dialect` (like `path_params["locale"]` in production) is
      # the decoded value. A plain `String.replace` against the decoded
      # dialect would miss the encoded "%65n-US" entirely and redirect
      # back to the same URL — the same bug class as #849, just on an
      # all-ASCII segment.
      request_path = "/phoenix_kit/%65n-US/users/log-in"

      conn =
        request_path
        |> dialect_conn()
        |> Auth.redirect_to_base_locale("en-US")

      assert conn.halted
      refute location(conn) == request_path
      assert location(conn) == "/phoenix_kit/en/users/log-in"
    end
  end

  describe "redirect_to_base_locale/2 declines rather than crashes on a hostile segment" do
    # `extract_base/1` (lib/modules/languages/dialect_mapper.ex) copies a
    # piece of its input verbatim into `base_code`, and `full_dialect` here
    # is the DECODED URL segment `process_locale/1` hands it with no other
    # validation (any segment containing "-" reaches this function). A
    # crafted segment can therefore make `base_code` carry "/", "\", a
    # control character, or land empty — spliced unchecked into the
    # redirect target, each of those reaches `Phoenix.Controller.redirect/2`
    # (or, for a leading "//", is rejected by its own local-path check) and
    # RAISES instead of declining, turning an anonymous GET into a 500.
    # `locale_segment_path/3`'s `safe_path_segment?/1` guard now rejects
    # these before they're ever joined into a path, so this function falls
    # through to `assign_default_locale/1` — no redirect, no crash — same
    # as any other unrecognized shape.

    import Phoenix.ConnTest, only: [build_conn: 3]

    defp hostile_conn(path) do
      build_conn(:get, path, nil) |> Plug.Conn.fetch_query_params()
    end

    defp with_url_prefix(value, fun) do
      previous = Application.fetch_env(:phoenix_kit, :url_prefix)
      Application.put_env(:phoenix_kit, :url_prefix, value)
      PhoenixKit.Config.clear_url_prefix_cache()

      try do
        fun.()
      after
        case previous do
          {:ok, prior} -> Application.put_env(:phoenix_kit, :url_prefix, prior)
          :error -> Application.delete_env(:phoenix_kit, :url_prefix)
        end

        PhoenixKit.Config.clear_url_prefix_cache()
      end
    end

    test "a base_code containing '//' does not raise at root url_prefix" do
      # decoded locale "//evil.com-x" → extract_base → "//evil.com". Before
      # the guard, `Enum.join(["//evil.com", "shop"], "/")` prefixed with
      # "/" produced "///evil.com/shop" — Phoenix's own leading-"//" check
      # in `Phoenix.Controller.redirect/2` raises ArgumentError on that,
      # and it only starts the string at root `url_prefix` (a mount
      # prefix segment like "phoenix_kit" pushes it off byte offset 0).
      with_url_prefix("/", fn ->
        conn =
          "/%2F%2Fevil.com-x/shop"
          |> hostile_conn()
          |> Auth.redirect_to_base_locale("//evil.com-x")

        refute conn.halted
        assert conn.assigns.current_locale_base == "en"
      end)
    end

    test "a base_code containing '//' does not raise under a named url_prefix either" do
      # Same payload as above, but under the default "/phoenix_kit" prefix
      # used everywhere else in this file: the guard applies uniformly
      # regardless of where the locale segment lands in the path.
      conn =
        "/phoenix_kit/%2F%2Fevil.com-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("//evil.com-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code containing a backslash does not raise" do
      # decoded locale "\\evil.com-x" (two literal backslashes) →
      # extract_base → a segment containing "\". Before the guard, the
      # joined path contained "\" and `Phoenix.Controller.redirect/2`
      # raises ArgumentError ("unsafe characters detected for local
      # redirect") on that unconditionally — not anchored to path
      # position, so this crashes under either url_prefix.
      conn =
        "/phoenix_kit/%5C%5Cevil.com-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("\\\\evil.com-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code containing a control character does not raise" do
      # decoded locale "\nevil-x" (leading newline) → extract_base →
      # "\nevil". Before the guard, the joined path contained "\n", which
      # `Phoenix.Controller.redirect/2`'s own local-path validation
      # (`Phoenix.URL.classify_local_path/1`) also rejects with
      # `ArgumentError` — again not position-anchored.
      conn =
        "/phoenix_kit/%0Aevil-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("\nevil-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code that extracts empty does not raise at root url_prefix" do
      # decoded locale "-x" → `String.split("-")` → ["", "x"] →
      # `List.first/1` → "" — an empty `base_code`. Before the guard,
      # `Enum.join(["", "shop"], "/")` prefixed with "/" produced
      # "//shop", the same leading-"//" crash as the first test, and same
      # positional caveat: only manifests at root `url_prefix`.
      with_url_prefix("/", fn ->
        conn =
          "/-x/shop"
          |> hostile_conn()
          |> Auth.redirect_to_base_locale("-x")

        refute conn.halted
        assert conn.assigns.current_locale_base == "en"
      end)
    end

    test "a base_code that extracts empty does not raise under a named url_prefix either" do
      conn =
        "/phoenix_kit/-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    # The MAJOR-1 regression (#849 follow-up): a decoded locale segment that
    # only SPELLS a percent-encoded control character as literal text — e.g.
    # the raw path segment "%2509-x" decodes ONCE (Phoenix router matching)
    # to "%09-x" (five printable ASCII characters: %, 0, 9, -, x — not an
    # actual tab byte). `extract_base/1` then yields "%09", which the OLD
    # blocklist-based `safe_path_segment?/1` waved through (no "/", no "\",
    # no control byte) — it had no opinion about "%" at all. Spliced into
    # the joined path next to a "/" separator, that reproduces the literal
    # substring "/%09" that `Phoenix.Controller.redirect/2`'s own local-path
    # validation refuses, raising `ArgumentError` on an anonymous GET.

    test "%2509 as base_code (decodes to literal '%09-x', not a control byte) does not raise at root url_prefix" do
      with_url_prefix("/", fn ->
        conn =
          "/%2509-x/shop"
          |> hostile_conn()
          |> Auth.redirect_to_base_locale("%09-x")

        refute conn.halted
        assert conn.assigns.current_locale_base == "en"
      end)
    end

    test "%2509 as base_code does not raise under a named url_prefix either" do
      conn =
        "/phoenix_kit/%2509-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("%09-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "%250A as base_code (decodes to literal '%0A-x') declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/%250A-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("%0A-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "%250D as base_code (decodes to literal '%0D-x') declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/%250D-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("%0D-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    # The allowlist rewrite of `safe_path_segment?/1` rejects anything
    # outside `[a-zA-Z0-9_-]`, not just the specific characters the old
    # blocklist happened to name. One representative case per category the
    # review called out, each crafted via `extract_base/1` the same way as
    # the tests above.
    #
    # None of `?`/`#`/space/UTF-8/`..` trip Phoenix's own local-path
    # validation (`unsafe_redirect_target?/1` mirrors that list exactly, and
    # none of these characters are in it) — pre-fix, each of these produced
    # a *malformed-but-successful* 302 (e.g. Location `/phoenix_kit/a?b/shop`,
    # which a browser reads as path `/phoenix_kit/a` plus query `b/shop`),
    # not a crash. Only the allowlist catches this class; test names below
    # say "declines rather than redirecting to a malformed target", not
    # "does not raise", to describe the actual pre-fix failure mode.

    test "a base_code containing '?' declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/a%3Fb-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("a?b-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code containing '#' declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/a%23b-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("a#b-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code containing a space declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/a%20b-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("a b-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code containing raw non-ASCII UTF-8 declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/caf%C3%A9-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("café-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end

    test "a base_code that is '..' declines rather than redirecting to a malformed target" do
      conn =
        "/phoenix_kit/..-x/shop"
        |> hostile_conn()
        |> Auth.redirect_to_base_locale("..-x")

      refute conn.halted
      assert conn.assigns.current_locale_base == "en"
    end
  end
end
