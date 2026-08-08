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

  describe "permission_key_for_admin_view/1" do
    test "returns key from static @admin_view_permissions map" do
      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Dashboard) ==
               "dashboard"

      assert Auth.permission_key_for_admin_view(PhoenixKitWeb.Live.Users.Users) ==
               "users"
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
  describe "can_access_admin_view?/2" do
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
  end
end
