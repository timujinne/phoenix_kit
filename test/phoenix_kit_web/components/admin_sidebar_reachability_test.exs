defmodule PhoenixKitWeb.Components.Dashboard.AdminSidebarReachabilityTest do
  @moduledoc """
  `/admin` is the guaranteed landing for every authenticated user, so the admin
  shell now renders for visitors who could never reach it before. These tests
  pin the properties that follow:

    * an Owner (and a default Admin) sees exactly what it saw before — the
      whole point is that the change is invisible to operators;
    * a visitor holding no permissions is offered nothing at all, rather than
      a menu of pages that redirect on arrival;
    * and nothing is left behind when the menu empties — no sidebar column, no
      burger button, no navigation landmark, no bordered footer strip.

  Every destination in the shell is covered, not only the sidebar: the
  notifications bell's "View all" footer links straight to `/admin/notifications`.

  DB-free. Scopes are literal structs (the pattern
  `test/phoenix_kit_web/users/auth_test.exs` uses), the tab set is the real
  `AdminTabs.default_tabs/0`, and every permission key involved is a core
  section key (always enabled, no module toggle) or one primed directly into
  the in-memory permission caches.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog, only: [with_log: 1]
  import Phoenix.Component, only: [sigil_H: 2, render_slot: 1]
  import Phoenix.LiveViewTest, only: [render_component: 2, rendered_to_string: 1]

  alias PhoenixKit.Dashboard.{AdminTabs, Tab}
  alias PhoenixKit.Users.Auth.{Scope, User}
  alias PhoenixKit.Users.Permissions
  alias PhoenixKitWeb.Components.Dashboard.AdminSidebar
  alias PhoenixKitWeb.Components.LayoutWrapper
  alias PhoenixKitWeb.Live.NotificationsBell

  # A host/module admin page wired the "single page" way: a tab naming a
  # LiveView. None of these modules need to exist — every gate resolves them by
  # name.
  @mapped_view PhoenixKitWeb.Live.Users.Users
  @custom_mapped_view PhoenixKitReachabilityFixture.Web.Reports
  @unmapped_view PhoenixKitReachabilityFixture.Web.Unmapped

  setup do
    # The custom-tab cache is what `Registry.auto_register_custom_permission/1`
    # writes at init for a tab carrying BOTH `live_view:` and `permission:`.
    Permissions.cache_custom_view_permission(@custom_mapped_view, "media")
    on_exit(fn -> Permissions.clear_custom_keys() end)
    :ok
  end

  defp scope(roles, permissions) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000aa", email: "nav@example.com"},
      authenticated?: true,
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  # Mirrors `Scope.for_user/1`: an Owner caches every key that exists.
  defp owner_scope, do: scope(["Owner"], Permissions.all_module_keys())

  defp admin_baseline do
    MapSet.difference(
      Permissions.enabled_module_keys(),
      MapSet.new(Permissions.admin_baseline_exclusions())
    )
  end

  defp admin_scope, do: scope(["Admin"], admin_baseline())

  # Authenticated, holds a narrow key, no operator keys — passes the
  # admin-area gate but almost nothing else.
  defp client_scope, do: scope(["Client"], ["client_portal"])

  # Authenticated with no permission rows whatsoever: the visitor `/admin` now
  # has to admit.
  defp plain_user_scope, do: scope(["User"], [])

  defp tab(id, attrs) do
    Tab.new!(
      Keyword.merge(
        [id: id, label: to_string(id), path: to_string(id), priority: 500, level: :admin],
        attrs
      )
    )
  end

  describe "an Owner and an Admin see an unchanged menu" do
    # "Before" is the input list itself: until this change the sidebar rendered
    # precisely what the registry handed it, so an identity result IS the
    # before/after comparison.
    test "every core admin entry survives for an Owner, in the same order" do
      before_entries = AdminTabs.default_tabs()

      assert AdminSidebar.reachable_tabs(before_entries, owner_scope()) == before_entries
    end

    test "every core admin entry survives for a default Admin, in the same order" do
      before_entries = AdminTabs.default_tabs()

      assert AdminSidebar.reachable_tabs(before_entries, admin_scope()) == before_entries
    end

    test "the core entry set is why: not one of them names a live_view" do
      # The new per-entry gate only engages on `live_view:`. Core declares its
      # admin routes in the router, so the filter is a structural no-op over
      # core — which is what makes the two identity assertions above robust
      # rather than a coincidence of the Owner's key set.
      assert Enum.all?(AdminTabs.default_tabs(), &is_nil(&1.live_view))
    end

    test "a live_view entry an operator can open is kept" do
      entries = [
        tab(:reach_core, live_view: {@mapped_view, :index}, permission: "users"),
        tab(:reach_custom, live_view: {@custom_mapped_view, :index}, permission: "media"),
        tab(:reach_unmapped, live_view: {@unmapped_view, :index})
      ]

      assert AdminSidebar.reachable_tabs(entries, owner_scope()) == entries
      assert AdminSidebar.reachable_tabs(entries, admin_scope()) == entries
    end
  end

  describe "a visitor with no permissions is offered nothing" do
    test "the whole core menu collapses to an empty list" do
      assert AdminSidebar.reachable_tabs(AdminTabs.default_tabs(), plain_user_scope()) == []
    end

    test "entries carrying no permission key collapse too" do
      # These are the ones the registry's own `permission_granted?/2` waves
      # through: `Tab.permission_granted?(%Tab{permission: nil}, _)` is `true`.
      # The personal notification tabs are the real instance of the shape —
      # their pages live under `/admin`, so the area gate bounces this visitor
      # off them as surely as off `/admin/users`.
      entries = [
        tab(:reach_no_permission, []),
        tab(:reach_personal, personal: true),
        tab(:reach_visible_fn, visible: fn _scope -> true end)
      ]

      assert AdminSidebar.reachable_tabs(entries, plain_user_scope()) == []
    end

    test "a nil scope is refused, where before it disabled filtering entirely" do
      # `Registry.get_tabs/1` skips permission filtering when scope is nil
      # (`maybe_filter_permission(tabs, nil)`), i.e. an unknown viewer used to
      # get the COMPLETE admin menu. Fail closed instead.
      assert AdminSidebar.reachable_tabs(AdminTabs.default_tabs(), nil) == []
    end

    test "the component renders no navigation landmark at all" do
      html =
        render_component(&AdminSidebar.admin_sidebar/1,
          current_path: "/admin",
          scope: plain_user_scope(),
          locale: "en"
        )

      refute html =~ "<nav"
      refute html =~ "Admin navigation"
      assert String.trim(html) == ""
    end
  end

  describe "a partial role keeps only what it can open" do
    test "a mapped live_view entry follows its permission key" do
      entries = [
        tab(:reach_core, live_view: {@mapped_view, :index}, permission: "users"),
        tab(:reach_custom, live_view: {@custom_mapped_view, :index}, permission: "media")
      ]

      kept = AdminSidebar.reachable_tabs(entries, scope(["Editor"], ["media"]))

      assert Enum.map(kept, & &1.id) == [:reach_custom]
    end

    test "an UNMAPPED live_view entry is hidden from everyone but a full-access scope" do
      # The defect this closes: a tab naming a view with no permission key is
      # `permission: nil`, so the registry rendered it for every visitor, while
      # `:phoenix_kit_ensure_admin` treats the view as unmapped and admits only
      # a scope holding every enabled permission.
      entries = [tab(:reach_unmapped, live_view: {@unmapped_view, :index})]

      assert AdminSidebar.reachable_tabs(entries, owner_scope()) == entries
      assert AdminSidebar.reachable_tabs(entries, admin_scope()) == entries
      assert AdminSidebar.reachable_tabs(entries, scope(["Support"], ["*"])) == entries

      assert AdminSidebar.reachable_tabs(entries, client_scope()) == []
      assert AdminSidebar.reachable_tabs(entries, scope(["Editor"], ["users", "media"])) == []
    end

    test "an entry with no live_view is left to the registry's own filtering" do
      # `reachable_tabs/2` must not start guessing at tabs it cannot resolve —
      # the registry has already applied `:permission` and `:visible` by then,
      # and re-deriving a gate here is exactly the drift this design avoids.
      entries = [tab(:reach_plain, permission: "users"), tab(:reach_bare, [])]

      assert AdminSidebar.reachable_tabs(entries, client_scope()) == entries
    end
  end

  # An empty menu must not leave its furniture behind: a 16rem sidebar column
  # with nothing in it, and a burger button opening an empty drawer, read as a
  # broken page rather than a deliberate one.
  describe "the admin chrome collapses around an empty menu" do
    defp admin_body do
      assigns = %{__changed__: nil}

      ~H"""
      <span id="the-body">PK_ADMIN_BODY</span>
      """
    end

    defp render_admin_shell(scope) do
      assigns = %{
        __changed__: nil,
        scope: scope,
        inner_block: [%{inner_block: fn _slot, _idx -> admin_body() end}]
      }

      ~H"""
      <LayoutWrapper.app_layout
        flash={%{}}
        current_path="/admin"
        phoenix_kit_current_scope={@scope}
      >
        {render_slot(@inner_block)}
      </LayoutWrapper.app_layout>
      """
      |> rendered_to_string()
    end

    test "a visitor with no permissions gets the page and the header, and no sidebar" do
      html = render_admin_shell(plain_user_scope())

      # No navigation furniture...
      refute html =~ ~s|id="pk-admin-sidebar"|
      refute html =~ "<aside"
      refute html =~ ~s|aria-label="Admin navigation"|
      refute html =~ ~s|<label for="admin-mobile-menu" class="btn|
      # ...and no reserved column for it either: `lg:drawer-open` would hold a
      # `max-content` grid track open around nothing.
      assert html =~ ~s|id="admin-drawer" class="drawer |
      refute html =~ "lg:drawer-open\""

      # What IS theirs stays: the page, the theme switcher, their own account
      # menu and sign-out.
      assert html =~ "PK_ADMIN_BODY"
      assert html =~ "admin-theme-dropdown"
      assert html =~ "Log out"
    end

    test "an operator still gets the full drawer" do
      # The registry is not booted in core's unit environment, so the menu is
      # empty here (and `get_tabs/1` says so on the log) — the chrome is what
      # this asserts, and it is decided by the scope, not by the tab count.
      {html, _log} = with_log(fn -> render_admin_shell(admin_scope()) end)

      assert html =~ ~s|id="pk-admin-sidebar"|
      assert html =~ "<aside"
      assert html =~ ~s|id="admin-drawer" class="drawer lg:drawer-open"|
      assert html =~ ~s|<label for="admin-mobile-menu" class="btn|
      assert html =~ "PK_ADMIN_BODY"
    end
  end

  # The sidebar is not the only place the shell points at `/admin`: the
  # notifications bell's footer links straight to the inbox.
  describe "the notifications bell's \"View all\" footer" do
    defp render_bell(can_open_inbox?) do
      %{
        __changed__: nil,
        user_uuid: "0193a5e4-0000-7000-8000-0000000000cc",
        locale: "en",
        unread_count: 0,
        recent: [],
        default_link: nil,
        can_open_inbox: can_open_inbox?
      }
      |> NotificationsBell.render()
      |> rendered_to_string()
    end

    test "is offered when the recipient can open the inbox" do
      html = render_bell(true)

      assert html =~ "View all"
      assert html =~ "/admin/notifications"
    end

    test "is dropped — strip and all — when the inbox would reject them" do
      html = render_bell(false)

      refute html =~ "View all"
      refute html =~ "/admin/notifications"
      # The bordered footer rule must go with it, not linger over nothing.
      refute html =~ "border-t border-base-200 p-2"
      # The bell itself still shows the recipient their own notifications.
      assert html =~ "Notifications"
    end
  end
end
