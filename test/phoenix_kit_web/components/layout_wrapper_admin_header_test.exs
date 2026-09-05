defmodule PhoenixKitWeb.Components.LayoutWrapperAdminHeaderTest do
  @moduledoc """
  The admin shell's header, for the visitor it was never written for.

  `/admin` is the landing page EVERY authenticated user can reach, so this
  chrome now renders for people who hold no permissions at all: no sidebar, no
  burger button, no page subtitle. The breadcrumb has to agree with the rest of
  it — telling someone with none of that that they are in the "Admin Panel" is
  the one claim left on the page that would be false.

  DB-free: both scopes are literal structs and every setting the layout reads is
  passed in as an assign.
  """
  use ExUnit.Case, async: false

  import Phoenix.Component, only: [sigil_H: 2]
  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Permissions
  alias PhoenixKitWeb.Components.LayoutWrapper

  defp scope(roles, permissions) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000d1", email: "head@example.com"},
      authenticated?: true,
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  defp plain_user_scope, do: scope(["User"], [])
  defp owner_scope, do: scope(["Owner"], Permissions.all_module_keys())

  defp admin_shell(scope, opts \\ []) do
    assigns = %{scope: scope, show_label: Keyword.get(opts, :show_admin_panel_label)}

    ~H"""
    <LayoutWrapper.app_layout
      flash={%{}}
      socket={nil}
      current_path="/admin"
      page_title="Dashboard"
      project_title="Acme"
      show_admin_panel_label={@show_label}
      phoenix_kit_current_scope={@scope}
    >
      <span id="pk-test-body">body</span>
    </LayoutWrapper.app_layout>
    """
    |> rendered_to_string()
  end

  test "an operator still sees the Admin Panel breadcrumb" do
    html = admin_shell(owner_scope())

    assert html =~ "Admin Panel"
    assert html =~ "Dashboard"
  end

  test "a visitor with no admin rights is not told they are in the Admin Panel" do
    html = admin_shell(plain_user_scope())

    refute html =~ "Admin Panel"
  end

  test "they still get a breadcrumb — the project title and the page" do
    # Omission, not a blank header: what remains is the ordinary
    # "project / page" trail the same markup already builds, so no new msgid
    # ships untranslated to do it.
    html = admin_shell(plain_user_scope())

    assert html =~ "Acme"
    assert html =~ "Dashboard"
  end

  test "page_crumbs render between the section and the title, linked when given a path" do
    assigns = %{scope: owner_scope()}

    html =
      ~H"""
      <LayoutWrapper.app_layout
        flash={%{}}
        socket={nil}
        current_path="/admin"
        page_title="Copper"
        page_section="Catalogues"
        page_section_path="/admin/catalogue"
        page_crumbs={[
          %{label: "Plumbing", path: "/admin/catalogue/c1"},
          %{label: "Unlinked"}
        ]}
        project_title="Acme"
        phoenix_kit_current_scope={@scope}
      >
        <span id="pk-test-body">body</span>
      </LayoutWrapper.app_layout>
      """
      |> rendered_to_string()

    assert html =~ ~s(href="/admin/catalogue/c1")
    assert html =~ "Plumbing"
    # A crumb without :path renders as plain text, not a link.
    assert html =~ "Unlinked"
    refute html =~ ~s(href="Unlinked")
    # The LAST crumb survives below sm (trail truncates from the left);
    # earlier crumbs collapse with the rest of the prefix.
    assert html =~ "items-center gap-1.5 min-w-0 flex"
    assert html =~ "hidden sm:flex shrink-0"
    # Order: section before crumbs before title — checked inside the top
    # bar's breadcrumb (anchored past "Admin Panel"; the drawer markup
    # earlier in the document also mentions the page title).
    {admin_at, _} = :binary.match(html, "Admin Panel")
    header = binary_part(html, admin_at, byte_size(html) - admin_at)
    catalogues_at = :binary.match(header, "Catalogues") |> elem(0)
    plumbing_at = :binary.match(header, "Plumbing") |> elem(0)
    copper_at = :binary.match(header, "Copper") |> elem(0)
    assert catalogues_at < plumbing_at and plumbing_at < copper_at
  end

  # A page's own toolbar: `{Module, :fun}` rendered with the LiveView's
  # assigns — this is what a plugin LiveView (which cannot pass a slot
  # through `layouts/admin.html.heex`) uses for a status picker or its ⋮.
  defmodule ToolbarPage do
    use Phoenix.Component

    def header_toolbar(assigns) do
      ~H"""
      <form id="pk-test-status" phx-change="change_status">
        <select name="status"><option>{@status}</option></select>
      </form>
      <button id="pk-test-menu" phx-click="open_menu">⋮</button>
      """
    end
  end

  test "the :toolbar slot renders beside the title, before the action chip" do
    assigns = %{scope: owner_scope()}

    html =
      ~H"""
      <LayoutWrapper.app_layout
        flash={%{}}
        socket={nil}
        current_path="/admin"
        page_title="Copper"
        page_action={%{icon: "hero-plus", label: "New", navigate: "/admin/new"}}
        project_title="Acme"
        phoenix_kit_current_scope={@scope}
      >
        <:toolbar><span id="pk-test-toolbar">tool</span></:toolbar>
        <span id="pk-test-body">body</span>
      </LayoutWrapper.app_layout>
      """
      |> rendered_to_string()

    {admin_at, _} = :binary.match(html, "Admin Panel")
    header = binary_part(html, admin_at, byte_size(html) - admin_at)
    title_at = :binary.match(header, "Copper") |> elem(0)
    toolbar_at = :binary.match(header, "pk-test-toolbar") |> elem(0)
    action_at = :binary.match(header, ~s(href="/admin/new")) |> elem(0)
    assert title_at < toolbar_at and toolbar_at < action_at
    # The toolbar is rendered as given — the chip shell is the action's only.
    refute binary_part(header, toolbar_at - 120, 120) =~ "[&>*]:btn"
  end

  test "render_page_toolbar/1 renders {Module, :fun} with the page's assigns, nil without one" do
    rendered =
      LayoutWrapper.render_page_toolbar(%{
        page_toolbar: {ToolbarPage, :header_toolbar},
        status: "In progress",
        __changed__: nil
      })

    html = rendered_to_string(rendered)
    assert html =~ ~s(id="pk-test-status")
    assert html =~ ~s(phx-change="change_status")
    assert html =~ "In progress"
    assert html =~ ~s(phx-click="open_menu")

    assert LayoutWrapper.render_page_toolbar(%{page_title: "x"}) == nil
  end

  test "the REAL admin layout carries page_toolbar into the header (the plugin path)" do
    # `layouts/admin.html.heex` is the only thing a plugin LiveView can reach;
    # the module's fixture layout is a stand-in. Render the real one with a
    # LiveView-shaped assigns map, as Phoenix does, and find the toolbar in
    # the header — before the page body. The sweep, 2026-09-05.
    html =
      PhoenixKitWeb.Layouts.admin(%{
        socket: nil,
        flash: %{},
        inner_content: {:safe, ~s(<div id="pk-test-body">body</div>)},
        phoenix_kit_current_scope: owner_scope(),
        current_path: "/admin/projects/1",
        page_title: "Copper",
        project_title: "Acme",
        page_toolbar: {ToolbarPage, :header_toolbar},
        status: "In progress",
        __changed__: nil
      })
      |> rendered_to_string()

    toolbar_at = :binary.match(html, "pk-test-status") |> elem(0)
    body_at = :binary.match(html, "pk-test-body") |> elem(0)
    assert toolbar_at < body_at
    assert html =~ ~s(phx-change="change_status")
    assert html =~ ~s(phx-click="open_menu")
    assert html =~ "In progress"
  end

  test "a page_toolbar naming no function renders no toolbar rather than raising" do
    import ExUnit.CaptureLog

    log =
      capture_log(fn ->
        assert LayoutWrapper.render_page_toolbar(%{
                 page_toolbar: {ToolbarPage, :no_such_fun},
                 __changed__: nil
               }) == nil
      end)

    assert log =~ "no_such_fun/1 is not a function component"
  end

  test "a page_crumb with patch is a same-LiveView link, not a navigate" do
    assigns = %{scope: owner_scope()}

    html =
      ~H"""
      <LayoutWrapper.app_layout
        flash={%{}}
        socket={nil}
        current_path="/admin"
        page_title="Pipes"
        page_section="Catalogues"
        page_section_path="/admin/catalogue"
        page_crumbs={[%{label: "Plumbing", patch: "/admin/catalogue/c1"}]}
        project_title="Acme"
        phoenix_kit_current_scope={@scope}
      >
        <span id="pk-test-body">body</span>
      </LayoutWrapper.app_layout>
      """
      |> rendered_to_string()

    assert html =~ ~s(href="/admin/catalogue/c1")
    assert html =~ ~s(data-phx-link="patch")
    assert html =~ "Plumbing"
  end

  test "the breadcrumb tracks the same gate as the sidebar, not the page" do
    # `show_admin_nav` is one decision: no nav, no burger, no "Admin Panel".
    plain = admin_shell(plain_user_scope())

    refute plain =~ ~s(id="pk-admin-sidebar")
    refute plain =~ "Admin Panel"

    operator = admin_shell(owner_scope())

    assert operator =~ ~s(id="pk-admin-sidebar")
    assert operator =~ "Admin Panel"
  end

  describe "the sidebar compact toggle" do
    # Compact mode is entirely client-side: `localStorage` + a `data-pk-sidebar`
    # stamp on <html>, with CSS doing the hiding. So what the server owes is
    # exactly the handles that machinery reads — and those are what is asserted
    # here, because a CSS selector that no longer matches anything fails
    # silently in a way no render test would otherwise catch.

    test "an operator gets the toggle" do
      html = admin_shell(owner_scope())

      assert html =~ "data-pk-sidebar-toggle"
      assert html =~ "pk-sidebar-toggle"
    end

    test "the pre-paint stamp ships above the sidebar markup" do
      # Order is the whole point: the script must run before the menu is
      # parsed, or a viewer who chose compact sees a frame of the full-width
      # sidebar on every load.
      html = admin_shell(owner_scope())

      stamp = :binary.match(html, "__pkSidebarCompact") |> elem(0)
      sidebar = :binary.match(html, ~s(id="pk-admin-sidebar")) |> elem(0)

      assert stamp < sidebar
    end

    test "the shell renders the handles the compact styles select on" do
      # Only the shell's own handles here — the Dashboard Registry is not
      # started in this DB-free run, so there are no tabs to carry the
      # per-item ones. Those live in TabItemTest, against a literal Tab.
      html = admin_shell(owner_scope())

      assert html =~ "pk-sidebar "
      assert html =~ "pk-sidebar-label"
      assert html =~ "pk-sidebar-toggle-icon"
    end

    test "labels are rendered, not omitted — CSS hides them" do
      # Compact mode has no server round-trip, so the label has to be in the
      # DOM for CSS to hide it. It is also what keeps the link's accessible
      # name intact while collapsed.
      html = admin_shell(owner_scope())

      assert html =~ "pk-sidebar-label"

      # And the server never stamps the state itself — that is the client's
      # job, pre-paint. Checked on the <html> OPEN TAG specifically: the
      # attribute name also appears throughout the stylesheet's selectors, so
      # a whole-document match would pass for the wrong reason.
      [open_tag | _] = String.split(html, ">", parts: 2)
      refute open_tag =~ "data-pk-sidebar"
    end

    test "a visitor with no admin rights gets neither sidebar nor toggle" do
      html = admin_shell(plain_user_scope())

      refute html =~ ~s(id="pk-admin-sidebar")
      refute html =~ "data-pk-sidebar-toggle"
    end
  end

  describe "compact-mode stylesheet" do
    # These guard a bug that shipped: the flyout's label overrides were written
    # without the `html[data-pk-sidebar="compact"]` prefix, read (1,2,0) against
    # the rail's own (1,2,1) hiding rule, and lost — so the flyout rendered as a
    # column of anonymous icons, which is the one thing it exists to prevent.
    # The `@media` block the rail rules live in contributes NO specificity, so
    # the prefix is the only thing separating them.

    defp compact_css do
      html = admin_shell(owner_scope())
      [_, rest] = String.split(html, "<style data-phoenix-kit-sidebar>", parts: 2)
      [css, _] = String.split(rest, "</style>", parts: 2)
      css
    end

    test "every flyout override outranks the rail rule it has to beat" do
      for line <- String.split(compact_css(), "\n"),
          String.contains?(line, ".pk-sidebar-flyout"),
          String.contains?(line, "{") do
        assert String.starts_with?(String.trim(line), ~s(html[data-pk-sidebar="compact"])),
               """
               Flyout override without the compact prefix — it will lose on \
               specificity to the rail rule and the flyout will show icons \
               with no text:

                 #{String.trim(line)}
               """
      end
    end

    test "the flyout un-hides the labels the rail hides" do
      css = compact_css()

      assert css =~ ".pk-sidebar-flyout .pk-sidebar-label"
      assert css =~ "clip-path: none"
    end

    test "the collapsed rail marks the section you are in" do
      # Expanded, the highlight sits on the active subtab; collapsed, that row
      # is hidden, so without this nothing is marked at all.
      assert compact_css() =~ ~s([data-pk-branch-active="true"])
    end

    test "the rail marks with an edge bar, not the expanded menu's filled block" do
      css = compact_css()

      # A solid primary slab is most of a 5rem row — it reads as a state
      # rather than a marker.
      assert css =~ ~s(> a[aria-current="page"]::after)
      assert css =~ ~s([data-pk-branch-active="true"] > a::after)
    end

    test "the bar is backed by a light tint, with a plain-transparent fallback" do
      css = compact_css()

      # `transparent` FIRST: it cancels the `bg-primary` utility and is what a
      # browser without `color-mix` keeps — the bar-only rendering, which is a
      # correct result rather than a broken one.
      transparent = :binary.match(css, "background-color: transparent") |> elem(0)
      tint = :binary.match(css, "color-mix(in oklab, var(--color-primary) 12%") |> elem(0)

      assert transparent < tint
    end

    test "the tint is primary-based, so it stays distinct from hover" do
      # daisyUI hovers rows with `base-200`; a neutral tint at this weight
      # would be indistinguishable, and the row would stop saying which page
      # you are on the moment the pointer crossed it.
      css = compact_css()

      refute css =~ "background-color: var(--color-base-200)"
      assert css =~ ~s(> a[aria-current="page"]:hover)
    end

    test "the edge bar never reaches inside the flyout" do
      # `.tab-with-subtabs > a` is a direct-child combinator on purpose: the
      # flyout's links are descendants of the same sidebar, and there the
      # ordinary filled highlight is the right thing.
      # Selector lines only — `[aria-current` with the bracket, which the
      # prose in the comment above the rule does not have.
      for line <- String.split(compact_css(), "\n"),
          String.contains?(line, "[aria-current"),
          String.contains?(line, "#pk-admin-sidebar") do
        assert String.contains?(line, ".tab-with-subtabs > a")
      end
    end
  end

  describe "the show_admin_panel_label setting" do
    # An operator switch, deliberately show/hide rather than a title field: the
    # WORDING stays `gettext("Admin Panel")`, which ships translated in every
    # locale. A stored string would serve one operator's language to everyone.

    test "an operator keeps the label by default" do
      # `nil` means "read the setting", and with no row (and no database in
      # this run) `get_boolean_setting/2` answers with its `true` default —
      # so every existing install is unchanged.
      assert admin_shell(owner_scope()) =~ "Admin Panel"
    end

    test "turning it off drops the label" do
      html = admin_shell(owner_scope(), show_admin_panel_label: false)

      refute html =~ "Admin Panel"
    end

    test "turning it off leaves the rest of the breadcrumb intact" do
      # Hiding the chip must not cost the trail around it — the project name
      # and the page title are what the header is actually for.
      html = admin_shell(owner_scope(), show_admin_panel_label: false)

      assert html =~ "Acme"
      assert html =~ "Dashboard"
    end

    test "it does not touch the sidebar" do
      # Distinct from `show_admin_nav`, which is a PERMISSION verdict. An
      # operator who hides the chip is still an operator.
      html = admin_shell(owner_scope(), show_admin_panel_label: false)

      assert html =~ ~s(id="pk-admin-sidebar")
    end

    test "turning it on cannot show it to a visitor with no admin rights" do
      # The permission gate wins over the preference. Telling someone with no
      # sidebar and no operator content that they are in the "Admin Panel" is
      # the one claim on the page that would be false, setting or not.
      html = admin_shell(plain_user_scope(), show_admin_panel_label: true)

      refute html =~ "Admin Panel"
    end
  end
end
