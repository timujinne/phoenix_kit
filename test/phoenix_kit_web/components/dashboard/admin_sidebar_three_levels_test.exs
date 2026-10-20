defmodule PhoenixKitWeb.Components.Dashboard.AdminSidebarThreeLevelsTest do
  @moduledoc """
  The admin sidebar's third level: a subtab with subtabs of its own
  (`usage-rules.md`, "Building admin pages"). A module section such as
  Projects › API keys › Keys / Usage is declared as a subtab with
  `redirect_to_first_subtab: true` and no LiveView, and two children whose
  `parent` is that subtab. This pins what the docs promise: the children are
  drawn under it while one of them is open, hidden otherwise, and the
  middle entry links to its first child.

  DB-free, like `AdminSidebarSettingsRedirectTest`: tabs are built directly
  and given their active state the way the registry would.
  """

  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [render_component: 2]

  alias PhoenixKit.Dashboard.{Tab, TabHelpers}
  alias PhoenixKitWeb.Components.Dashboard.AdminSidebar

  defp tab(attrs), do: Tab.resolve_path(struct!(Tab, Keyword.put(attrs, :level, :admin)), :admin)

  defp tabs do
    [
      tab(
        id: :demo_projects,
        label: "Projects",
        icon: "hero-folder",
        path: "demo-projects",
        priority: 600,
        match: :exact,
        subtab_display: :when_active,
        highlight_with_subtabs: false
      ),
      tab(
        id: :demo_projects_tasks,
        label: "Tasks",
        icon: "hero-check",
        path: "demo-projects/tasks",
        priority: 601,
        parent: :demo_projects
      ),
      # The middle level: a section with no page of its own.
      tab(
        id: :demo_projects_keys,
        label: "API keys",
        icon: "hero-key",
        path: "demo-projects/api-keys",
        priority: 602,
        match: :prefix,
        parent: :demo_projects,
        subtab_display: :when_active,
        redirect_to_first_subtab: true,
        highlight_with_subtabs: false
      ),
      tab(
        id: :demo_projects_keys_list,
        label: "Keys",
        icon: "hero-key",
        path: "demo-projects/api-keys/list",
        priority: 603,
        match: :exact,
        parent: :demo_projects_keys
      ),
      tab(
        id: :demo_projects_keys_usage,
        label: "Usage",
        icon: "hero-chart-bar",
        path: "demo-projects/api-keys/usage",
        priority: 604,
        match: :exact,
        parent: :demo_projects_keys
      )
    ]
  end

  defp render_at(current_path) do
    all = tabs() |> TabHelpers.add_active_state(current_path)

    render_component(&AdminSidebar.__tab_with_subtabs_for_test__/1,
      tab: Enum.find(all, &(&1.id == :demo_projects)),
      all_tabs: all,
      locale: nil
    )
  end

  # Every anchor carrying `data-tab-id="<id>"` — the inline list and the
  # compact-mode flyout each draw one.
  defp anchors(html, id) do
    ~r{<a [^>]*data-tab-id="#{id}"[^>]*>}
    |> Regex.scan(html)
    |> List.flatten()
  end

  defp lit?(anchor), do: anchor =~ ~s(aria-current="page")

  test "on a third-level page its siblings are drawn under the middle entry, the open one marked" do
    html = render_at("/admin/demo-projects/api-keys/usage")

    assert html =~ "sub-subtabs"
    assert [usage] = anchors(html, "demo_projects_keys_usage")
    assert lit?(usage)
    assert [list] = anchors(html, "demo_projects_keys_list")
    refute lit?(list)

    # The middle entry, in the list and in the flyout alike, is not lit
    # while one of its children is the open page.
    middles = anchors(html, "demo_projects_keys")
    assert length(middles) == 2
    refute Enum.any?(middles, &lit?/1)
  end

  test "the middle entry links to its first child" do
    html = render_at("/admin/demo-projects/api-keys/usage")

    for middle <- anchors(html, "demo_projects_keys") do
      assert middle =~ ~r{href="[^"]*/admin/demo-projects/api-keys/list"}
    end
  end

  test "elsewhere in the section the third level stays folded" do
    html = render_at("/admin/demo-projects/tasks")

    assert anchors(html, "demo_projects_keys") != []
    refute html =~ "sub-subtabs"
    assert anchors(html, "demo_projects_keys_usage") == []
  end
end
