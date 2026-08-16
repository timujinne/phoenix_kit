defmodule PhoenixKitWeb.Components.Core.TreeTableTest do
  @moduledoc """
  Render tests for `<.tree_name_cell>`. Pins:

  - depth indents via padding-left; root rows get no inline style
  - expandable rows render the chevron with toggle event/value/aria
  - chevron icon flips between right (collapsed) and down (expanded)
  - non-expandable rows render the aligning spacer, no button
  - optional leading icon + custom icon class
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [rendered_to_string: 1]
  import Phoenix.Component, only: [sigil_H: 2]
  import PhoenixKitWeb.Components.Core.TreeTable

  defp render_cell(assigns) do
    rendered_to_string(~H"""
    <.tree_name_cell
      depth={@depth}
      expandable={@expandable}
      expanded={@expanded}
      toggle_event="toggle_node"
      value="uuid-1"
      icon={assigns[:icon]}
      icon_class={assigns[:icon_class]}
    >
      Node name
    </.tree_name_cell>
    """)
  end

  test "root depth renders without indentation style" do
    html = render_cell(%{depth: 0, expandable: false, expanded: false})
    refute html =~ "padding-left"
    assert html =~ "Node name"
  end

  test "nested depth indents by depth * indent" do
    html = render_cell(%{depth: 2, expandable: false, expanded: false})
    assert html =~ "padding-left: calc(2 * 1.5rem)"
  end

  test "expandable collapsed row renders chevron-right with toggle wiring" do
    html = render_cell(%{depth: 0, expandable: true, expanded: false})
    assert html =~ ~s(phx-click="toggle_node")
    assert html =~ ~s(phx-value-uuid="uuid-1")
    assert html =~ ~s(aria-expanded="false")
    assert html =~ "hero-chevron-right-mini"
  end

  test "expanded row flips to chevron-down" do
    html = render_cell(%{depth: 0, expandable: true, expanded: true})
    assert html =~ ~s(aria-expanded="true")
    assert html =~ "hero-chevron-down-mini"
  end

  test "non-expandable row renders spacer and no button" do
    html = render_cell(%{depth: 0, expandable: false, expanded: false})
    refute html =~ "<button"
    assert html =~ ~s(class="w-5 shrink-0")
  end

  test "leading icon renders with default class" do
    html = render_cell(%{depth: 0, expandable: false, expanded: false, icon: "hero-folder"})
    assert html =~ "hero-folder"
    assert html =~ "w-4 h-4 shrink-0"
  end

  test "custom icon_class replaces the default" do
    html =
      render_cell(%{
        depth: 0,
        expandable: false,
        expanded: false,
        icon: "hero-folder",
        icon_class: "w-5 h-5 text-warning"
      })

    assert html =~ "w-5 h-5 text-warning"
    refute html =~ "w-4 h-4 shrink-0"
  end

  test "name content is wrapped so long labels truncate inside the flex cell" do
    html = render_cell(%{depth: 0, expandable: false, expanded: false})
    assert html =~ ~s(class="min-w-0 truncate")
    assert html =~ "Node name"
  end
end
