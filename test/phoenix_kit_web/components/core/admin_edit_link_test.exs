defmodule PhoenixKitWeb.Components.Core.AdminEditLinkTest do
  @moduledoc """
  Renderer half of the "Edit link on public pages" feature. It reads whatever
  `PhoenixKitWeb.AdminEditHelper.assign_admin_edit/3` assigned and renders
  nothing when there is no URL — a host wires this up unconditionally in its
  public layout, so the no-`url` case (guest, non-admin, ungated page) has to
  produce zero markup, not an empty shell.

  DB-free: this component takes plain assigns, no scope/context needed.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest, only: [render_component: 2]

  alias PhoenixKitWeb.Components.Core.AdminEditLink

  test "no url: renders nothing" do
    html =
      render_component(&AdminEditLink.admin_edit_link/1, %{
        url: nil,
        label: nil,
        variant: :button,
        class: nil
      })

    assert String.trim(html) == ""
  end

  test "button variant: renders a link with the button classes, icon, and given label" do
    html =
      render_component(&AdminEditLink.admin_edit_link/1, %{
        url: "/admin/posts/1/edit",
        label: "Edit Post",
        variant: :button,
        class: nil
      })

    assert html =~ ~s(href="/admin/posts/1/edit")
    assert html =~ "btn btn-sm btn-outline"
    assert html =~ "hero-pencil-square"
    assert html =~ "Edit Post"
  end

  test "button variant: nil label falls back to gettext \"Edit\"" do
    html =
      render_component(&AdminEditLink.admin_edit_link/1, %{
        url: "/admin/posts/1/edit",
        label: nil,
        variant: :button,
        class: nil
      })

    assert html =~ "Edit"
  end

  test "menu_item variant: renders a daisyUI menu <li> with the link inside" do
    html =
      render_component(&AdminEditLink.admin_edit_link/1, %{
        url: "/admin/posts/1/edit",
        label: "Edit Post",
        variant: :menu_item,
        class: nil
      })

    assert html =~ "<li>"
    assert html =~ ~s(href="/admin/posts/1/edit")
    assert html =~ "flex items-center gap-3"
    assert html =~ "hero-pencil-square"
    assert html =~ "Edit Post"
  end

  test "extra class is appended, not replacing the base classes" do
    html =
      render_component(&AdminEditLink.admin_edit_link/1, %{
        url: "/admin/posts/1/edit",
        label: "Edit",
        variant: :button,
        class: "ml-2"
      })

    assert html =~ "btn btn-sm btn-outline"
    assert html =~ "ml-2"
  end
end
