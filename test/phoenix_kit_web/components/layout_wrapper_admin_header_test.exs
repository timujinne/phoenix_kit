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

  defp admin_shell(scope) do
    assigns = %{scope: scope}

    ~H"""
    <LayoutWrapper.app_layout
      flash={%{}}
      socket={nil}
      current_path="/admin"
      page_title="Dashboard"
      project_title="Acme"
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

  test "the breadcrumb tracks the same gate as the sidebar, not the page" do
    # `show_admin_nav` is one decision: no nav, no burger, no "Admin Panel".
    plain = admin_shell(plain_user_scope())

    refute plain =~ ~s(id="pk-admin-sidebar")
    refute plain =~ "Admin Panel"

    operator = admin_shell(owner_scope())

    assert operator =~ ~s(id="pk-admin-sidebar")
    assert operator =~ "Admin Panel"
  end
end
