defmodule PhoenixKitWeb.AdminEditHelperTest do
  @moduledoc """
  `assign_admin_edit/3` is the public producer API a host LiveView or a
  module's own controller/LiveView calls to say "this public page's edit
  target is `path`". It has to behave the same for `Plug.Conn` and
  `Phoenix.LiveView.Socket`, keep accepting a bare string label (every
  existing caller, including publishing, passes one), and additionally gate
  on a per-module permission key when the caller opts into one — an admin
  who can only see Publishing must not get an Edit link into Ecommerce.

  DB-free: scopes are literal structs, the pattern used across
  `test/phoenix_kit_web/components/*_test.exs`.
  """
  use ExUnit.Case, async: true

  alias PhoenixKit.Users.Auth.{Scope, User}
  alias PhoenixKitWeb.AdminEditHelper

  defp scope(roles, permissions) do
    %Scope{
      user: %User{uuid: "0193a5e4-0000-7000-8000-0000000000e1", email: "editor@example.com"},
      authenticated?: true,
      cached_roles: roles,
      cached_permissions: MapSet.new(permissions)
    }
  end

  defp admin_scope(permissions \\ []), do: scope(["Admin"], permissions)
  defp plain_user_scope, do: scope(["User"], [])

  defp conn(scope) do
    %Plug.Conn{assigns: %{phoenix_kit_current_scope: scope}}
  end

  defp socket(scope) do
    %Phoenix.LiveView.Socket{
      assigns: %{phoenix_kit_current_scope: scope, __changed__: %{}}
    }
  end

  describe "Plug.Conn — no permission key required" do
    test "no scope assigned: conn returned untouched" do
      result = AdminEditHelper.assign_admin_edit(%Plug.Conn{assigns: %{}}, "/admin/posts/1/edit")

      refute Map.has_key?(result.assigns, :admin_edit_url)
      refute Map.has_key?(result.assigns, :admin_edit_label)
    end

    test "non-admin scope: conn returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(conn(plain_user_scope()), "/admin/posts/1/edit")

      refute Map.has_key?(result.assigns, :admin_edit_url)
      refute Map.has_key?(result.assigns, :admin_edit_label)
    end

    test "admin scope, default label: assigns url and the gettext default label" do
      result = AdminEditHelper.assign_admin_edit(conn(admin_scope()), "/admin/posts/1/edit")

      assert result.assigns.admin_edit_url == "/admin/posts/1/edit"
      assert result.assigns.admin_edit_label == "Edit"
    end

    test "admin scope, string label (existing callers): assigns the given string as-is" do
      result =
        AdminEditHelper.assign_admin_edit(
          conn(admin_scope()),
          "/admin/posts/1/edit",
          "Edit Post"
        )

      assert result.assigns.admin_edit_url == "/admin/posts/1/edit"
      assert result.assigns.admin_edit_label == "Edit Post"
    end
  end

  describe "Plug.Conn — with a `permission:` key" do
    test "admin without the module permission: conn returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(
          conn(admin_scope(["publishing"])),
          "/admin/ecommerce/products/1/edit",
          permission: "ecommerce"
        )

      refute Map.has_key?(result.assigns, :admin_edit_url)
      refute Map.has_key?(result.assigns, :admin_edit_label)
    end

    test "admin with the module permission: conn gets both assigns" do
      result =
        AdminEditHelper.assign_admin_edit(
          conn(admin_scope(["ecommerce"])),
          "/admin/ecommerce/products/1/edit",
          label: "Edit Product",
          permission: "ecommerce"
        )

      assert result.assigns.admin_edit_url == "/admin/ecommerce/products/1/edit"
      assert result.assigns.admin_edit_label == "Edit Product"
    end

    test "non-admin scope with a permission key: still returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(
          conn(plain_user_scope()),
          "/admin/ecommerce/products/1/edit",
          permission: "ecommerce"
        )

      refute Map.has_key?(result.assigns, :admin_edit_url)
    end

    test "keyword opts without a permission key: only the admin-area gate applies" do
      result =
        AdminEditHelper.assign_admin_edit(
          conn(admin_scope([])),
          "/admin/posts/1/edit",
          label: "Edit Post"
        )

      assert result.assigns.admin_edit_url == "/admin/posts/1/edit"
      assert result.assigns.admin_edit_label == "Edit Post"
    end
  end

  describe "Phoenix.LiveView.Socket" do
    test "no scope assigned: socket returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(
          %Phoenix.LiveView.Socket{assigns: %{}},
          "/admin/posts/1/edit"
        )

      refute Map.has_key?(result.assigns, :admin_edit_url)
    end

    test "non-admin scope: socket returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(socket(plain_user_scope()), "/admin/posts/1/edit")

      refute Map.has_key?(result.assigns, :admin_edit_url)
    end

    test "admin without the module permission: socket returned untouched" do
      result =
        AdminEditHelper.assign_admin_edit(
          socket(admin_scope(["publishing"])),
          "/admin/ecommerce/products/1/edit",
          permission: "ecommerce"
        )

      refute Map.has_key?(result.assigns, :admin_edit_url)
    end

    test "admin with the module permission, default label: assigns both" do
      result =
        AdminEditHelper.assign_admin_edit(
          socket(admin_scope(["ecommerce"])),
          "/admin/ecommerce/products/1/edit",
          permission: "ecommerce"
        )

      assert result.assigns.admin_edit_url == "/admin/ecommerce/products/1/edit"
      assert result.assigns.admin_edit_label == "Edit"
    end

    test "admin scope, string label (existing callers): assigns the given string as-is" do
      result =
        AdminEditHelper.assign_admin_edit(
          socket(admin_scope()),
          "/admin/posts/1/edit",
          "Edit Post"
        )

      assert result.assigns.admin_edit_url == "/admin/posts/1/edit"
      assert result.assigns.admin_edit_label == "Edit Post"
    end
  end
end
