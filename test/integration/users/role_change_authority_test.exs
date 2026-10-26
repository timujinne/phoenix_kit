defmodule PhoenixKit.Integration.Users.RoleChangeAuthorityTest do
  @moduledoc """
  Who may give a role, take one away or delete one (`Roles.can_manage_role?/2`):
  an Owner always; anyone else only a role that is neither Owner nor Admin and
  whose every key they hold. Nobody but an Owner changes their own roles.
  Checked in the context, so every caller — and a crafted event the UI would
  never send — gets the same answer.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Utils.Routes

  defp role!(keys) do
    {:ok, role} = Roles.create_role(%{name: "Rca #{System.unique_integer([:positive])}"})
    for key <- keys, do: {:ok, _} = Permissions.grant_permission(role.uuid, key)
    role
  end

  defp user!(roles \\ []) do
    {:ok, user} =
      Auth.register_user(%{
        email: "rca-#{System.unique_integer([:positive])}@example.com",
        password: "TestPassword123!"
      })

    {:ok, user} = Auth.admin_confirm_user(user)
    for role <- roles, do: {:ok, _} = Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  defp seed_owner, do: Auth.get_user_by_email("seed-owner@phoenixkit.test")

  describe "sync_user_roles/3" do
    test "a non-Owner cannot change their own roles" do
      editor_role = role!(["users"])
      extra = role!([])
      editor = user!([editor_role])

      assert {:error, :cannot_modify_own_roles} =
               Roles.sync_user_roles(editor, [editor_role.name, extra.name, "User"],
                 actor: editor
               )

      refute Roles.user_has_role?(editor, extra.name)

      # Nor drop one.
      assert {:error, :cannot_modify_own_roles} =
               Roles.sync_user_roles(editor, ["User"], actor: editor)

      assert Roles.user_has_role?(editor, editor_role.name)
    end

    test "an unchanged submission of your own roles is not an error" do
      editor_role = role!(["users"])
      editor = user!([editor_role])

      assert {:ok, %{refused: []}} =
               Roles.sync_user_roles(editor, Roles.get_user_roles(editor), actor: editor)
    end

    test "a role holding a key the actor lacks is neither given nor taken" do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])
      target = user!()

      assert {:ok, %{refused: refused}} =
               Roles.sync_user_roles(target, ["User", wider.name], actor: editor)

      assert refused == [wider.name]
      refute Roles.user_has_role?(target, wider.name)

      holder = user!([wider])

      assert {:ok, %{refused: [_]}} = Roles.sync_user_roles(holder, ["User"], actor: editor)
      assert Roles.user_has_role?(holder, wider.name)
    end

    test "a role within the actor's keys is changed" do
      editor = user!([role!(["users", "sitemap"])])
      narrower = role!(["sitemap"])
      target = user!()

      assert {:ok, %{refused: []}} =
               Roles.sync_user_roles(target, ["User", narrower.name], actor: editor)

      assert Roles.user_has_role?(target, narrower.name)
    end

    test ~S(a role holding "*" needs "*") do
      editor = user!([role!(Permissions.enabled_module_keys() |> MapSet.to_list())])
      super_role = role!(["*"])
      target = user!()

      assert {:ok, %{refused: [_]}} =
               Roles.sync_user_roles(target, ["User", super_role.name], actor: editor)

      refute Roles.user_has_role?(target, super_role.name)

      assert {:ok, %{refused: []}} =
               Roles.sync_user_roles(target, ["User", super_role.name], actor: seed_owner())

      assert Roles.user_has_role?(target, super_role.name)
    end

    test "system callers stay unrestricted" do
      wide = role!(["users", "sitemap", "settings"])
      target = user!()

      assert {:ok, %{refused: []}} = Roles.sync_user_roles(target, ["User", wide.name])
      assert Roles.user_has_role?(target, wide.name)
    end
  end

  describe "assign_role/4 and remove_role/3 with an actor" do
    test "apply the same rules" do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])
      target = user!()

      assert {:error, :not_permitted} =
               Roles.assign_role(target, wider.name, editor, actor: editor)

      refute Roles.user_has_role?(target, wider.name)

      {:ok, _} = Roles.assign_role(target, wider.name)
      assert {:error, :not_permitted} = Roles.remove_role(target, wider.name, actor: editor)
      assert Roles.user_has_role?(target, wider.name)

      assert {:error, :cannot_modify_own_roles} =
               Roles.assign_role(editor, role!([]).name, editor, actor: editor)
    end
  end

  describe "promote_to_admin/3, demote_to_user/2, safely_remove_role/3 with an actor" do
    test "only an Owner actor gives or takes Admin" do
      editor = user!([role!(["users"])])
      target = user!()

      assert {:error, :not_permitted} = Roles.promote_to_admin(target, editor, actor: editor)
      refute Roles.user_has_role?(target, "Admin")

      assert {:ok, _} = Roles.promote_to_admin(target, nil, actor: seed_owner())
      assert {:error, :not_permitted} = Roles.demote_to_user(target, actor: editor)
      assert {:error, :not_permitted} = Roles.safely_remove_role(target, "Admin", actor: editor)
      assert Roles.user_has_role?(target, "Admin")

      assert {:ok, _} = Roles.demote_to_user(target, actor: seed_owner())
      refute Roles.user_has_role?(target, "Admin")
    end
  end

  describe "a failed read of a role's keys refuses" do
    test "a role whose keys cannot be read is not manageable" do
      editor = user!([role!(["users"])])

      # A uuid the database rejects: the old reader answered [] for it (an
      # empty role, so any actor passed the subset check).
      broken = %PhoenixKit.Users.Role{uuid: "not-a-uuid", name: "Broken", is_system_role: false}

      assert Permissions.get_permissions_for_role("not-a-uuid") == []
      assert {:error, _} = Permissions.fetch_permissions_for_role("not-a-uuid")
      refute Roles.can_manage_role?(editor, broken)
      assert Roles.can_manage_role?(seed_owner(), broken)
    end
  end

  describe "delete_role/2" do
    test "needs every key of the role; an Owner always may" do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])

      assert {:error, :not_permitted} = Roles.delete_role(wider, actor: editor)
      assert Roles.get_role_by_uuid(wider.uuid)

      narrower = role!(["users"])
      assert {:ok, _} = Roles.delete_role(narrower, actor: editor)
      assert {:ok, _} = Roles.delete_role(wider, actor: seed_owner())
    end

    test "the Roles page refuses a crafted delete", %{conn: conn} do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])

      {:ok, view, _} = live(log_in_user(conn, editor), Routes.path("/admin/users/roles"))

      html = render_click(view, "delete_role", %{"role_uuid" => to_string(wider.uuid)})

      assert html =~ "You can only delete a role whose permissions you hold yourself"
      assert Roles.get_role_by_uuid(wider.uuid)
    end
  end

  describe "the role modals" do
    test "user details refuses a crafted change of your own roles", %{conn: conn} do
      editor_role = role!(["users"])
      editor = user!([editor_role])
      extra = role!([])

      {:ok, view, _} =
        live(log_in_user(conn, editor), Routes.path("/admin/users/view/#{editor.uuid}"))

      html =
        render_submit(view, "sync_user_roles", %{
          "roles" => %{"a" => editor_role.name, "b" => extra.name, "c" => "User"}
        })

      assert html =~ "Cannot modify your own roles"
      refute Roles.user_has_role?(editor, extra.name)
    end

    test "user details says when a role was refused", %{conn: conn} do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])
      target = user!()

      {:ok, view, _html} =
        live(log_in_user(conn, editor), Routes.path("/admin/users/view/#{target.uuid}"))

      # The modal renders the role locked.
      assert render_click(view, "show_role_management", %{}) =~
               "You can only give roles whose permissions you hold"

      html =
        render_submit(view, "sync_user_roles", %{
          "roles" => %{"a" => "User", "b" => wider.name}
        })

      assert html =~ "you can only give or take away roles whose permissions you hold"
      refute Roles.user_has_role?(target, wider.name)
    end

    test "the users list refuses a crafted grant", %{conn: conn} do
      editor = user!([role!(["users"])])
      wider = role!(["users", "sitemap"])
      target = user!()

      {:ok, view, _} = live(log_in_user(conn, editor), Routes.path("/admin/users"))
      render_click(view, "show_role_management", %{"user_uuid" => target.uuid})

      html =
        render_submit(view, "sync_user_roles", %{"roles" => %{"a" => "User", "b" => wider.name}})

      assert html =~ "you can only give or take away roles whose permissions you hold"
      refute Roles.user_has_role?(target, wider.name)
    end
  end
end
