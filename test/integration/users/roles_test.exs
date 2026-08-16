defmodule PhoenixKit.Integration.Users.RolesTest do
  use PhoenixKit.DataCase, async: true

  # These tests assert BOOTSTRAP semantics (first-user-becomes-Owner, last-
  # Owner guards, owner counts), so the suite's committed seed Owner is
  # demoted inside this test's own sandbox transaction — see DataCase.
  setup :demote_seed_owner

  alias PhoenixKit.RepoHelper
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Role
  alias PhoenixKit.Users.Roles

  defp unique_email, do: "roles_#{System.unique_integer([:positive])}@example.com"

  defp create_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    user
  end

  # Create two users so first gets Owner, second gets User role
  defp create_standard_user do
    _owner = create_user()
    create_user()
  end

  describe "list_roles/0" do
    test "returns system roles from migrations" do
      roles = Roles.list_roles()
      role_names = Enum.map(roles, & &1.name)

      assert "Owner" in role_names
      assert "Admin" in role_names
      assert "User" in role_names
    end

    test "system roles are flagged" do
      roles = Roles.list_roles()

      Enum.each(roles, fn role ->
        if role.name in ["Owner", "Admin", "User"] do
          assert role.is_system_role
        end
      end)
    end
  end

  describe "assign_role/4" do
    test "assigns Admin role to user" do
      user = create_standard_user()

      assert {:ok, _assignment} = Roles.assign_role(user, "Admin")
      assert Roles.user_has_role?(user, "Admin")
    end

    test "prevents manual Owner role assignment" do
      user = create_standard_user()

      assert {:error, :owner_role_protected} = Roles.assign_role(user, "Owner")
    end

    test "is idempotent - assigning same role twice succeeds" do
      user = create_standard_user()

      assert {:ok, _} = Roles.assign_role(user, "Admin")
      assert {:ok, _} = Roles.assign_role(user, "Admin")
      assert Roles.user_has_role?(user, "Admin")
    end

    test "assigns role with assigned_by parameter" do
      owner = create_user()
      user = create_user()

      assert {:ok, assignment} = Roles.assign_role(user, "Admin", owner)
      assert assignment
      assert Roles.user_has_role?(user, "Admin")
    end
  end

  describe "remove_role/3" do
    test "removes assigned role" do
      user = create_standard_user()
      {:ok, _} = Roles.assign_role(user, "Admin")

      assert {:ok, _} = Roles.remove_role(user, "Admin")
      refute Roles.user_has_role?(user, "Admin")
    end

    test "returns error for non-assigned role" do
      user = create_standard_user()

      assert {:error, :assignment_not_found} = Roles.remove_role(user, "Admin")
    end
  end

  describe "user_has_role?/2" do
    test "returns true for assigned role" do
      user = create_standard_user()
      assert Roles.user_has_role?(user, "User")
    end

    test "returns false for unassigned role" do
      user = create_standard_user()
      refute Roles.user_has_role?(user, "Admin")
    end
  end

  describe "get_user_roles/1" do
    test "returns list of role names" do
      user = create_standard_user()
      roles = Roles.get_user_roles(user)

      assert "User" in roles
    end

    test "returns multiple roles" do
      user = create_standard_user()
      {:ok, _} = Roles.assign_role(user, "Admin")

      roles = Roles.get_user_roles(user)
      assert "User" in roles
      assert "Admin" in roles
    end
  end

  describe "get_role_stats/0" do
    test "returns role distribution" do
      _owner = create_user()
      _user = create_user()

      stats = Roles.get_role_stats()

      assert stats.total_users >= 2
      assert stats.owner_count >= 1
      assert is_integer(stats.admin_count)
      assert is_integer(stats.user_count)
    end
  end

  describe "promote_to_admin/2 and demote_to_user/1" do
    test "promotes user to Admin" do
      user = create_standard_user()

      assert {:ok, _} = Roles.promote_to_admin(user)
      assert Roles.user_has_role?(user, "Admin")
    end

    test "demotes admin back to User" do
      user = create_standard_user()
      {:ok, _} = Roles.promote_to_admin(user)

      assert {:ok, _} = Roles.demote_to_user(user)
      refute Roles.user_has_role?(user, "Admin")
      assert Roles.user_has_role?(user, "User")
    end
  end

  describe "users_with_role/1" do
    test "returns users with the specified role" do
      owner = create_user()
      _user = create_user()

      owners = Roles.users_with_role("Owner")
      owner_uuids = Enum.map(owners, & &1.uuid)

      assert owner.uuid in owner_uuids
    end

    test "returns empty list for nonexistent role" do
      assert Roles.users_with_role("NonexistentRole") == []
    end
  end

  describe "count_users_with_role/1" do
    test "returns correct count for Owner" do
      _owner = create_user()
      _user = create_user()

      assert Roles.count_users_with_role("Owner") >= 1
    end

    test "returns correct count for User role" do
      _owner = create_user()
      _user = create_user()

      assert Roles.count_users_with_role("User") >= 1
    end

    test "returns 0 for nonexistent role" do
      assert Roles.count_users_with_role("NonexistentRole") == 0
    end
  end

  describe "sync_user_roles/3 authorization" do
    # first-created user is the seed Owner; make some named actors
    defp make(actor_roles) do
      _seed_owner = create_user()
      user = create_user()
      Enum.each(actor_roles, fn r -> {:ok, _} = Roles.assign_role(user, r) end)
      user
    end

    test "a non-Owner cannot grant Owner or Admin to another account (no escalation)" do
      editor = make([])
      target = create_user()

      {:ok, _} = Roles.sync_user_roles(target, ["Admin"], actor: editor)
      refute Roles.user_has_role?(target, "Admin")

      # Owner is additionally un-assignable system-wide; either way it never lands
      _ = Roles.sync_user_roles(target, ["Owner"], actor: editor)
      refute Roles.user_has_role?(target, "Owner")
    end

    test "a non-Owner CAN manage custom roles" do
      editor = make([])
      {:ok, _} = Roles.create_role(%{name: "Manager", description: "d"})
      target = create_user()

      {:ok, _} = Roles.sync_user_roles(target, ["Manager"], actor: editor)
      assert Roles.user_has_role?(target, "Manager")
    end

    test "returns the before/after role sets captured in the transaction (exact audit)" do
      {:ok, _} = Roles.create_role(%{name: "Manager", description: "d"})
      target = create_user()
      before_roles = Roles.get_user_roles(target)

      {:ok, result} =
        Roles.sync_user_roles(target, before_roles ++ ["Manager"], actor: :system)

      assert %{roles_before: rb, roles_after: ra, assignments: _} = result
      assert Enum.sort(rb) == Enum.sort(before_roles)
      assert "Manager" in ra
      refute "Manager" in rb
    end

    test "a non-Owner submitting an Owner's modal cannot strip Owner (disabled-checkbox wipe)" do
      # seed owner is the FIRST user; the target here is that seed owner
      seed_owner = create_user()
      editor = create_user()
      # the disabled Owner checkbox never submits → role_names lacks Owner
      {:ok, _} = Roles.sync_user_roles(seed_owner, [], actor: editor)
      assert Roles.user_has_role?(seed_owner, "Owner")
    end

    test "the last Owner cannot be removed even by an Owner actor" do
      seed_owner = create_user()
      assert Roles.user_has_role?(seed_owner, "Owner")

      assert {:error, :cannot_remove_last_owner} =
               Roles.sync_user_roles(seed_owner, [], actor: seed_owner)

      assert Roles.user_has_role?(seed_owner, "Owner")
    end
  end

  describe "custom role CRUD" do
    test "create_role/1 creates a custom role" do
      assert {:ok, role} = Roles.create_role(%{name: "Editor", description: "Can edit content"})

      assert role.name == "Editor"
      assert role.is_system_role == false
    end

    test "update_role/2 updates a custom role" do
      {:ok, role} = Roles.create_role(%{name: "Reviewer"})

      assert {:ok, updated} = Roles.update_role(role, %{description: "Reviews submissions"})
      assert updated.description == "Reviews submissions"
    end

    test "delete_role/1 deletes a custom role with no assignments" do
      {:ok, role} = Roles.create_role(%{name: "Temporary"})

      assert {:ok, _deleted} = Roles.delete_role(role)
    end

    test "delete_role/1 prevents deletion of system role" do
      system_role = Enum.find(Roles.list_roles(), &(&1.name == "User"))

      assert {:error, :system_role_protected} = Roles.delete_role(system_role)
    end

    test "delete_role/1 prevents deletion of role with assignments" do
      {:ok, role} = Roles.create_role(%{name: "InUseRole"})
      user = create_standard_user()
      {:ok, _} = Roles.assign_role(user, "InUseRole")

      assert {:error, :role_in_use} = Roles.delete_role(role)
    end
  end

  describe "get_custom_roles/0" do
    test "returns only non-system roles" do
      {:ok, _} = Roles.create_role(%{name: "CustomOnly"})

      custom_roles = Roles.get_custom_roles()
      custom_names = Enum.map(custom_roles, & &1.name)

      assert "CustomOnly" in custom_names
      refute "Owner" in custom_names
      refute "Admin" in custom_names
      refute "User" in custom_names
    end
  end

  describe "ensure_first_user_is_owner/1" do
    test "rolls back cleanly when the Owner role row is missing" do
      user = create_user()

      # Rename rather than delete — the row is referenced by every existing
      # assignment. The bootstrap path looks the role up by name, so a renamed
      # row is a missing row: the owner count reads 0 and the Owner assignment
      # then finds nothing to assign. The earlier implementation dereferenced
      # the locked role row directly and raised on the nil instead.
      {1, _} =
        RepoHelper.repo().update_all(
          from(r in Role, where: r.name == ^"Owner"),
          set: [name: "OwnerRenamed"]
        )

      assert {:error, :role_not_found} = Roles.ensure_first_user_is_owner(user)
    end
  end
end
