defmodule PhoenixKit.Integration.Users.MultiSessionTest do
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.RoleAssignment
  alias PhoenixKit.Users.Roles
  alias PhoenixKitWeb.Users.MultiSession

  defp unique_email, do: "ms_#{System.unique_integer([:positive])}@example.com"

  defp owner_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)

    # `Roles.assign_role/3` deliberately refuses to assign the Owner role
    # (`:owner_role_protected`) — Owner is only ever bootstrapped onto the first
    # user. Insert the assignment directly so this helper deterministically
    # yields an Owner regardless of user-creation order. `on_conflict: :nothing`
    # covers the case where this IS the first user and already got Owner.
    owner_role = Roles.get_role_by_name("Owner")

    {:ok, _} =
      %RoleAssignment{}
      |> RoleAssignment.changeset(%{
        user_uuid: user.uuid,
        role_uuid: owner_role.uuid
      })
      |> Repo.insert(
        on_conflict: :nothing,
        conflict_target: [:user_uuid, :role_uuid]
      )

    Repo.get!(Auth.User, user.uuid)
  end

  defp plain_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    Repo.get!(Auth.User, user.uuid)
  end

  defp custom_role_user(role_name) do
    {:ok, role} =
      Repo.insert(%PhoenixKit.Users.Role{
        name: role_name,
        description: role_name,
        is_system_role: false
      })

    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    Roles.assign_role(user, role.name)
    Repo.get!(Auth.User, user.uuid)
  end

  # Build a conn whose root (active) account is `user`, logged in like log_in_user.
  defp conn_for(user) do
    token = Auth.generate_user_session_token(user)

    Phoenix.ConnTest.build_conn()
    |> Phoenix.ConnTest.init_test_session(%{})
    |> Plug.Conn.put_session(:user_token, token)
    |> Plug.Conn.put_session(:live_socket_id, "phoenix_kit_sessions:#{Base.url_encode64(token)}")
    |> Plug.Conn.put_session(:pk_session_accounts, [token])
  end

  # The FIRST user registered in a fresh sandbox auto-becomes Owner
  # (`Auth.register_user` → `Roles.ensure_first_user_is_owner`, which only
  # promotes when no active Owner exists yet). Seed a throwaway Owner up front so
  # the users each test builds get their INTENDED roles (plain "User" / a custom
  # role / an explicit Owner via `owner_user/0`) instead of being silently
  # promoted to Owner just for being the first account created.
  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  describe "add_account/3" do
    test "appends a real account and makes it active" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)

      assert {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")

      session = Plug.Conn.get_session(conn)
      assert length(session["pk_session_accounts"]) == 2
      # active token now resolves to the added user
      assert Auth.get_user_by_session_token(session["user_token"]).uuid == other.uuid
      # root unchanged
      [root_token | _] = session["pk_session_accounts"]
      assert Auth.get_user_by_session_token(root_token).uuid == owner.uuid
    end

    test "rejects invalid credentials, stack unchanged" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)

      assert {:error, :invalid_credentials} =
               MultiSession.add_account(conn, other.email, "wrong-password")

      assert length(Plug.Conn.get_session(conn)["pk_session_accounts"]) == 1
    end

    test "rejects when the stack is full" do
      owner = owner_user()
      conn = conn_for(owner)

      conn =
        Enum.reduce(1..(MultiSession.max_accounts() - 1), conn, fn _, acc ->
          u = plain_user()
          {:ok, acc} = MultiSession.add_account(acc, u.email, "ValidPassword123!")
          acc
        end)

      full = plain_user()

      assert {:error, :stack_full} =
               MultiSession.add_account(conn, full.email, "ValidPassword123!")
    end
  end

  describe "switch_to/2" do
    test "activates a token already in the stack by ref" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")

      [root | _] = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      assert {:ok, conn, user} = MultiSession.switch_to(conn, root.ref)
      assert user.uuid == owner.uuid

      assert Auth.get_user_by_session_token(Plug.Conn.get_session(conn)["user_token"]).uuid ==
               owner.uuid
    end

    test "rejects a ref not in the stack" do
      owner = owner_user()
      conn = conn_for(owner)
      assert {:error, :not_in_stack} = MultiSession.switch_to(conn, Ecto.UUID.generate())
    end
  end

  describe "remove_account/2" do
    test "deletes a non-root token from DB and stack" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")

      accounts = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      added = Enum.find(accounts, &(not &1.root?))
      added_token = Enum.at(Plug.Conn.get_session(conn)["pk_session_accounts"], 1)

      assert {:ok, conn} = MultiSession.remove_account(conn, added.ref)
      assert length(Plug.Conn.get_session(conn)["pk_session_accounts"]) == 1
      assert is_nil(Auth.get_user_by_session_token(added_token))
      # active fell back to root
      assert Auth.get_user_by_session_token(Plug.Conn.get_session(conn)["user_token"]).uuid ==
               owner.uuid
    end

    test "refuses to remove the root account" do
      owner = owner_user()
      conn = conn_for(owner)
      [root | _] = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      assert {:error, :cannot_remove_root} = MultiSession.remove_account(conn, root.ref)
    end
  end

  describe "log_out_active/1 and delete_all_stack_tokens/1" do
    test "log_out_active switches to root when a non-root account is active" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")
      added_token = Plug.Conn.get_session(conn)["user_token"]

      assert {:switched, conn, user} = MultiSession.log_out_active(conn)
      assert user.uuid == owner.uuid
      assert is_nil(Auth.get_user_by_session_token(added_token))
      assert length(Plug.Conn.get_session(conn)["pk_session_accounts"]) == 1
    end

    test "log_out_active returns :full when the root account is active" do
      owner = owner_user()
      conn = conn_for(owner)
      assert {:full, _conn} = MultiSession.log_out_active(conn)
    end

    test "delete_all_stack_tokens deletes every token in the stack" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)
      {:ok, conn} = MultiSession.add_account(conn, other.email, "ValidPassword123!")
      tokens = Plug.Conn.get_session(conn)["pk_session_accounts"]

      _conn = MultiSession.delete_all_stack_tokens(conn)
      assert Enum.all?(tokens, &is_nil(Auth.get_user_by_session_token(&1)))
    end
  end

  # --- Change 1: role_label shows real role name ---

  describe "list_accounts/1 role labels" do
    test "owner account shows 'Owner'" do
      owner = owner_user()
      conn = conn_for(owner)
      [account] = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      assert account.role == "Owner"
    end

    test "plain user account shows 'User'" do
      user = plain_user()
      conn = conn_for(user)
      [account] = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      assert account.role == "User"
    end

    test "custom-role user is labelled with the actual role name, not 'Admin'" do
      # A custom role with no explicit permissions — admin?/1 would return false,
      # but it might return true if permissions were seeded. The real fix is that we
      # no longer call admin?/1 at all — we read cached_roles directly.
      user = custom_role_user("Manager")
      conn = conn_for(user)
      [account] = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      # Must show the real role name, not "Admin" or "User"
      assert account.role == "Manager"
      refute account.role == "Admin"
    end
  end

  # --- Change 2: gate_allowed? for any authenticated user ---

  describe "gate_allowed?/1" do
    test "returns false when multi_session_enabled setting is off" do
      Settings.update_boolean_setting("multi_session_enabled", false)
      owner = owner_user()
      conn = conn_for(owner)
      refute MultiSession.gate_allowed?(Plug.Conn.get_session(conn))
    end

    test "returns true for a plain (non-admin) authenticated user when setting is on" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      user = plain_user()
      conn = conn_for(user)
      assert MultiSession.gate_allowed?(Plug.Conn.get_session(conn))
    end

    test "returns true for an owner when setting is on" do
      Settings.update_boolean_setting("multi_session_enabled", true)
      owner = owner_user()
      conn = conn_for(owner)
      assert MultiSession.gate_allowed?(Plug.Conn.get_session(conn))
    end

    test "returns false when there is no root user token (anonymous)" do
      Settings.update_boolean_setting("multi_session_enabled", true)

      empty_session =
        Phoenix.ConnTest.build_conn()
        |> Phoenix.ConnTest.init_test_session(%{})
        |> Plug.Conn.get_session()

      refute MultiSession.gate_allowed?(empty_session)
    end
  end

  # --- Change 3: add_authenticated_user/2 stack-append path ---

  describe "add_authenticated_user/2" do
    test "appends an active user to the stack and makes them active" do
      owner = owner_user()
      other = plain_user()
      conn = conn_for(owner)

      assert {:ok, conn} = MultiSession.add_authenticated_user(conn, other)

      session = Plug.Conn.get_session(conn)
      assert length(session["pk_session_accounts"]) == 2
      assert Auth.get_user_by_session_token(session["user_token"]).uuid == other.uuid
      [root_token | _] = session["pk_session_accounts"]
      assert Auth.get_user_by_session_token(root_token).uuid == owner.uuid
    end

    test "rejects when the account is already in the stack" do
      owner = owner_user()
      conn = conn_for(owner)

      # Add the same user a second time via add_authenticated_user
      assert {:ok, conn} = MultiSession.add_authenticated_user(conn, plain_user())
      added = plain_user()
      # Force a second call with the same user object (reuse owner)
      assert {:ok, conn_with_two} = MultiSession.add_authenticated_user(conn, added)

      assert {:error, :already_in_stack} =
               MultiSession.add_authenticated_user(conn_with_two, added)
    end

    test "rejects when the stack is full" do
      owner = owner_user()
      conn = conn_for(owner)

      conn =
        Enum.reduce(1..(MultiSession.max_accounts() - 1), conn, fn _, acc ->
          {:ok, acc} = MultiSession.add_authenticated_user(acc, plain_user())
          acc
        end)

      assert {:error, :stack_full} = MultiSession.add_authenticated_user(conn, plain_user())
    end

    test "rejects an inactive user" do
      owner = owner_user()
      conn = conn_for(owner)

      {:ok, inactive} =
        Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})

      # inactive user (not confirmed, is_active false by default until confirmed)
      # Deactivate explicitly
      inactive = %{inactive | is_active: false}

      assert {:error, :inactive} = MultiSession.add_authenticated_user(conn, inactive)
    end
  end

  describe "impersonate/2" do
    defp admin_user do
      {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
      {:ok, user} = Auth.admin_confirm_user(user)
      Roles.assign_role(user, "Admin")
      Repo.get!(Auth.User, user.uuid)
    end

    test "an admin can take a plain user's account without their password" do
      admin = admin_user()
      target = plain_user()

      assert {:ok, conn} = MultiSession.impersonate(conn_for(admin), target)

      accounts = MultiSession.list_accounts(Plug.Conn.get_session(conn))
      assert length(accounts) == 2
      assert Enum.find(accounts, & &1.active?).email == target.email
      # the admin's own account stays, and stays the root
      assert Enum.find(accounts, & &1.root?).email == admin.email
    end

    test "the Owner account is never a target" do
      assert {:error, :target_is_owner} =
               MultiSession.impersonate(conn_for(admin_user()), owner_user())
    end

    test "an admin cannot take another admin — that is sideways, not support" do
      assert {:error, :target_is_staff} =
               MultiSession.impersonate(conn_for(admin_user()), admin_user())
    end

    test "an owner can take an admin, because there is nothing above it to reach" do
      assert {:ok, _conn} = MultiSession.impersonate(conn_for(owner_user()), admin_user())
    end

    test "a permission holder who is not staff cannot impersonate at all" do
      # The hole this guards: `can_access_admin_area?/1` is true for ANY
      # permission holder, so a customer granted one self-service permission
      # would qualify under a permission-based check and could borrow another
      # customer's account. The rule is role-based for exactly this reason.
      assert {:error, :not_allowed} =
               MultiSession.impersonate(conn_for(custom_role_user("Client")), plain_user())
    end

    test "an anonymous session cannot impersonate" do
      conn = Phoenix.ConnTest.build_conn() |> Phoenix.ConnTest.init_test_session(%{})
      assert {:error, :not_allowed} = MultiSession.impersonate(conn, plain_user())
    end

    test "taking your own account is refused rather than duplicated" do
      admin = admin_user()
      assert {:error, :self} = MultiSession.impersonate(conn_for(admin), admin)
    end

    test "the same account cannot be taken twice" do
      admin = admin_user()
      target = plain_user()

      assert {:ok, conn} = MultiSession.impersonate(conn_for(admin), target)
      assert {:error, :already_in_stack} = MultiSession.impersonate(conn, target)
    end

    test "a deactivated account is refused" do
      target = plain_user()
      {:ok, target} = Auth.update_user_status(target, %{"is_active" => false})

      assert {:error, :inactive} = MultiSession.impersonate(conn_for(admin_user()), target)
    end
  end
end
