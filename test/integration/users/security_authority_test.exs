defmodule PhoenixKit.Integration.Users.SecurityAuthorityTest do
  @moduledoc """
  Covers the three account-takeover paths closed together:

  * credential management (set password / mail a reset / change the address it
    goes to) is decided by role and rank, not by the `users` permission;
  * deactivating a user revokes their sessions instead of merely denying them;
  * the multi-session root account is resolved through the active-user filter,
    so a token that outlives a deactivation cannot be used to impersonate.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.RoleAssignment
  alias PhoenixKit.Users.Roles
  alias PhoenixKitWeb.Users.MultiSession

  defp unique_email, do: "sec_#{System.unique_integer([:positive])}@example.com"

  defp plain_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    Repo.get!(Auth.User, user.uuid)
  end

  # `Roles.assign_role/3` refuses the Owner role by design, so insert it.
  defp owner_user do
    user = plain_user()
    owner_role = Roles.get_role_by_name("Owner")

    {:ok, _} =
      %RoleAssignment{}
      |> RoleAssignment.changeset(%{user_uuid: user.uuid, role_uuid: owner_role.uuid})
      |> Repo.insert(on_conflict: :nothing, conflict_target: [:user_uuid, :role_uuid])

    Repo.get!(Auth.User, user.uuid)
  end

  defp admin_user do
    user = plain_user()
    Roles.assign_role(user, "Admin")
    Repo.get!(Auth.User, user.uuid)
  end

  # The first account in a fresh sandbox is auto-promoted to Owner; seed a
  # throwaway one so every user below gets the role the test asked for.
  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)

    # Handed back because the deletion tests need the sandbox's sole Owner by
    # name: it is what the last-Owner guard protects.
    {:ok, seed: Repo.get!(Auth.User, seed.uuid)}
  end

  describe "can_manage_user_credentials?/2" do
    test "an Owner may manage anyone" do
      owner = owner_user()

      assert Auth.can_manage_user_credentials?(plain_user(), owner)
      assert Auth.can_manage_user_credentials?(admin_user(), owner)
      assert Auth.can_manage_user_credentials?(owner, owner)
    end

    test "an Admin may manage an ordinary user" do
      assert Auth.can_manage_user_credentials?(plain_user(), admin_user())
    end

    test "an Admin may NOT manage an Owner — the takeover this closes" do
      refute Auth.can_manage_user_credentials?(owner_user(), admin_user())
    end

    test "an Admin may NOT manage another Admin" do
      refute Auth.can_manage_user_credentials?(admin_user(), admin_user())
    end

    test "holding a permission is not holding a rank: a non-staff user may manage nobody" do
      # The `users` permission is what admits a visitor to /admin/users. It must
      # not decide whether they may take over an account there.
      staffless = plain_user()

      refute Auth.can_manage_user_credentials?(plain_user(), staffless)
      refute Auth.can_manage_user_credentials?(admin_user(), staffless)
      refute Auth.can_manage_user_credentials?(owner_user(), staffless)
    end

    test "everyone may manage their own account" do
      user = plain_user()

      assert Auth.can_manage_user_credentials?(user, user)
    end
  end

  describe "can_manage_user_status?/2 applies the same rank rule" do
    test "an Admin may deactivate an ordinary user but not an Owner or another Admin" do
      admin = admin_user()

      assert Auth.can_manage_user_status?(plain_user(), admin)
      refute Auth.can_manage_user_status?(owner_user(), admin)
      refute Auth.can_manage_user_status?(admin_user(), admin)
    end

    test "an Owner may deactivate anyone; a non-staff holder of `users` may deactivate nobody" do
      owner = owner_user()

      assert Auth.can_manage_user_status?(admin_user(), owner)
      assert Auth.can_manage_user_status?(plain_user(), owner)

      refute Auth.can_manage_user_status?(admin_user(), plain_user())
      refute Auth.can_manage_user_status?(plain_user(), nil)
    end

    test "your own status is not yours to change, unlike your own credentials" do
      owner = owner_user()
      admin = admin_user()

      refute Auth.can_manage_user_status?(owner, owner)
      refute Auth.can_manage_user_status?(admin, admin)

      # The contrast is deliberate: changing your own password is ordinary,
      # switching your own account off is not — and the admin form only ever
      # said so in markup.
      assert Auth.can_manage_user_credentials?(admin, admin)
    end

    test "a missing actor is refused rather than defaulting open" do
      refute Auth.can_manage_user_credentials?(plain_user(), nil)
      refute Auth.can_manage_user_credentials?(nil, owner_user())
    end
  end

  describe "update_user_status/3 enforces rank in the context" do
    # The predicate tests above pass while a caller that never asks the
    # predicate still flips the flag — which is exactly what happened: the guard
    # was added to the edit form only, and the user-list and user-detail pages
    # reached `update_user_status/2` ungated. These tests bind the rule to the
    # function every caller goes through.
    test "an out-of-rank actor is refused and nothing is written" do
      owner = owner_user()
      admin = admin_user()

      assert {:error, :insufficient_permissions} =
               Auth.update_user_status(owner, %{"is_active" => false}, actor: admin)

      assert Repo.get!(Auth.User, owner.uuid).is_active
    end

    test "an Admin may not switch off another Admin" do
      target = admin_user()

      assert {:error, :insufficient_permissions} =
               Auth.update_user_status(target, %{"is_active" => false}, actor: admin_user())

      assert Repo.get!(Auth.User, target.uuid).is_active
    end

    test "a non-staff actor holding only a permission is refused" do
      target = plain_user()

      assert {:error, :insufficient_permissions} =
               Auth.update_user_status(target, %{"is_active" => false}, actor: plain_user())

      assert Repo.get!(Auth.User, target.uuid).is_active
    end

    test "an in-rank actor succeeds" do
      target = plain_user()

      assert {:ok, updated} =
               Auth.update_user_status(target, %{"is_active" => false}, actor: admin_user())

      refute updated.is_active
    end

    test "omitting the actor is the system path and still applies the last-Owner guard" do
      target = plain_user()

      assert {:ok, updated} = Auth.update_user_status(target, %{"is_active" => false})
      refute updated.is_active
    end
  end

  describe "deletion answers to the same rank rule" do
    # `can_delete_user?/2` was cited as the model the credential rule mirrors,
    # but it was two rules short of it: the only target it refused was an Admin,
    # and it never asked whether the ACTOR held a staff role at all — that was
    # deferred to a page gate which is true for any holder of a single
    # permission. So a non-last Owner was deletable by an Admin, and by a
    # Manager who happened to hold `users`.
    test "an Admin may not delete an Owner while another Owner remains" do
      # The setup seed is already an Owner, so the last-Owner guard is not what
      # does the refusing here — the rank rule is.
      target = owner_user()
      admin = admin_user()

      refute Auth.can_delete_user?(target, admin)
      assert {:error, :target_is_owner} = Auth.delete_user(target, %{current_user: admin})
      assert Repo.get(Auth.User, target.uuid)
    end

    test "a holder of the users permission with no staff role may delete nobody" do
      staffless = plain_user()
      target = plain_user()

      refute Auth.can_delete_user?(target, staffless)

      assert {:error, :insufficient_permissions} =
               Auth.delete_user(target, %{current_user: staffless})

      assert Repo.get(Auth.User, target.uuid)
    end

    test "an Admin may not delete another Admin, but may delete an ordinary user" do
      refute Auth.can_delete_user?(admin_user(), admin_user())
      assert Auth.can_delete_user?(plain_user(), admin_user())
    end

    test "an Owner may delete an Admin", %{seed: seed} do
      assert Auth.can_delete_user?(admin_user(), seed)
    end

    test "the last-Owner guard keeps its own reason rather than the rank one",
         %{seed: seed} do
      # `seed` is the only Owner in this sandbox, so both rules would refuse an
      # Admin actor. The target-only rule is checked first and must win, or the
      # operator is told "no permission" for something no permission can fix.
      assert {:error, :cannot_delete_last_owner} =
               Auth.delete_user(seed, %{current_user: admin_user()})
    end
  end

  describe "deactivation revokes sessions" do
    test "the session token stops resolving the moment the account is deactivated" do
      user = plain_user()
      token = Auth.generate_user_session_token(user)

      assert %Auth.User{uuid: uuid} = Auth.get_user_by_session_token(token)
      assert uuid == user.uuid

      {:ok, _deactivated} = Auth.update_user_status(user, %{"is_active" => false})

      refute Auth.get_user_by_session_token(token)
      assert Auth.get_all_user_session_tokens(user) == []
    end

    test "re-activating does not resurrect the revoked token" do
      user = plain_user()
      token = Auth.generate_user_session_token(user)

      {:ok, deactivated} = Auth.update_user_status(user, %{"is_active" => false})
      {:ok, _reactivated} = Auth.update_user_status(deactivated, %{"is_active" => true})

      refute Auth.get_user_by_session_token(token)
    end

    test "activation leaves existing sessions alone" do
      user = plain_user()
      token = Auth.generate_user_session_token(user)

      {:ok, _} = Auth.update_user_status(user, %{"is_active" => true})

      assert %Auth.User{} = Auth.get_user_by_session_token(token)
    end
  end

  describe "multi-session root resolution filters inactive accounts" do
    test "a token that outlives a deactivation cannot impersonate" do
      admin = admin_user()
      token = Auth.generate_user_session_token(admin)

      session = %{"pk_session_accounts" => [token], "user_token" => token}
      assert MultiSession.may_impersonate?(session)

      # Deactivate WITHOUT going through update_user_status/2, which now revokes
      # tokens — this is the defence-in-depth half: a token minted before that
      # fix, or an is_active flip made directly against the database, must still
      # be refused by the root resolution itself.
      admin
      |> Auth.User.status_changeset(%{"is_active" => false})
      |> Repo.update!()

      refute MultiSession.may_impersonate?(session)
      refute MultiSession.gate_allowed?(session)
    end
  end
end
