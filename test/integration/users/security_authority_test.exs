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

  # These tests assert BOOTSTRAP semantics (first-user-becomes-Owner, last-
  # Owner guards, owner counts), so the suite's committed seed Owner is
  # demoted inside this test's own sandbox transaction — see DataCase.
  setup {PhoenixKit.DataCase, :demote_seed_owner}

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions
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

  # Re-read rather than trust the struct: the credential tests assert on what
  # was actually stored, so a guard that refuses only after writing still fails.
  defp password_hash(user), do: Repo.get!(Auth.User, user.uuid).hashed_password

  # Same reason, for the confirmation toggle: the refusal has to be visible in
  # the row, not merely in the return value.
  defp confirmed_at(user), do: Repo.get!(Auth.User, user.uuid).confirmed_at

  # The actor this whole series exists to stop: a role that holds the `users`
  # permission — which is what admits it to the user pages — and no staff role.
  #
  # Built properly rather than approximated with `plain_user/0`. Three tests here
  # were named for this actor while handing the predicate a bare default-role
  # user, so they passed for the wrong reason: the rule refuses an actor with no
  # staff role whether or not it holds any permission, and the test could not
  # tell those two cases apart. If `validate_admin_authority_over/2` ever starts
  # consulting `Permissions`, the difference is the whole finding.
  defp users_permission_holder do
    user = plain_user()
    suffix = System.unique_integer([:positive])

    {:ok, role} =
      Roles.create_role(%{
        name: "SecTestUsersOnly#{suffix}",
        description: "Holds the users permission and no staff rank"
      })

    {:ok, _} = Permissions.grant_permission(role.uuid, "users")
    {:ok, _} = Roles.assign_role(user, role.name)

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
      staffless = users_permission_holder()

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
               Auth.update_user_status(target, %{"is_active" => false},
                 actor: users_permission_holder()
               )

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

    test "a present but malformed actor is refused rather than taking the system path" do
      # The system path exists for callers that pass no `:actor` at all —
      # `PhoenixKit.Users.Referrals` expiring an account, plus seeds and mix
      # tasks. A value that is present but not a `%User{}` (a map decoded from
      # JSON by a host application's controller, a bare uuid string) is a caller
      # that meant to supply an actor and got the shape wrong, and reading that
      # as "no actor" hands it the unchecked path. Same table of shapes as the
      # `admin_update_user_password/3` test below, because it is the same rule.
      target = plain_user()

      for malformed <- [%{"uuid" => Ecto.UUID.generate()}, "some-uuid-string", false, 42] do
        assert {:error, :insufficient_permissions} =
                 Auth.update_user_status(target, %{"is_active" => false}, actor: malformed),
               "a #{inspect(malformed)} actor took the unchecked path"
      end

      assert Repo.get!(Auth.User, target.uuid).is_active
    end
  end

  describe "admin_update_user_password/3 enforces rank in the context" do
    # The predicate has existed since the takeover fixes, but only the edit form
    # ever asked it: `admin_update_user_password/3` itself took the actor purely
    # as audit metadata (`context[:admin_user]`) and wrote the hash for anyone.
    # Its sibling `update_user_status/3` was moved into the context for exactly
    # this reason; credentials were left behind. These tests bind the rule to
    # the function, so a second caller cannot reintroduce the gap.
    #
    # Each assertion checks the stored hash, not just the return value: a guard
    # that refuses AFTER writing would still satisfy the tuple.
    test "an Admin may not set an Owner's password — the takeover this closes" do
      owner = owner_user()
      before = password_hash(owner)

      assert {:error, :insufficient_permissions} =
               Auth.admin_update_user_password(owner, %{password: "NewPassword123!"}, %{
                 admin_user: admin_user()
               })

      assert password_hash(owner) == before
    end

    test "an Admin may not set another Admin's password" do
      target = admin_user()
      before = password_hash(target)

      assert {:error, :insufficient_permissions} =
               Auth.admin_update_user_password(target, %{password: "NewPassword123!"}, %{
                 admin_user: admin_user()
               })

      assert password_hash(target) == before
    end

    test "a non-staff actor holding only a permission is refused" do
      target = plain_user()
      before = password_hash(target)

      assert {:error, :insufficient_permissions} =
               Auth.admin_update_user_password(target, %{password: "NewPassword123!"}, %{
                 admin_user: users_permission_holder()
               })

      assert password_hash(target) == before
    end

    test "an in-rank actor succeeds" do
      target = plain_user()
      before = password_hash(target)

      assert {:ok, _updated} =
               Auth.admin_update_user_password(target, %{password: "NewPassword123!"}, %{
                 admin_user: admin_user()
               })

      refute password_hash(target) == before
    end

    test "changing your own password is allowed, as it is for the predicate" do
      actor = admin_user()
      before = password_hash(actor)

      assert {:ok, _updated} =
               Auth.admin_update_user_password(actor, %{password: "NewPassword123!"}, %{
                 admin_user: actor
               })

      refute password_hash(actor) == before
    end

    test "a present but malformed actor is refused rather than taking the system path" do
      # The system path exists for seeds, migrations and mix tasks, which pass no
      # actor at all. A value that is present but not a `%User{}` — a map decoded
      # from JSON by a host application's controller, a bare uuid string — is a
      # caller that meant to supply an actor and got the shape wrong, and letting
      # it through unchecked is the worst of both readings. PhoenixKit is a
      # library: it cannot see its hosts' callers, so this fails closed.
      target = plain_user()
      before = password_hash(target)

      for malformed <- [%{"uuid" => Ecto.UUID.generate()}, "some-uuid-string", false, 42] do
        assert {:error, :insufficient_permissions} =
                 Auth.admin_update_user_password(target, %{password: "NewPassword123!"}, %{
                   admin_user: malformed
                 }),
               "a #{inspect(malformed)} actor took the unchecked path"
      end

      assert password_hash(target) == before
    end

    test "a malformed TARGET is refused rather than crashing the refusal path" do
      # The mirror of the test above, on the other operand. The public head takes
      # `user` unguarded, `can_manage_user_credentials?/2` answers `false` for a
      # non-`%User{}` target rather than raising, and the refusal branch is then
      # the one that has to survive the shape — it logs the target's uuid. It
      # must reach for that uuid defensively: a fail-closed guard that raises
      # instead of returning its error tuple has failed differently, not safely,
      # and a host passing a JSON-decoded map is the exact case the actor branch
      # was just written to expect.
      for malformed <- [%{"uuid" => Ecto.UUID.generate()}, "some-uuid-string", nil, 42] do
        assert {:error, :insufficient_permissions} =
                 Auth.admin_update_user_password(malformed, %{password: "NewPassword123!"}, %{
                   admin_user: admin_user()
                 }),
               "a #{inspect(malformed)} target did not refuse cleanly"
      end
    end

    test "omitting the actor is the system path and still writes" do
      target = plain_user()
      before = password_hash(target)

      assert {:ok, _updated} =
               Auth.admin_update_user_password(target, %{password: "NewPassword123!"})

      refute password_hash(target) == before
    end
  end

  describe "toggle_user_confirmation/2 enforces rank in the context" do
    # The third function offered from the same pages, to the same holders of the
    # `users` permission, and until now the least covered: it had no test of the
    # rank rule at all. Unconfirming is the sharper half of the toggle —
    # `require_email_confirmation` is honoured at eleven gates, so clearing
    # `confirmed_at` locks the target out of every protected page. That is the
    # same denial of service `update_user_status/3` closes, against the same
    # accounts that are meant to outrank the actor.
    #
    # Each assertion re-reads `confirmed_at` from the database rather than
    # trusting the return value: a guard that refuses after writing would still
    # satisfy the tuple.
    test "an Admin may not unconfirm an Owner — the lockout this closes" do
      owner = owner_user()

      assert {:error, :insufficient_permissions} =
               Auth.toggle_user_confirmation(owner, actor: admin_user())

      assert confirmed_at(owner)
    end

    test "an Admin may not unconfirm another Admin" do
      target = admin_user()

      assert {:error, :insufficient_permissions} =
               Auth.toggle_user_confirmation(target, actor: admin_user())

      assert confirmed_at(target)
    end

    test "a non-staff actor holding only a permission is refused" do
      target = plain_user()

      assert {:error, :insufficient_permissions} =
               Auth.toggle_user_confirmation(target, actor: users_permission_holder())

      assert confirmed_at(target)
    end

    test "your own confirmation is not yours to toggle" do
      # `can_manage_user_status?/2` is the shared predicate, and it refuses self
      # where the credential rule allows it. Inherited here on purpose: locking
      # yourself out of every gated page is the same accident, not a routine one.
      actor = admin_user()

      assert {:error, :insufficient_permissions} =
               Auth.toggle_user_confirmation(actor, actor: actor)

      assert confirmed_at(actor)
    end

    test "an in-rank actor may toggle in both directions" do
      target = plain_user()
      admin = admin_user()

      assert {:ok, unconfirmed} = Auth.toggle_user_confirmation(target, actor: admin)
      refute unconfirmed.confirmed_at
      refute confirmed_at(target)

      assert {:ok, reconfirmed} = Auth.toggle_user_confirmation(unconfirmed, actor: admin)
      assert reconfirmed.confirmed_at
      assert confirmed_at(target)
    end

    test "a present but malformed actor is refused rather than taking the system path" do
      target = plain_user()

      for malformed <- [%{"uuid" => Ecto.UUID.generate()}, "some-uuid-string", false, 42] do
        assert {:error, :insufficient_permissions} =
                 Auth.toggle_user_confirmation(target, actor: malformed),
               "a #{inspect(malformed)} actor took the unchecked path"
      end

      assert confirmed_at(target)
    end

    test "omitting the actor is the system path and still writes" do
      target = plain_user()

      assert {:ok, updated} = Auth.toggle_user_confirmation(target)
      refute updated.confirmed_at
      refute confirmed_at(target)
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
      staffless = users_permission_holder()
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
