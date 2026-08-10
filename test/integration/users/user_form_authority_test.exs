defmodule PhoenixKit.Integration.Users.UserFormAuthorityTest do
  @moduledoc """
  The credential rank rule as the admin form actually enforces it.

  `security_authority_test.exs` pins the rule at the context functions. This
  file pins it at the form, because the form is where the params arrive — and
  the takeover these rules exist to stop was reachable through a param the
  context rules never see.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.RoleAssignment
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  defp unique_email, do: "form_#{System.unique_integer([:positive])}@example.com"

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

  # A value that is hostile AND schema-valid for its field. Both halves matter:
  # hostile so the assertion means something, valid so the changeset is not
  # rejected for a reason that has nothing to do with the filter under test. A
  # value that fails validation makes the test pass no matter what the filter
  # does, which is exactly how this test spent its life proving nothing.
  defp poison_for(:email), do: "attacker@example.com"
  defp poison_for(:user_timezone), do: "0"
  defp poison_for(field), do: "attacker-#{field}"

  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  describe "custom_fields cannot carry schema identity fields past the rank rule" do
    # `Auth.update_user_fields/2` resolves each key with `String.to_existing_atom/1`
    # and writes `:email` / `:username` straight into the schema when the name
    # matches. The form was handing it `params["custom_fields"]` verbatim, so the
    # `Map.drop` that protects the profile params never saw these — an actor who
    # may not manage the target's credentials could rewrite the address a reset
    # link is delivered to, which is the whole takeover in one request.
    # The event is pushed straight at the LiveView rather than through `form/3`.
    # That is not a shortcut, it is the threat model: `form/3` refuses params
    # with no matching rendered input, and the form renders no
    # `custom_fields[email]` box — but nothing stops a client from putting the
    # key on the wire, which is exactly how this reaches the context.
    test "an Admin cannot rewrite an Owner's email through custom_fields", %{conn: conn} do
      owner = owner_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{owner.uuid}"))

      render_submit(view, "save_user", %{
        "user" => %{
          "first_name" => "Harmless",
          "custom_fields" => %{"email" => "attacker@example.com"}
        }
      })

      assert Repo.get!(Auth.User, owner.uuid).email == owner.email
    end

    test "an Admin cannot rewrite an Owner's username through custom_fields", %{conn: conn} do
      owner = owner_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{owner.uuid}"))

      render_submit(view, "save_user", %{
        "user" => %{
          "first_name" => "Harmless",
          "custom_fields" => %{"username" => "attacker"}
        }
      })

      assert Repo.get!(Auth.User, owner.uuid).username == owner.username
    end

    test "a stale authority assign refuses cleanly instead of crashing", %{conn: conn} do
      # `can_manage_credentials` is computed once at mount. The context rule is
      # evaluated again at write time, so the two can disagree: mount while the
      # target is an ordinary user, promote them, then save with a password.
      #
      # Before this was handled, the context's `{:error, :insufficient_permissions}`
      # fell into the clause that expects a changeset, `merge_password_errors/2`
      # called `.errors` on the atom and the LiveView died — after the profile
      # write had already committed, leaving a partial update behind.
      target = plain_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))

      owner_role = Roles.get_role_by_name("Owner")

      {:ok, _} =
        %RoleAssignment{}
        |> RoleAssignment.changeset(%{user_uuid: target.uuid, role_uuid: owner_role.uuid})
        |> Repo.insert(on_conflict: :nothing, conflict_target: [:user_uuid, :role_uuid])

      before = Repo.get!(Auth.User, target.uuid)

      # A crash inside `handle_event/3` surfaces here as a raise from
      # `render_submit/3`, so the call itself is the liveness assertion — and a
      # clean refusal (or a redirect after saving the non-credential fields) is
      # not a failure. What must hold either way is that neither credential of an
      # account this actor no longer outranks was rewritten.
      #
      # `email` is in the payload on purpose: the password is protected by the
      # context regardless, but the address is dropped only by the form, so this
      # is what pins the form's own write-time check rather than the context's.
      #
      # It does NOT pin the reload inside `credential_authority_now/2` — that
      # claim was made here and is wrong. `Auth.get_user!/1` leaves `:roles`
      # unloaded, so `has_system_role?/2` queries by uuid either way and the
      # mounted struct answers just as freshly. What goes red if the write-time
      # check is reverted to `socket.assigns.can_manage_credentials` is this same
      # assertion; the reload itself is unpinned belt-and-braces.
      try do
        render_submit(view, "save_user", %{
          "user" => %{
            "first_name" => "Renamed",
            "email" => "attacker@example.com",
            "password" => "AttackerPassword123!"
          }
        })
      catch
        :exit, {{:shutdown, {:redirect, _, _}}, _} -> :ok
      end

      after_submit = Repo.get!(Auth.User, target.uuid)
      assert after_submit.hashed_password == before.hashed_password
      assert after_submit.email == before.email

      # The other half of "refuses cleanly": only the credential fields are
      # dropped. Asserting the two unchanged fields alone is satisfied just as
      # well by a regression that abandons the whole write — the crash this test
      # was written for did exactly that, half-way through — so pin that the
      # non-credential field this submission carried did land.
      assert after_submit.first_name == "Renamed"
    end

    test "every field the context routes into the schema is dropped, not just the two",
         %{conn: conn} do
      # The pin against drift. The form filters `custom_fields` against
      # `Auth.updatable_profile_fields/0`; the two tests above only exercise
      # `email` and `username`, so a field added to that list and forgotten in
      # the filter would leave them both green while re-opening the bypass for
      # the new one. Submitting the whole list means the coverage grows with it.
      owner = owner_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{owner.uuid}"))

      # ONE poisoned field per submission, not all five in one payload.
      #
      # The all-at-once form was vacuous and had never once exercised the bypass
      # it is named after. `Auth.update_user_fields/2` routes every schema field
      # it recognises into a SINGLE `profile_changeset`, and the generated value
      # for `user_timezone` — "attacker-user_timezone" — fails that field's
      # format validation. One invalid member made the whole changeset invalid,
      # so nothing was written whether the filter ran or not, and the assertion
      # loop compared an untouched row to itself. Verified: with
      # `drop_schema_identity_fields/2` deleted, the old form still passed.
      #
      # Per-field submission is also what keeps this honest as the list grows: a
      # sixth field with its own validator would silently re-vacuum a shared
      # payload, and nothing would say so.
      for field <- Auth.updatable_profile_fields() do
        {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{owner.uuid}"))

        render_submit(view, "save_user", %{
          "user" => %{"custom_fields" => %{Atom.to_string(field) => poison_for(field)}}
        })

        after_submit = Repo.get!(Auth.User, owner.uuid)

        assert Map.get(after_submit, field) == Map.get(owner, field),
               "#{field} reached the schema through custom_fields"
      end
    end

    test "a legitimate custom field still saves alongside the filter", %{conn: conn} do
      # The filter drops by name. Nothing else in the map may go with it — a
      # `Map.drop` widened by accident (or a filter that bailed out of the whole
      # submission on seeing a poisoned key) would show up here and nowhere else.
      target = plain_user()
      conn = log_in_user(conn, admin_user())

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))

      render_submit(view, "save_user", %{
        "user" => %{
          "custom_fields" => %{"email" => "attacker@example.com", "department" => "Engineering"}
        }
      })

      after_submit = Repo.get!(Auth.User, target.uuid)
      assert after_submit.email == target.email
      assert get_in(after_submit.custom_fields, ["department"]) == "Engineering"
    end

    test "an Admin may still set these fields on a user they do outrank", %{conn: conn} do
      target = plain_user()
      conn = log_in_user(conn, admin_user())
      new_email = unique_email()

      {:ok, view, _html} = live(conn, Routes.path("/admin/users/edit/#{target.uuid}"))

      render_submit(view, "save_user", %{"user" => %{"email" => new_email}})

      assert Repo.get!(Auth.User, target.uuid).email == new_email
    end
  end
end
