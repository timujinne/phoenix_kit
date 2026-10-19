defmodule PhoenixKit.Integration.Users.ProfileCustomFieldsAuthorityTest do
  @moduledoc """
  What the account holder may write into their own `custom_fields`.

  The column is shared: admin-defined profile fields sit next to state the
  system keeps per user (the avatar file, the invite-only stamp, the account's
  `source`, notification routing). A profile form posts whatever the client
  sends, so `User.profile_changeset/3` accepts only defined, user-accessible
  fields from it and merges them over the stored map.

  Every rule is driven twice: through `/profile/settings` with the real form,
  and through `Auth.update_user_profile/2` directly.
  """
  use PhoenixKitWeb.ConnCase, async: true

  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.CustomFields
  alias PhoenixKit.Utils.Routes

  @form "#profile-user-settings-account-custom-fields-form"
  @identity_form "#profile-user-settings-account-profile-form"
  @seed_avatar "0198f3a2-7c1e-7d4b-9a55-0c2f6f1f9a01"

  defp unique(prefix), do: "#{prefix}_#{System.unique_integer([:positive])}"

  defp define!(key, attrs) do
    {:ok, _} =
      CustomFields.add_field_definition(
        Map.merge(
          %{
            "key" => key,
            "label" => "Label #{key}",
            "type" => "text",
            "enabled" => true,
            "user_accessible" => true,
            "position" => 1
          },
          attrs
        )
      )

    key
  end

  defp reload(user), do: Repo.get!(AuthCtx.User, user.uuid)

  defp seeded_user(extra \\ %{}) do
    {:ok, user} =
      AuthCtx.register_user(%{
        email: "#{unique("cf_auth")}@example.com",
        password: "ValidPassword123!"
      })

    {:ok, user} = AuthCtx.admin_confirm_user(user)

    {:ok, user} =
      Auth.update_user_custom_fields(
        user,
        Map.merge(
          %{
            "avatar_file_uuid" => @seed_avatar,
            "source" => "guest_checkout",
            "notification_preferences" => %{"comment.created" => false}
          },
          extra
        ),
        ensure_definitions: false
      )

    reload(user)
  end

  # `typed` goes through the form's own inputs; `forged` is added to the
  # payload the way a client composing its own submit would.
  defp save(%{driver: :live_view, conn: conn}, user, typed, forged) do
    {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

    html =
      view
      |> form(@form, %{"profile_form" => %{"user" => %{"custom_fields" => typed}}})
      |> render_submit(%{"profile_form" => %{"user" => %{"custom_fields" => forged}}})

    %{html: html, stored: reload(user).custom_fields}
  end

  defp save(%{driver: :context}, user, typed, forged) do
    result = Auth.update_user_profile(user, %{"custom_fields" => Map.merge(typed, forged)})
    %{result: result, stored: reload(user).custom_fields}
  end

  defp assert_refused(%{html: html, stored: stored}, user, key) do
    assert html =~ "Label #{key}:"
    assert stored == user.custom_fields
  end

  defp assert_refused(%{result: result, stored: stored}, user, key) do
    assert {:error, changeset} = result
    assert [{:custom_fields, {_message, opts}}] = changeset.errors
    assert opts[:field] == key
    assert stored == user.custom_fields
  end

  for driver <- [:live_view, :context] do
    describe "saving custom fields through #{driver}" do
      @describetag driver: driver

      test "a defined key with a valid value is stored, the rest untouched", ctx do
        phone = define!(unique("phone"), %{})
        user = seeded_user()

        %{stored: stored} = save(ctx, user, %{phone => "555-1234"}, %{})

        assert stored == Map.put(user.custom_fields, phone, "555-1234")
      end

      test "an undefined key is not stored", ctx do
        phone = define!(unique("phone"), %{})
        user = seeded_user()

        %{stored: stored} = save(ctx, user, %{phone => "555-1234"}, %{"ghost_key" => "boo"})

        assert stored == Map.put(user.custom_fields, phone, "555-1234")
      end

      test "system keys are neither written, changed nor blanked", ctx do
        phone = define!(unique("phone"), %{})
        user = seeded_user()

        forged = %{
          "avatar_file_uuid" => "0198f3a2-7c1e-7d4b-9a55-ffffffffffff",
          "source" => "",
          "notification_preferences" => "",
          "referral_satisfied_at" => "2026-01-01T00:00:00Z",
          "oauth_avatar_url" => "https://tracker.test/pixel.gif",
          "pending_invitation_uuid" => "0198f3a2-7c1e-7d4b-9a55-eeeeeeeeeeee",
          "start_page" => "//evil.test",
          "notification_channel:telegram" => %{"site_chat_id" => "42", "enabled" => true}
        }

        %{stored: stored} = save(ctx, user, %{phone => "555-1234"}, forged)

        assert stored == Map.put(user.custom_fields, phone, "555-1234")
      end

      test "an internal key stays refused even when a definition marks it accessible", ctx do
        # A definition auto-registered before `user_accessible` existed reads
        # as accessible, and several internal keys have one.
        define!("source", %{})
        user = seeded_user()

        %{stored: stored} = save(ctx, user, %{}, %{"source" => "staff_placeholder"})

        assert stored == user.custom_fields
      end

      test "a field the admin kept for themselves is not writable", ctx do
        define!(unique("phone"), %{})
        notes = define!(unique("admin_notes"), %{"user_accessible" => false})
        disabled = define!(unique("retired"), %{"enabled" => false})
        user = seeded_user(%{notes => "vetted"})

        %{stored: stored} = save(ctx, user, %{}, %{notes => "self-vetted", disabled => "x"})

        assert stored == user.custom_fields
      end

      test "a defined key with an invalid value is refused", ctx do
        mail = define!(unique("contact_mail"), %{"type" => "email"})
        user = seeded_user()

        ctx |> save(user, %{mail => "not an address"}, %{}) |> assert_refused(user, mail)
      end

      test "a select takes only an offered option", ctx do
        colour = define!(unique("colour"), %{"type" => "select", "options" => ["Red", "Blue"]})
        user = seeded_user(%{colour => "Red"})

        ctx |> save(user, %{}, %{colour => "Ultraviolet"}) |> assert_refused(user, colour)

        %{stored: stored} = save(ctx, user, %{colour => "Blue"}, %{})
        assert stored[colour] == "Blue"
      end

      test "a required field cannot be blanked", ctx do
        badge = define!(unique("badge"), %{"required" => true})
        user = seeded_user(%{badge => "A-1"})

        ctx |> save(user, %{}, %{badge => ""}) |> assert_refused(user, badge)
      end

      test "an oversized value is refused", ctx do
        bio = define!(unique("bio"), %{"type" => "textarea"})
        user = seeded_user()
        limit = CustomFields.max_user_value_length()

        ctx
        |> save(user, %{bio => String.duplicate("a", limit + 1)}, %{})
        |> assert_refused(user, bio)

        %{stored: stored} = save(ctx, user, %{bio => String.duplicate("a", limit)}, %{})
        assert String.length(stored[bio]) == limit
      end

      test "a nested map or a list under a defined key is refused", ctx do
        phone = define!(unique("phone"), %{})
        user = seeded_user()

        ctx
        |> save(user, %{}, %{phone => %{"deep" => %{"er" => "x"}}})
        |> assert_refused(user, phone)

        ctx |> save(user, %{}, %{phone => ["a", "b"]}) |> assert_refused(user, phone)
      end

      test "a structured value stored under a defined key cannot be overwritten", ctx do
        key = define!(unique("line_params"), %{})
        user = seeded_user(%{key => %{"width" => 13}})

        %{stored: stored} = save(ctx, user, %{}, %{key => "flattened"})

        assert stored == user.custom_fields
      end

      test "a stored value the definition no longer accepts does not block the save", ctx do
        # The form posts every field back; an unchanged one is not re-validated.
        mail = define!(unique("contact_mail"), %{"type" => "email"})
        phone = define!(unique("phone"), %{"position" => 2})
        user = seeded_user(%{mail => "legacy free text"})

        %{stored: stored} =
          save(ctx, user, %{phone => "555-1234", mail => "legacy free text"}, %{})

        assert stored == Map.put(user.custom_fields, phone, "555-1234")
      end
    end
  end

  describe "the settings page" do
    test "saving a mounted form preserves newer system fields", %{conn: conn} do
      phone = define!(unique("phone"), %{})
      user = seeded_user()
      {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

      {:ok, current} =
        Auth.merge_user_custom_fields(
          user,
          %{"notification_preferences" => %{"comment.created" => true}},
          ensure_definitions: false,
          broadcast: false
        )

      view
      |> form(@form, %{"profile_form" => %{"user" => %{"custom_fields" => %{phone => "555"}}}})
      |> render_submit()

      assert reload(user).custom_fields == Map.put(current.custom_fields, phone, "555")
    end

    test "a custom_fields payload that is not a map changes nothing", %{conn: conn} do
      define!(unique("phone"), %{})
      user = seeded_user()
      {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

      view
      |> form(@identity_form, %{})
      |> render_submit(%{"user" => %{"custom_fields" => "1"}})

      assert reload(user).custom_fields == user.custom_fields
      assert {:error, changeset} = Auth.update_user_profile(user, %{"custom_fields" => "1"})
      assert {"must be a valid map", _} = changeset.errors[:custom_fields]
    end

    test "saving the identity form leaves custom_fields exactly as stored", %{conn: conn} do
      phone = define!(unique("phone"), %{})
      user = seeded_user(%{phone => "555-1234"})
      {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

      view
      |> form(@identity_form, %{"user" => %{"first_name" => "Renamed"}})
      |> render_submit(%{"user" => %{"custom_fields" => %{"referral_satisfied_at" => "now"}}})

      saved = reload(user)
      assert saved.first_name == "Renamed"
      assert saved.custom_fields == user.custom_fields
    end

    test "the profile form cannot change the email address", %{conn: conn} do
      # The address changes only through the password-checked, mail-confirmed
      # email form; the profile events used to write it straight through.
      user = seeded_user()
      {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

      view
      |> form(@identity_form, %{"user" => %{"first_name" => "Renamed"}})
      |> render_submit(%{"user" => %{"email" => "taken-over@example.com"}})

      saved = reload(user)
      assert saved.first_name == "Renamed"
      assert saved.email == user.email
    end

    test "validating shows the refusal and stores nothing", %{conn: conn} do
      mail = define!(unique("contact_mail"), %{"type" => "email"})
      user = seeded_user()
      {:ok, view, _html} = live(log_in_user(conn, user), Routes.path("/profile/settings"))

      html =
        view
        |> form(@form, %{"profile_form" => %{"user" => %{"custom_fields" => %{mail => "nope"}}}})
        |> render_change(%{
          "profile_form" => %{"user" => %{"custom_fields" => %{"source" => "x"}}}
        })

      assert html =~ "Label #{mail}:"
      assert reload(user).custom_fields == user.custom_fields
    end
  end

  describe "flows that write system keys" do
    test "a custom-field save for a deleted user still raises a stale-entry error" do
      phone = define!(unique("phone"), %{})
      user = seeded_user()
      Repo.delete!(user)

      assert_raise Ecto.StaleEntryError, fn ->
        Auth.update_user_profile(user, %{"custom_fields" => %{phone => "555"}})
      end
    end

    test "a profile save from a stale user preserves added keys and never restores deleted ones" do
      phone = define!(unique("phone"), %{})
      user = seeded_user()

      {:ok, current} =
        Auth.merge_user_custom_fields(user, %{"preferred_locale" => "et"},
          ensure_definitions: false
        )

      {:ok, current} = Auth.delete_user_custom_field(current, "avatar_file_uuid")

      assert {:ok, updated} =
               Auth.update_user_profile(user, %{"custom_fields" => %{phone => "555"}})

      assert updated.custom_fields == Map.put(current.custom_fields, phone, "555")
      assert reload(user).custom_fields == updated.custom_fields
    end

    test "a stale profile cannot replace a field that has since become structured" do
      phone = define!(unique("phone"), %{})
      user = seeded_user(%{phone => "old"})

      {:ok, current} = Auth.merge_user_custom_fields(user, %{phone => %{"managed" => true}})

      assert {:ok, updated} =
               Auth.update_user_profile(user, %{"custom_fields" => %{phone => "555"}})

      assert updated.custom_fields == current.custom_fields
      assert reload(user).custom_fields == current.custom_fields
    end

    test "guest checkout stamps its source, and the account cannot restamp it" do
      {:ok, guest} = Auth.create_guest_user(%{email: "#{unique("guest")}@example.com"})
      assert guest.custom_fields["source"] == "guest_checkout"

      {:ok, _} =
        Auth.update_user_profile(guest, %{"custom_fields" => %{"source" => "crm_contact"}})

      assert reload(guest).custom_fields["source"] == "guest_checkout"
    end

    test "a server-side registration keeps the custom_fields it passes" do
      {:ok, user} =
        Auth.register_user(%{
          "email" => "#{unique("placeholder")}@example.com",
          "password" => "ValidPassword123!",
          "custom_fields" => %{"source" => "staff_placeholder"}
        })

      assert reload(user).custom_fields["source"] == "staff_placeholder"
    end

    test "the avatar write path still sets the file and its crop" do
      user = seeded_user()
      next = "0198f3a2-7c1e-7d4b-9a55-0c2f6f1f9a02"
      crop = %{"x" => 0.5, "y" => 0.5, "zoom" => 2.0, "aspect" => 1.0}

      {:ok, updated} =
        Auth.update_user_fields(user, %{"avatar_file_uuid" => next, "avatar_crop" => crop})

      assert updated.custom_fields["avatar_file_uuid"] == next
      assert updated.custom_fields["avatar_crop"] == crop
      assert updated.custom_fields["source"] == "guest_checkout"
    end

    test "an admin's own write path still reaches a field the user cannot edit" do
      notes = define!(unique("admin_notes"), %{"user_accessible" => false})
      user = seeded_user()

      {:ok, updated} = Auth.update_user_fields(user, %{notes => "vetted"})

      assert updated.custom_fields[notes] == "vetted"
    end
  end
end
