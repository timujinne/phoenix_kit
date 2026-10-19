defmodule PhoenixKit.Modules.Storage.PersonalLibraryTest do
  @moduledoc """
  The personal library a host may give its accounts (`ensure_personal_library/2`,
  `backfill_personal_libraries/1`): never made by PhoenixKit itself, made once,
  never again once the user has deleted it, the user's default when they have no
  other, and made for the accounts that were there before by the backfill (not
  for guests, API-only or inactive accounts).
  """
  use PhoenixKit.DataCase, async: false

  import Ecto.Query

  alias PhoenixKit.Modules.Storage.{Libraries, Library}
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Users.Auth.{Scope, User}

  setup do
    {:ok, _} = Settings.update_boolean_setting("storage_user_libraries_enabled", true)

    {:ok, role} = Roles.create_role(%{name: "Librarians #{System.unique_integer([:positive])}"})
    {:ok, _} = Permissions.grant_permission(role.uuid, "storage")
    {:ok, _} = Permissions.grant_permission(role.uuid, "storage.create_library")

    %{role: role}
  end

  defp librarian!(role) do
    user = register!()
    {:ok, _} = Roles.assign_role(user, role.name)
    user
  end

  defp register!(attrs \\ %{}) do
    {:ok, user} =
      Auth.register_user(
        Map.merge(
          %{
            "email" => "personal-#{System.unique_integer([:positive])}@example.com",
            "password" => "ValidPassword123!"
          },
          attrs
        )
      )

    user
  end

  defp owned(user),
    do: Repo.all(from(l in Library, where: l.kind == "user" and l.owner_uuid == ^user.uuid))

  describe "PhoenixKit does not make one by itself" do
    test "registering an account, however, creates no library" do
      user = register!()

      assert owned(user) == []
      assert Libraries.default_user_library(user.uuid) == nil
    end

    test "an admin-created account neither" do
      admin = register!()

      {:ok, user} =
        Auth.admin_create_user(
          %{
            "email" => "by-admin-#{System.unique_integer([:positive])}@example.com",
            "password" => "ValidPassword123!"
          },
          admin
        )

      assert owned(user) == []
    end
  end

  describe "ensure_personal_library/2, once the host calls it" do
    test "a private library, the user's default, marked as the personal one" do
      user = register!()

      assert {:ok, %Library{} = library} = Libraries.ensure_personal_library(user.uuid)
      assert library.name == "My library"
      assert library.visibility == "private"
      assert library.is_default
      assert library.settings["personal"] == true
      assert is_nil(library.storage_profile_uuid)
      assert Libraries.role(library, user.uuid) == :owner
      assert Libraries.default_user_library(user.uuid).uuid == library.uuid
    end

    test "it needs no permission: the account has none" do
      user = register!()
      refute Libraries.may_create_library?(Scope.for_user(Repo.get!(User, user.uuid)))

      assert {:ok, %Library{}} = Libraries.ensure_personal_library(user.uuid)
    end

    test "while user libraries are off it makes nothing: that switch governs it too" do
      {:ok, _} = Settings.update_boolean_setting("storage_user_libraries_enabled", false)
      user = register!()

      assert {:error, :user_libraries_off} = Libraries.ensure_personal_library(user.uuid)
      assert {:error, :user_libraries_off} = Libraries.backfill_personal_libraries()
      assert owned(user) == []
    end

    test "the name is the host's choice" do
      user = register!()

      assert {:ok, %Library{name: "My photos"}} =
               Libraries.ensure_personal_library(user.uuid, name: "  My photos ")

      other = register!()

      assert {:ok, %Library{name: "My library"}} =
               Libraries.ensure_personal_library(other.uuid, name: " ")
    end
  end

  describe "ensure_personal_library/2, once and only once" do
    test "never makes a second" do
      user = register!()
      {:ok, first} = Libraries.ensure_personal_library(user.uuid)

      assert {:ok, :exists} = Libraries.ensure_personal_library(user.uuid)
      assert [%{uuid: uuid}] = owned(user)
      assert uuid == first.uuid
    end

    test "a user who trashed theirs is not given another" do
      user = register!()
      {:ok, library} = Libraries.ensure_personal_library(user.uuid)
      scope = Scope.for_user(Repo.get!(User, user.uuid))
      {:ok, _} = Libraries.trash_library(scope, library)

      assert {:ok, :exists} = Libraries.ensure_personal_library(user.uuid)
      assert [%{trashed_at: %DateTime{}}] = owned(user)
    end

    test "but not when they already have a default of their own", %{role: role} do
      user = librarian!(role)

      {:ok, mine} =
        Libraries.create_user_library(
          Scope.for_user(Repo.get!(User, user.uuid)),
          %{"name" => "Mine"}
        )

      assert mine.is_default
      assert {:ok, %Library{is_default: false}} = Libraries.ensure_personal_library(user.uuid)
      assert Enum.count(owned(user), & &1.is_default) == 1
    end

    test "it takes a free name when the user already has a library called that", %{role: role} do
      user = librarian!(role)

      scope = Scope.for_user(Repo.get!(User, user.uuid))
      {:ok, _} = Libraries.create_user_library(scope, %{"name" => "My library"})

      assert {:ok, %Library{name: "My library 2"}} = Libraries.ensure_personal_library(user.uuid)
    end
  end

  describe "backfill_personal_libraries/0" do
    test "makes one for each account that has none, once" do
      old = for _ <- 1..2, do: register!()

      first = Libraries.backfill_personal_libraries()
      assert first.created >= 2
      assert first.failed == 0
      assert Enum.all?(old, &match?([%{settings: %{"personal" => true}}], owned(&1)))

      second = Libraries.backfill_personal_libraries()
      assert second.created == 0
      assert second.existing >= 2
    end

    test "leaves guests, API-only and inactive accounts out" do
      guest = register!()
      api = register!()
      inactive = register!()
      regular = register!()

      Repo.update_all(from(u in User, where: u.uuid == ^guest.uuid),
        set: [custom_fields: %{"source" => "guest_checkout"}]
      )

      Repo.update_all(from(u in User, where: u.uuid == ^api.uuid), set: [api_only: true])
      Repo.update_all(from(u in User, where: u.uuid == ^inactive.uuid), set: [is_active: false])

      Libraries.backfill_personal_libraries()

      assert owned(guest) == []
      assert owned(api) == []
      assert owned(inactive) == []
      assert [_] = owned(regular)
    end
  end
end
