defmodule PhoenixKitWeb.StorageApiAuthzTest do
  @moduledoc """
  The authorization decisions behind the storage HTTP API — the upload owner
  resolver and the file-info read guard. Both endpoints live in the
  unauthenticated `[:browser, :phoenix_kit_auto_setup]` scope, so the guard is
  the controller's own, and these functions are it (issue #687 class: an
  anonymous, attacker-controlled write / signed-URL handout).
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RateLimiter
  alias PhoenixKit.Users.Roles
  alias PhoenixKitWeb.FileController
  alias PhoenixKitWeb.UploadController

  # The first registered user is auto-promoted to Owner; seed one so the users
  # these tests build are genuinely non-privileged.
  setup do
    {:ok, seed} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, _} = Auth.admin_confirm_user(seed)
    :ok
  end

  defp unique_email, do: "storage_#{System.unique_integer([:positive])}@example.com"

  defp plain_user do
    {:ok, user} = Auth.register_user(%{email: unique_email(), password: "ValidPassword123!"})
    {:ok, user} = Auth.admin_confirm_user(user)
    Repo.get!(Auth.User, user.uuid)
  end

  defp admin_user do
    user = plain_user()
    Roles.assign_role(user, "Admin")
    Repo.get!(Auth.User, user.uuid)
  end

  # A user who holds a module permission but NOT the Owner/Admin system role.
  # `can_access_admin_area?/1` is true for them; `system_role?/1` is not — the
  # exact distinction the storage gates must honor.
  defp permission_holder_user do
    user = plain_user()
    user_role = Roles.get_role_by_name("User")
    {:ok, _} = Permissions.grant_permission(user_role.uuid, "media")
    Repo.get!(Auth.User, user.uuid)
  end

  defp make_file(owner_uuid) do
    checksum = "cs_#{System.unique_integer([:positive])}"

    {:ok, file} =
      Storage.create_file(%{
        original_file_name: "photo.jpg",
        file_name: "photo.jpg",
        mime_type: "image/jpeg",
        file_type: "image",
        ext: "jpg",
        file_checksum: checksum,
        user_file_checksum: "u_#{checksum}",
        size: 1234,
        status: "active",
        user_uuid: owner_uuid
      })

    file
  end

  describe "UploadController.resolve_upload_user/2 — the anonymous-write hole" do
    test "an unauthenticated request is refused, even with a user_uuid param" do
      assert {:error, :no_user} =
               UploadController.resolve_upload_user(nil, %{"user_uuid" => "any-victim-uuid"})
    end

    test "an authenticated non-admin is attributed to themselves, override ignored" do
      user = plain_user()

      assert {:ok, uuid} =
               UploadController.resolve_upload_user(user, %{"user_uuid" => "someone-else"})

      assert uuid == user.uuid
    end

    test "an authenticated non-admin with no override is attributed to themselves" do
      user = plain_user()
      assert {:ok, uuid} = UploadController.resolve_upload_user(user, %{})
      assert uuid == user.uuid
    end

    test "an authenticated admin may override the owner" do
      admin = admin_user()

      assert {:ok, "target-uuid"} =
               UploadController.resolve_upload_user(admin, %{"user_uuid" => "target-uuid"})
    end

    test "a mere permission holder (not Owner/Admin) cannot override the owner" do
      user = permission_holder_user()

      # Proves this is the middle case: the broad `can_access_admin_area?/1`
      # predicate would have let them through — `system_role?/1` does not.
      assert Scope.can_access_admin_area?(Scope.for_user(user))
      refute Scope.system_role?(Scope.for_user(user))

      assert {:ok, uuid} =
               UploadController.resolve_upload_user(user, %{"user_uuid" => "someone-else"})

      assert uuid == user.uuid
    end
  end

  describe "FileController file-info read guard — anonymous handout + enumeration" do
    test "require_user refuses an unauthenticated caller" do
      assert {:error, :no_user} = FileController.require_user(nil)
      user = plain_user()
      assert {:ok, ^user} = FileController.require_user(user)
    end

    test "the owner may read their file" do
      owner = plain_user()
      file = make_file(owner.uuid)
      assert {:ok, got} = FileController.authorize_file_read(file, owner)
      assert got.uuid == file.uuid
    end

    test "a non-owner cannot tell a foreign file from a missing one (no oracle)" do
      owner = plain_user()
      stranger = plain_user()
      file = make_file(owner.uuid)

      assert {:error, :not_found} = FileController.authorize_file_read(file, stranger)
      assert {:error, :not_found} = FileController.authorize_file_read(nil, stranger)
    end

    test "an admin may read any file" do
      owner = plain_user()
      admin = admin_user()
      file = make_file(owner.uuid)
      assert {:ok, got} = FileController.authorize_file_read(file, admin)
      assert got.uuid == file.uuid
    end

    test "a mere permission holder cannot read another user's file" do
      owner = plain_user()
      holder = permission_holder_user()
      file = make_file(owner.uuid)

      assert Scope.can_access_admin_area?(Scope.for_user(holder))
      refute Scope.system_role?(Scope.for_user(holder))
      assert {:error, :not_found} = FileController.authorize_file_read(file, holder)
    end
  end

  describe "RateLimiter.check_upload_rate_limit/1" do
    test "allows the first request and is keyed on the account" do
      assert :ok = RateLimiter.check_upload_rate_limit(Ecto.UUID.generate())
    end
  end
end
