defmodule PhoenixKit.Modules.Storage.UserStorageCreationTest do
  @moduledoc """
  Creating a user library on the user's own storage (V206): who may, both
  modes end to end (bucket, profile, library in one transaction), the probe
  that runs before anything is written, every failure leaving nothing behind,
  and the choice being final.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Integrations
  alias PhoenixKit.Modules.Storage
  alias PhoenixKit.Modules.Storage.{Libraries, Library, Profiles}
  alias PhoenixKit.Settings
  alias PhoenixKit.Test.Repo
  alias PhoenixKit.Users.{Auth, Permissions, Roles}
  alias PhoenixKit.Users.Auth.Scope

  setup do
    original = Application.get_env(:phoenix_kit, :secret_key_base)
    Application.put_env(:phoenix_kit, :secret_key_base, "test-secret-for-own-storage")

    on_exit(fn ->
      if original,
        do: Application.put_env(:phoenix_kit, :secret_key_base, original),
        else: Application.delete_env(:phoenix_kit, :secret_key_base)
    end)

    {:ok, _} = Settings.update_boolean_setting("storage_user_libraries_enabled", true)
    {:ok, _} = Settings.update_boolean_setting("storage_user_buckets_enabled", true)
    {:ok, _} = Settings.update_setting("storage_user_library_limit", "5")

    n = System.unique_integer([:positive])
    {:ok, role} = Roles.create_role(%{name: "Own storage #{n}"})
    {:ok, _} = Permissions.grant_permission(role.uuid, "storage")
    {:ok, _} = Permissions.grant_permission(role.uuid, "storage.create_library")
    {:ok, _} = Permissions.grant_permission(role.uuid, "storage.own_storage")
    {:ok, _} = Permissions.grant_permission(role.uuid, "integrations")

    {:ok, plain_role} = Roles.create_role(%{name: "Plain #{n}"})
    {:ok, _} = Permissions.grant_permission(plain_role.uuid, "storage")
    {:ok, _} = Permissions.grant_permission(plain_role.uuid, "storage.create_library")

    {:ok, site} =
      Storage.create_bucket(%{
        name: "site-#{n}",
        provider: "local",
        endpoint: Path.join(System.tmp_dir!(), "pk_own_storage"),
        enabled: true
      })

    %{role: role, plain_role: plain_role, site: site}
  end

  defp user!(role) do
    {:ok, user} =
      Auth.register_user(%{
        "email" => "own-storage-#{System.unique_integer([:positive])}@example.com",
        "password" => "ValidPassword123!"
      })

    {:ok, _} = Roles.assign_role(user, role.name)
    user
  end

  defp scope(user), do: Scope.for_user(Repo.get!(Auth.User, user.uuid))

  defp connection!(user, name \\ "mine") do
    {:ok, %{uuid: uuid}} =
      Integrations.add_connection("object_storage", name, nil, owner: {:user, user.uuid})

    {:ok, _} =
      Integrations.save_setup(uuid, %{"access_key" => "AKIA", "secret_key" => "s"}, nil,
        owner: {:user, user.uuid}
      )

    uuid
  end

  defp storage(user, extra \\ %{}) do
    Map.merge(
      %{
        "mode" => "only",
        "integration_uuid" => connection!(user),
        "provider" => "s3",
        "bucket_name" => "my-photos",
        "region" => "eu-central-1"
      },
      extra
    )
  end

  # A probe that says the bucket works, and remembers what it was asked.
  defp probe_ok do
    test = self()

    fn params ->
      send(test, {:probed, params})
      :ok
    end
  end

  defp create(user, storage, opts \\ [probe: probe_ok()]) do
    Libraries.create_user_library(scope(user), %{"name" => "Photos", "storage" => storage}, opts)
  end

  describe "who may" do
    test "needs the storage.own_storage permission", %{plain_role: role} do
      user = user!(role)

      refute Libraries.may_use_own_storage?(scope(user))
      assert {:error, :not_allowed} = create(user, storage(user))
      assert Storage.list_owned_buckets(user.uuid) == []
    end

    test "needs the Integrations permission: the keys are a personal connection", %{role: role} do
      {:ok, no_integrations} =
        Roles.create_role(%{name: "No integrations #{System.unique_integer([:positive])}"})

      for key <- ["storage", "storage.create_library", "storage.own_storage"],
          do: {:ok, _} = Permissions.grant_permission(no_integrations.uuid, key)

      user = user!(no_integrations)
      refute Libraries.may_use_own_storage?(scope(user))

      assert Libraries.may_use_own_storage?(scope(user!(role)))
    end

    test "needs the site to allow it", %{role: role} do
      user = user!(role)
      assert Libraries.may_use_own_storage?(scope(user))

      {:ok, _} = Settings.update_boolean_setting("storage_user_buckets_enabled", false)

      refute Libraries.may_use_own_storage?(scope(user))
      assert {:error, :not_allowed} = create(user, storage(user))
    end

    test "a library on the site's storage needs neither", %{plain_role: role} do
      user = user!(role)

      assert {:ok, %Library{storage_profile_uuid: nil}} =
               Libraries.create_user_library(scope(user), %{"name" => "Plain"})

      assert {:ok, %Library{storage_profile_uuid: nil}} =
               Libraries.create_user_library(scope(user), %{
                 "name" => "Plain too",
                 "storage" => %{"mode" => "site"}
               })
    end

    test "an unknown mode is refused", %{role: role} do
      user = user!(role)

      assert {:error, :not_allowed} = create(user, storage(user, %{"mode" => "both"}))
    end
  end

  describe "only mode" do
    test "creates the bucket, the profile and the library together", %{role: role} do
      user = user!(role)

      assert {:ok, %Library{} = library} = create(user, storage(user))

      assert is_binary(library.storage_profile_uuid)
      profile = Profiles.get_profile(library.storage_profile_uuid)
      assert profile.owner_uuid == user.uuid
      assert [%{role: "primary"}] = profile.buckets

      assert [%{owner_uuid: owner, name: "Photos", bucket_name: "my-photos"}] =
               Storage.list_owned_buckets(user.uuid)

      assert owner == user.uuid
    end

    test "probes the bucket first, as the user", %{role: role} do
      user = user!(role)
      {:ok, _} = create(user, storage(user))

      assert_received {:probed, params}
      assert params["owner_uuid"] == user.uuid
      assert params["bucket_name"] == "my-photos"
      assert is_binary(params["integration_uuid"])
    end
  end

  describe "backup mode" do
    test "keeps the site's buckets and adds the user's as a backup", %{role: role, site: site} do
      user = user!(role)

      assert {:ok, library} = create(user, storage(user, %{"mode" => "backup"}))

      profile = Profiles.get_profile(library.storage_profile_uuid)
      roles = Map.new(profile.buckets, &{to_string(&1.bucket_uuid), &1.role})

      assert roles[to_string(site.uuid)] == "primary"
      assert "backup" in Map.values(roles)
    end
  end

  describe "a failure leaves nothing behind" do
    test "a probe that fails creates nothing, and says why", %{role: role} do
      user = user!(role)
      failing = fn _params -> {:error, "The bucket can be read but not written to"} end

      assert {:error, {:storage, "The bucket can be read but not written to"}} =
               create(user, storage(user), probe: failing)

      assert Storage.list_owned_buckets(user.uuid) == []
      assert Libraries.list_user_libraries(user.uuid) == []
    end

    test "bucket fields that do not pass are reported as a changeset, and not probed", %{
      role: role
    } do
      user = user!(role)

      assert {:error, {:storage, %Ecto.Changeset{} = changeset}} =
               create(user, storage(user, %{"endpoint" => "https://10.0.0.5"}))

      assert %{endpoint: [_]} =
               Ecto.Changeset.traverse_errors(changeset, fn {message, _} -> message end)

      refute_received {:probed, _}
      assert Storage.list_owned_buckets(user.uuid) == []
      assert Libraries.list_user_libraries(user.uuid) == []
    end

    test "someone else's connection is refused", %{role: role} do
      user = user!(role)
      other = user!(role)

      assert {:error, {:storage, %Ecto.Changeset{}}} =
               create(user, storage(user, %{"integration_uuid" => connection!(other)}))

      assert Storage.list_owned_buckets(user.uuid) == []
    end

    test "backup mode with no site storage to back up creates nothing", %{role: role} do
      user = user!(role)
      Repo.delete_all(PhoenixKit.Modules.Storage.ProfileBucket)

      assert {:error, :no_site_storage} = create(user, storage(user, %{"mode" => "backup"}))

      assert Storage.list_owned_buckets(user.uuid) == []
      assert Libraries.list_user_libraries(user.uuid) == []
    end

    test "the library limit is still enforced, and leaves no bucket behind", %{role: role} do
      user = user!(role)
      {:ok, _} = Settings.update_setting("storage_user_library_limit", "1")
      {:ok, _} = Libraries.create_user_library(scope(user), %{"name" => "First"})

      assert {:error, :limit_reached} = create(user, storage(user))
      assert Storage.list_owned_buckets(user.uuid) == []
    end
  end

  describe "buckets from the integration" do
    test "the provider, region and endpoint are the integration's, not asked again", %{role: role} do
      user = user!(role)

      {:ok, %{uuid: uuid}} =
        Integrations.add_connection("object_storage", "tigris", nil, owner: {:user, user.uuid})

      {:ok, _} =
        Integrations.save_setup(
          uuid,
          %{"access_key" => "AKIA", "secret_key" => "s", "endpoint" => "t3.storage.dev"},
          nil,
          owner: {:user, user.uuid}
        )

      assert {:ok, library} =
               create(user, %{
                 "mode" => "only",
                 "targets" => [%{"integration_uuid" => uuid, "bucket_name" => "my-photos"}]
               })

      assert %{bucket: bucket} = Profiles.user_storage_for([library])[to_string(library.uuid)]

      assert {bucket.provider, bucket.endpoint, bucket.integration_uuid} ==
               {"tigris", "t3.storage.dev", uuid}

      assert_received {:probed, %{"provider" => "tigris", "endpoint" => "t3.storage.dev"}}
    end

    test "more integrations than the maximum are refused before anything is made", %{role: role} do
      user = user!(role)

      targets =
        for n <- 1..(Profiles.max_user_buckets() + 1) do
          %{"integration_uuid" => connection!(user, "int#{n}"), "bucket_name" => "bucket-#{n}"}
        end

      assert {:error, {:storage, message}} =
               create(user, %{"mode" => "only", "targets" => targets})

      assert message =~ "at most"
      assert Storage.list_owned_buckets(user.uuid) == []
    end

    test "the same bucket twice is refused", %{role: role} do
      user = user!(role)
      uuid = connection!(user)
      target = %{"integration_uuid" => uuid, "bucket_name" => "same"}

      assert {:error, {:storage, message}} =
               create(user, %{"mode" => "only", "targets" => [target, target]})

      assert message =~ "same bucket"
    end

    test "list_own_buckets asks the integration, described without its keys", %{role: role} do
      user = user!(role)
      uuid = connection!(user)
      test = self()

      list = fn bucket ->
        send(test, {:listed, bucket})
        {:ok, ["b-two", "a-one"]}
      end

      assert {:ok, ["b-two", "a-one"]} = Libraries.list_own_buckets(scope(user), uuid, list: list)

      assert_received {:listed, bucket}
      assert bucket.integration_uuid == uuid
      assert bucket.owner_uuid == user.uuid
      assert bucket.provider == "s3"
      assert is_nil(bucket.access_key_id) and is_nil(bucket.secret_access_key)
    end

    test "list_own_buckets is for a user who may use their own storage, and their own integration",
         %{role: role, plain_role: plain_role} do
      user = user!(role)
      other = user!(role)
      theirs = connection!(other)
      list = fn _bucket -> flunk("must not be asked") end

      assert {:error, :not_allowed} =
               Libraries.list_own_buckets(scope(user!(plain_role)), connection!(user), list: list)

      assert {:error, message} = Libraries.list_own_buckets(scope(user), theirs, list: list)
      assert message =~ "not yours"
    end

    test "integration_summary names the service and never a secret", %{role: role} do
      user = user!(role)
      uuid = connection!(user)

      summary = Libraries.integration_summary(user.uuid, uuid)

      assert %{provider: "s3", service: "aws_s3"} = summary
      refute inspect(summary) =~ "AKIA"
      assert is_nil(Libraries.integration_summary(user!(role).uuid, uuid))
    end
  end

  test "the choice is final: the library cannot be moved off its own storage", %{role: role} do
    user = user!(role)
    {:ok, library} = create(user, storage(user))

    assert {:error, :user_storage_locked} = Profiles.set_library_profile(library, nil)
  end
end
