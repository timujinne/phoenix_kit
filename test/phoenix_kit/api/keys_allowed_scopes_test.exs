defmodule PhoenixKit.API.KeysAllowedScopesTest do
  @moduledoc """
  `PhoenixKit.API.Keys.allowed_scopes_for/1`: the scopes an owner could be given,
  from the tools of the enabled modules and the owner's permissions.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport

  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.KeyTestSupport.SharedScopeModule
  alias PhoenixKit.API.Registry
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles

  setup do
    register_fake_module!()
    %{owner: owner_user()}
  end

  describe "allowed_scopes_for/1" do
    test "allowed scopes are those of the enabled tools whose permission the owner holds", ctx do
      assert Keys.allowed_scopes_for(ctx.owner) == Enum.sort(all_scopes())

      {reader, _} = user_with(["media"])
      assert Keys.allowed_scopes_for(reader) == [read_scope()]

      {manager, _} = user_with(["media", "media.manage"])
      assert Keys.allowed_scopes_for(manager) == Enum.sort([read_scope(), write_scope()])

      {nobody, _} = user_with([])
      assert Keys.allowed_scopes_for(nobody) == []
    end

    test "a module switched off in api_disabled_modules offers no scopes, the others keep theirs",
         ctx do
      ModuleRegistry.register(SharedScopeModule)
      on_exit(fn -> ModuleRegistry.unregister(SharedScopeModule) end)
      shared = SharedScopeModule.scope()
      assert shared in Keys.allowed_scopes_for(ctx.owner)

      {:ok, _} = Settings.update_setting("api_disabled_modules", "apikeytest")

      assert Keys.allowed_scopes_for(ctx.owner) == [shared]

      {:ok, _} = Settings.update_setting("api_disabled_modules", "")
      assert Keys.allowed_scopes_for(ctx.owner) == Enum.sort([shared | all_scopes()])
    end

    test "a scope shared by tools of different permissions needs all of those permissions" do
      ModuleRegistry.register(SharedScopeModule)
      on_exit(fn -> ModuleRegistry.unregister(SharedScopeModule) end)
      shared = SharedScopeModule.scope()

      {media_only, _} = user_with(["media"])
      {jobs_only, _} = user_with(["jobs.manage"])
      {both, _} = user_with(["media", "jobs.manage"])

      refute shared in Keys.allowed_scopes_for(media_only)
      refute shared in Keys.allowed_scopes_for(jobs_only)
      assert shared in Keys.allowed_scopes_for(both)
      assert shared in Keys.allowed_scopes_for(owner_user())

      # The scope is refused for the owner who lacks one of the permissions, so a key can
      # never carry it to a tool whose permission its owner does not hold.
      assert {:error, :invalid_scopes} =
               Keys.create_key(media_only, scope_of(media_only), %{name: "k", scopes: [shared]})

      # Hiding the stricter tool leaves a scope that only needs `media`.
      {:ok, _} = Settings.update_setting("api_disabled_tools", "apishared.read_b")
      assert shared in Keys.allowed_scopes_for(media_only)
      refute shared in Keys.allowed_scopes_for(jobs_only)
    end

    test "a stored shared scope is not effective for an owner who lacks one permission" do
      ModuleRegistry.register(SharedScopeModule)
      on_exit(fn -> ModuleRegistry.unregister(SharedScopeModule) end)
      start_key_cache!()
      shared = SharedScopeModule.scope()

      {user, role, scope} = api_holder(["media", "jobs.manage"])
      {_key, token} = create_key!(user, scope, %{scopes: [shared]})

      {:ok, actor} = Keys.verify(token, nil)
      assert actor.scopes == [shared]

      :ok = Permissions.revoke_permission(role.uuid, "jobs.manage")

      {:ok, actor} = Keys.verify(token, nil)
      assert actor.scopes == []
      assert Enum.all?(Registry.visible_tools(:admin, actor.scopes), &(&1.scope != shared))
    end

    test "the allowed scopes are a subset of the scopes the admin tools declare" do
      assert Enum.any?(ModuleRegistry.all_api_tools(), &(&1.name == "apikeytest.public_thing"))

      admin_scopes =
        for tool <- ModuleRegistry.all_api_tools(), tool.audience == :admin, do: tool.scope

      {user, _} = user_with(["media"])

      for allowed <- [Keys.allowed_scopes_for(user), Keys.allowed_scopes_for(owner_user())] do
        assert allowed != []
        assert Enum.all?(allowed, &(&1 in admin_scopes))
        assert Enum.all?(allowed, &String.contains?(&1, ":"))
      end
    end

    test "the role switcher does not narrow what the API allows" do
      {:ok, _} = Settings.update_boolean_setting("role_switcher_enabled", true)

      {reader_role, _} = role_with(["media"])
      {writer_role, _} = role_with(["media", "media.manage"])
      user = register_user!()
      {:ok, _} = Roles.assign_role(user, reader_role.name)
      {:ok, _} = Roles.assign_role(user, writer_role.name)

      # The user is acting as the reader: the web scope has no media.manage.
      acting_as_reader = %{user | active_role_uuid: reader_role.uuid}

      refute Scope.can?(
               Scope.for_user(acting_as_reader),
               "media.manage"
             )

      # The API rights are the union of all roles.
      assert Keys.allowed_scopes_for(acting_as_reader) == Enum.sort([read_scope(), write_scope()])
    end
  end
end
