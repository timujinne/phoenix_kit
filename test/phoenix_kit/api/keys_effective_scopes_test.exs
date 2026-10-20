defmodule PhoenixKit.API.KeysEffectiveScopesTest do
  @moduledoc """
  `PhoenixKit.API.Keys.effective_scopes/1`: a key's scopes filtered by what its
  owner may do right now and by the tools that are currently enabled.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.API.KeyTestSupport

  alias PhoenixKit.API.Actor
  alias PhoenixKit.API.Keys
  alias PhoenixKit.API.Keys.Key
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions

  setup do
    register_fake_module!()
    start_key_cache!()

    owner = owner_user()
    %{owner: owner, owner_scope: scope_of(owner)}
  end

  describe "effective_scopes/1" do
    test "a scope no enabled tool declares grants nothing, whoever holds the key", ctx do
      {key, _} = create_key!(ctx.owner, ctx.owner_scope, %{scopes: [read_scope()]})

      # A scope of a module that has since been disabled stays on the key.
      Repo.update_all(from(k in Key, where: k.uuid == ^key.uuid),
        set: [scopes: [read_scope(), "disabledmodule.things:read"]]
      )

      stored = Repo.get!(Key, key.uuid)
      assert "disabledmodule.things:read" in stored.scopes
      assert Keys.effective_scopes(stored) == [read_scope()]
    end

    test "a tool hidden through api_disabled_tools stops granting its scope", ctx do
      {key, _} = create_key!(ctx.owner, ctx.owner_scope, %{scopes: [read_scope(), write_scope()]})
      assert Keys.effective_scopes(key) == Enum.sort([read_scope(), write_scope()])

      put_setting("api_disabled_tools", "apikeytest.set_things")

      assert Keys.effective_scopes(key) == [read_scope()]
      refute write_scope() in Keys.allowed_scopes_for(ctx.owner)
    end

    test "a module switched off in api_disabled_modules stops granting its scopes, and back on it grants them again",
         ctx do
      {key, token} =
        create_key!(ctx.owner, ctx.owner_scope, %{scopes: [read_scope(), write_scope()]})

      put_setting("api_disabled_modules", "apikeytest")

      assert Keys.effective_scopes(key) == []
      assert Keys.allowed_scopes_for(ctx.owner) == []
      assert {:ok, actor} = Keys.verify(token, nil)
      assert actor.scopes == []

      assert Enum.sort(Repo.get!(Key, key.uuid).scopes) ==
               Enum.sort([read_scope(), write_scope()])

      put_setting("api_disabled_modules", "")

      assert Keys.effective_scopes(key) == Enum.sort([read_scope(), write_scope()])
      assert {:ok, actor} = Keys.verify(token, nil)
      assert actor.scopes == Enum.sort([read_scope(), write_scope()])
    end

    test "effective_scopes/1 follows the owner's permissions live" do
      {user, role, scope} = api_holder(["media", "media.manage"])
      {key, _} = create_key!(user, scope, %{scopes: [read_scope(), write_scope()]})

      assert Keys.effective_scopes(key) == Enum.sort([read_scope(), write_scope()])

      :ok = Permissions.revoke_permission(role.uuid, "media.manage")
      assert Keys.effective_scopes(key) == [read_scope()]

      {:ok, _} = Auth.update_user_status(user, %{is_active: false})
      assert Keys.effective_scopes(key) == []
    end

    test "effective_scopes/1 of an actor is recomputed from the owner's current rights" do
      {user, role, scope} = api_holder(["media", "media.manage"])
      {_key, token} = create_key!(user, scope, %{scopes: [read_scope(), write_scope()]})
      {:ok, actor} = Keys.verify(token, nil)
      assert length(actor.scopes) == 2

      :ok = Permissions.revoke_permission(role.uuid, "media.manage")
      assert Keys.effective_scopes(actor) == [read_scope()]
      assert Keys.effective_scopes(%Actor{}) == []
    end
  end
end
