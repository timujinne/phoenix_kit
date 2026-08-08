defmodule PhoenixKit.Dashboard.SubPermissionTabTest do
  # async: false — registers a fake module and mutates global registry state.
  use ExUnit.Case, async: false

  alias PhoenixKit.Dashboard.Registry
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Permissions

  defmodule FakeShop do
    def module_key, do: "fake_shop"
    def module_name, do: "Fake Shop"
    def enabled?, do: true

    def permission_metadata do
      %{
        key: "fake_shop",
        label: "Fake Shop",
        icon: "hero-shopping-bag",
        description: "Fake module for sub-permission tab tests",
        sub_permissions: [
          %{key: "manage_settings", label: "Manage settings", description: "Settings page"}
        ]
      }
    end
  end

  defmodule FakeSettingsView do
  end

  setup do
    ModuleRegistry.register(FakeShop)

    on_exit(fn -> ModuleRegistry.unregister(FakeShop) end)

    :ok
  end

  # A tab may be gated on a SUB-permission ("fake_shop.manage_settings").
  # Those are declared through `permission_metadata/0`, and `register_custom_key/2`
  # rejects a dotted key outright — the raise then aborted the whole callback
  # before it could cache the view → permission mapping, so the module silently
  # lost core's automatic gate on that view and warned on every boot.
  test "a tab gated on a sub-permission caches its view mapping without registering a custom key" do
    assert "fake_shop.manage_settings" in Permissions.sub_permission_keys()

    Registry.auto_register_custom_permission(%{
      id: :fake_shop_settings,
      label: "Fake Shop Settings",
      path: "fake-shop/settings",
      permission: "fake_shop.manage_settings",
      live_view: {FakeSettingsView, :index}
    })

    assert Permissions.custom_view_permissions()[FakeSettingsView] ==
             "fake_shop.manage_settings",
           "the view → permission mapping core's admin gate reads was not cached"

    refute "fake_shop.manage_settings" in Permissions.custom_keys(),
           "a sub-permission must not be re-registered as a custom key"
  end

  test "the resolved sub-key still reports its module as enabled" do
    # `feature_enabled?/1` resolves a dotted key through its parent, so gating
    # a view on the sub-key must not read as "module disabled" and lock
    # everyone out — including the Owner.
    assert Permissions.feature_enabled?("fake_shop.manage_settings")
    assert "fake_shop.manage_settings" in Permissions.all_module_keys()
  end

  test "an orphaned sub-key does not open the view its base no longer allows" do
    # The cascade normally keeps a sub-key's base granted; this is the case
    # where a sub row outlives its base (a module leaves the registry and
    # returns). `can?/2` rejects it, and the automatic view gate must agree.
    orphan =
      %Scope{}
      |> Map.put(:cached_permissions, MapSet.new(["fake_shop.manage_settings"]))
      |> Map.put(:cached_roles, ["User"])

    refute Scope.can?(orphan, "fake_shop.manage_settings")

    held =
      %Scope{}
      |> Map.put(:cached_permissions, MapSet.new(["fake_shop", "fake_shop.manage_settings"]))
      |> Map.put(:cached_roles, ["User"])

    assert Scope.can?(held, "fake_shop.manage_settings")
  end
end
