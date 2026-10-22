defmodule PhoenixKitWeb.Live.Settings.ApiSessionWriteTest do
  @moduledoc """
  Settings -> API: the "Agent may act" box of a module that has write tools. On adds the
  module's key to `api_session_write_modules`, the allow-list of the writes a person's live
  session may propose. It is off by default, shown only for a module with write tools,
  disabled while the module's API is off, and every change is in the settings history.
  The server checks the module, the state and the person's rights again, like the switch.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Activity
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RolePermission
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @path Routes.path("/admin/settings/api")
  @box "#api-module-session-write-apikeytest"
  @switch "#api-module-switch-apikeytest"

  # A module whose admin tools only read: it has no box.
  defmodule ReadOnlyModule do
    @moduledoc false
    def module_key, do: "sessionwrite_reader"
    def module_name, do: "Reader module"
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "sessionwrite_reader.list_things",
          audience: :admin,
          scope: "sessionwrite_reader.things:read",
          permission: "media",
          handler: {__MODULE__, :run},
          annotations: %{read_only: true}
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  setup %{conn: conn} do
    KeyTestSupport.register_fake_module!()
    :ok = ModuleRegistry.register(ReadOnlyModule)
    on_exit(fn -> ModuleRegistry.unregister(ReadOnlyModule) end)

    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")
    {:ok, _} = Permissions.grant_permission(role.uuid, "api")

    %{conn: log_in_user(conn, admin), admin: admin}
  end

  defp changed_settings(admin) do
    Activity.list(action: "setting.changed", actor_uuid: admin.uuid).entries
    |> Enum.map(& &1.metadata["key"])
  end

  defp set(view, key, state),
    do: render_click(view, "set_module_session_write", %{"module" => key, "state" => state})

  test "a module with write tools has the box, off by default; a module that only reads has none",
       %{conn: conn} do
    {:ok, view, _html} = live(conn, @path)

    assert has_element?(view, ~s(#{@box}[phx-click="set_module_session_write"]))
    refute has_element?(view, "#{@box}[checked]")
    refute has_element?(view, "#{@box}[disabled]")
    assert has_element?(view, ~s(#{@box}[aria-label="Let the agent act in API key test module"]))
    assert has_element?(view, "#api-module-row-apikeytest label", "Agent may act")
    assert has_element?(view, "#api-modules-session-write-hint")

    assert has_element?(view, "#api-module-row-sessionwrite_reader")
    refute has_element?(view, "#api-module-session-write-sessionwrite_reader")
    assert Config.session_write_modules() == []
  end

  test "the box lets the agent act and stops it again, with the admin in the history", %{
    conn: conn,
    admin: admin
  } do
    {:ok, view, _html} = live(conn, @path)

    html = render_click(element(view, @box))
    assert html =~ "The agent may act in API key test module."
    assert Config.session_write_modules() == ["apikeytest"]
    assert has_element?(view, "#{@box}[checked]")

    assert has_element?(
             view,
             ~s(#{@box}[aria-label="Stop the agent acting in API key test module"])
           )

    html = render_click(element(view, @box))
    assert html =~ "The agent may no longer act in API key test module."
    assert Config.session_write_modules() == []
    refute has_element?(view, "#{@box}[checked]")

    assert changed_settings(admin) == ["api_session_write_modules", "api_session_write_modules"]
    # The module's API switch is another setting and did not move.
    assert Config.disabled_modules() == []
  end

  test "only this module's key changes; other keys stay", %{conn: conn} do
    {:ok, _} = Settings.update_setting("api_session_write_modules", "gone_module")
    {:ok, view, _html} = live(conn, @path)

    set(view, "apikeytest", "on")
    assert Config.session_write_modules() == ["gone_module", "apikeytest"]

    set(view, "apikeytest", "off")
    assert Config.session_write_modules() == ["gone_module"]
  end

  test "asking for the state it is already in changes and logs nothing", %{
    conn: conn,
    admin: admin
  } do
    {:ok, view, _html} = live(conn, @path)

    set(view, "apikeytest", "off")
    assert Settings.get_setting("api_session_write_modules") == nil

    set(view, "apikeytest", "on")
    set(view, "apikeytest", "on")
    assert changed_settings(admin) == ["api_session_write_modules"]
  end

  describe "while the module's API is off" do
    test "the box is disabled and cannot be turned on, but can be turned off", %{
      conn: conn,
      admin: admin
    } do
      {:ok, view, _html} = live(conn, @path)
      set(view, "apikeytest", "on")
      render_click(element(view, @switch))

      assert has_element?(view, "#{@box}[disabled]")

      html = set(view, "apikeytest", "off")
      refute html =~ "That action is not available."
      assert Config.session_write_modules() == []

      html = set(view, "apikeytest", "on")
      assert html =~ "That action is not available."
      assert Config.session_write_modules() == []

      assert changed_settings(admin) == [
               "api_session_write_modules",
               "api_disabled_modules",
               "api_session_write_modules"
             ]
    end
  end

  describe "forged input" do
    test "a module that is not listed or has no write tools is refused and writes nothing", %{
      conn: conn,
      admin: admin
    } do
      {:ok, view, _html} = live(conn, @path)

      for key <- ["evil", "sessionwrite_reader", "media", "", "apikeytest\ngone"] do
        assert set(view, key, "on") =~ "That action is not available.", inspect(key)
      end

      for params <- [
            %{"module" => "apikeytest", "state" => "maybe"},
            %{"module" => "apikeytest"},
            %{"module" => ["apikeytest"], "state" => "on"}
          ] do
        html = render_click(view, "set_module_session_write", params)
        assert html =~ "That action is not available.", inspect(params)
      end

      assert Settings.get_setting("api_session_write_modules") == nil
      assert changed_settings(admin) == []
    end
  end

  describe "rights are checked again on the server" do
    test "after the person lost api, the box writes nothing", %{conn: conn, admin: admin} do
      {:ok, view, _html} = live(conn, @path)

      role = Roles.get_role_by_name("Admin")

      {1, _} =
        Repo.delete_all(
          from(rp in RolePermission, where: rp.role_uuid == ^role.uuid and rp.module_key == "api")
        )

      assert set(view, "apikeytest", "on") =~ "You are not allowed to do that."
      assert Config.session_write_modules() == []
      assert changed_settings(admin) == []
    end
  end
end
