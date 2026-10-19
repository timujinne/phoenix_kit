defmodule PhoenixKitWeb.Live.Settings.ApiModulesTest do
  @moduledoc """
  Settings -> API: the per-module switches.

  Every module that declares API tools has a switch. Off adds the module's key to
  `api_disabled_modules` (kept as the same newline-separated list), and
  `PhoenixKit.API.Registry` then withholds the module's tools. The event names the module
  by key and the state it wants; the server checks both again, and re-reads the person's
  rights first, like every other event of the page.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.Activity
  alias PhoenixKit.API.Config
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.Registry
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth.Scope
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.RolePermission
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @path Routes.path("/admin/settings/api")
  @row "#api-module-row-apikeytest"
  @switch "#api-module-switch-apikeytest"

  setup %{conn: conn} do
    KeyTestSupport.register_fake_module!()

    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")
    {:ok, _} = Permissions.grant_permission(role.uuid, "api")

    %{conn: log_in_user(conn, admin), admin: admin}
  end

  defp tool_names, do: Enum.map(Registry.all_tools(), & &1.name)

  defp page_assigns(view), do: :sys.get_state(view.pid).socket.assigns

  defp changed_settings(admin) do
    Activity.list(action: "setting.changed", actor_uuid: admin.uuid).entries
    |> Enum.map(& &1.metadata["key"])
  end

  # The page's scope is captured at mount; a plain delete sends no PubSub message,
  # so the page does not hear of it: the window the server-side re-check is for.
  defp drop_api_silently! do
    role = Roles.get_role_by_name("Admin")

    {1, _} =
      Repo.delete_all(
        from(rp in RolePermission, where: rp.role_uuid == ^role.uuid and rp.module_key == "api")
      )

    :ok
  end

  test "the card lists the module with its switch on, as every module is on by default", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, @path)

    assert has_element?(view, "#api-modules-card")
    assert has_element?(view, @row)
    assert has_element?(view, ~s(#{@switch}[phx-click="set_module_api"][checked]))
    assert "apikeytest.list_things" in tool_names()
  end

  test "the switch turns the module's tools off and on again, with the admin in the history", %{
    conn: conn,
    admin: admin
  } do
    {:ok, view, _html} = live(conn, @path)
    switch = element(view, @switch)

    render_click(switch)
    assert Config.disabled_modules() == ["apikeytest"]
    refute Enum.any?(tool_names(), &String.starts_with?(&1, "apikeytest."))
    refute has_element?(view, "#{@switch}[checked]")
    assert {:ok, _tool} = Registry.find("system.get_identity", :admin)

    render_click(switch)
    assert Config.disabled_modules() == []
    assert "apikeytest.list_things" in tool_names()
    assert has_element?(view, "#{@switch}[checked]")

    assert changed_settings(admin) == ["api_disabled_modules", "api_disabled_modules"]
  end

  test "the switch names the module and the action, and says API on or API off", %{conn: conn} do
    {:ok, view, _html} = live(conn, @path)

    assert has_element?(
             view,
             ~s(#{@switch}[aria-label="Switch the API of API key test module off"])
           )

    assert has_element?(view, "#{@row} label", "API on")

    render_click(element(view, @switch))

    assert has_element?(
             view,
             ~s(#{@switch}[aria-label="Switch the API of API key test module on"])
           )

    assert has_element?(view, "#{@row} label", "API off")
    refute has_element?(view, "#{@row} label", "API on")
  end

  test "the flash names the module and the state it is in", %{conn: conn} do
    {:ok, view, _html} = live(conn, @path)

    assert render_click(element(view, @switch)) =~ "The API of API key test module is off."
    assert render_click(element(view, @switch)) =~ "The API of API key test module is on."
  end

  describe "the list is read from the database, not from the settings cache" do
    setup do
      KeyTestSupport.start_cache_registry!()
      start_supervised!({PhoenixKit.Cache, name: :settings})
      :ok
    end

    test "a stale cached list on this node does not drop a module another node switched off",
         %{conn: conn} do
      {:ok, _} = Settings.update_setting("api_disabled_modules", "gone_module")
      # What a node that has not heard of the write yet still holds.
      PhoenixKit.Cache.put(:settings, "api_disabled_modules", "")
      assert Config.disabled_modules() == []

      {:ok, view, _html} = live(conn, @path)
      element(view, @switch) |> render_click()

      assert Settings.get_setting("api_disabled_modules") == "gone_module\napikeytest"
      assert Config.disabled_modules() == ["gone_module", "apikeytest"]
    end

    test "switching on with a stale cached list keeps the other modules switched off",
         %{conn: conn} do
      {:ok, _} = Settings.update_setting("api_disabled_modules", "apikeytest\ngone_module")
      PhoenixKit.Cache.put(:settings, "api_disabled_modules", "apikeytest")

      {:ok, view, _html} = live(conn, @path)
      element(view, @switch) |> render_click()

      assert Settings.get_setting("api_disabled_modules") == "gone_module"
    end
  end

  describe "a switch that cannot be saved" do
    test "says so, changes nothing and leaves no history", %{conn: conn, admin: admin} do
      # The setting holds at most 1000 characters: this list leaves no room for one more key.
      full = String.duplicate("g", 995)
      {:ok, _} = Settings.update_setting("api_disabled_modules", full)
      {:ok, view, _html} = live(conn, @path)

      html = render_click(element(view, @switch))

      assert html =~ "The switch could not be saved."
      refute html =~ "The API of API key test module"
      assert Settings.get_setting("api_disabled_modules") == full
      assert Config.disabled_modules() == [full]
      assert "apikeytest.list_things" in tool_names()
      assert changed_settings(admin) == []
    end
  end

  test "only this module's key changes: keys of modules that are not installed stay", %{
    conn: conn
  } do
    {:ok, _} = Settings.update_setting("api_disabled_modules", "gone_module")
    {:ok, view, _html} = live(conn, @path)

    refute has_element?(view, "#api-module-row-gone_module")
    element(view, @switch) |> render_click()
    assert Config.disabled_modules() == ["gone_module", "apikeytest"]

    element(view, @switch) |> render_click()
    assert Config.disabled_modules() == ["gone_module"]
  end

  test "asking for the state the module is already in changes and logs nothing", %{
    conn: conn,
    admin: admin
  } do
    {:ok, view, _html} = live(conn, @path)

    # Already on: no setting row is made for nothing.
    html = render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "on"})
    refute html =~ "could not be saved"
    assert Settings.get_setting("api_disabled_modules") == nil
    assert changed_settings(admin) == []

    render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "off"})
    render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "off"})
    assert Config.disabled_modules() == ["apikeytest"]
    assert changed_settings(admin) == ["api_disabled_modules"]

    render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "on"})
    render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "on"})
    assert Config.disabled_modules() == []
    assert changed_settings(admin) == ["api_disabled_modules", "api_disabled_modules"]
  end

  describe "forged input" do
    test "a module the page does not list is refused and writes nothing", %{
      conn: conn,
      admin: admin
    } do
      {:ok, view, _html} = live(conn, @path)

      # "evil" does not exist; "media" is a real module key that declares no tools.
      for key <- ["evil", "media", "", "system", "apikeytest\ngone"] do
        html = render_click(view, "set_module_api", %{"module" => key, "state" => "off"})

        assert html =~ "That action is not available.", inspect(key)
      end

      assert Settings.get_setting("api_disabled_modules") == nil
      assert Config.disabled_modules() == []
      assert changed_settings(admin) == []
    end

    test "a state other than on or off, and params of the wrong shape, write nothing", %{
      conn: conn
    } do
      {:ok, view, _html} = live(conn, @path)

      for params <- [
            %{"module" => "apikeytest", "state" => "maybe"},
            %{"module" => "apikeytest", "state" => true},
            %{"module" => "apikeytest"},
            %{"state" => "off"},
            %{"module" => ["apikeytest"], "state" => "off"},
            %{"module" => %{"a" => "b"}, "state" => "off"}
          ] do
        html = render_click(view, "set_module_api", params)
        assert html =~ "That action is not available.", inspect(params)
      end

      assert Config.disabled_modules() == []
      assert has_element?(view, "#api-settings-page")
    end
  end

  describe "rights are checked again on the server" do
    test "after the person lost api, the switch writes nothing", %{conn: conn, admin: admin} do
      {:ok, view, _html} = live(conn, @path)

      drop_api_silently!()
      # Not vacuous: the page has not heard of it, its scope still says api.
      assert Scope.can?(page_assigns(view).phoenix_kit_current_scope, "api")

      html = render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "off"})

      assert html =~ "You are not allowed to do that."
      assert Config.disabled_modules() == []
      assert "apikeytest.list_things" in tool_names()
      assert changed_settings(admin) == []
    end

    test "a person blocked while the page was open can do nothing", %{conn: conn, admin: admin} do
      {:ok, view, _html} = live(conn, @path)

      # A plain update: blocking through the context would also end the session
      # and close the page, which is not the window under test.
      {1, _} =
        Repo.update_all(from(u in User, where: u.uuid == ^admin.uuid), set: [is_active: false])

      html = render_click(view, "set_module_api", %{"module" => "apikeytest", "state" => "off"})

      assert html =~ "You are not allowed to do that."
      assert Config.disabled_modules() == []
    end
  end
end
