defmodule PhoenixKitWeb.Live.ModulesApiBadgeTest do
  @moduledoc """
  The Modules page marks a module that declares API tools with a badge, linking to the
  module's switch in Settings -> API: "API off" when the module's switch is off, "API idle"
  when the switch is on but nothing can call the module now (it is disabled, or every
  audience it serves is switched off), "API on" otherwise.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleDiscovery
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @modules_path Routes.path("/admin/modules")

  defmodule WithTools do
    def module_key, do: "badge_with_tools"
    def module_name, do: "Badge with tools"

    def permission_metadata,
      do: %{
        key: "badge_with_tools",
        label: "Badge with tools",
        icon: "hero-puzzle-piece",
        description: "A test module."
      }

    def enabled?, do: :persistent_term.get({__MODULE__, :enabled}, true)
    def get_config, do: %{enabled: enabled?()}

    def enable_system, do: :persistent_term.put({__MODULE__, :enabled}, true)
    def disable_system, do: :persistent_term.put({__MODULE__, :enabled}, false)

    def api_tools do
      [Tool.new!(name: "badge_with_tools.search", audience: :public, handler: {__MODULE__, :run})]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  defmodule BothAudiences do
    def module_key, do: "badge_both_audiences"
    def module_name, do: "Badge both audiences"

    def permission_metadata,
      do: %{
        key: "badge_both_audiences",
        label: "Badge both audiences",
        icon: "hero-puzzle-piece",
        description: "A test module."
      }

    def enabled?, do: true
    def get_config, do: %{enabled: true}

    def api_tools do
      [
        Tool.new!(
          name: "badge_both_audiences.list",
          audience: :admin,
          scope: "badge_both_audiences.things:read",
          permission: "badge_both_audiences",
          handler: {__MODULE__, :run}
        ),
        Tool.new!(
          name: "badge_both_audiences.search",
          audience: :public,
          handler: {__MODULE__, :run}
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  defmodule WithoutTools do
    def module_key, do: "badge_without_tools"
    def module_name, do: "Badge without tools"

    def permission_metadata,
      do: %{
        key: "badge_without_tools",
        label: "Badge without tools",
        icon: "hero-puzzle-piece",
        description: "A test module."
      }

    def enabled?, do: true
    def get_config, do: %{enabled: true}
  end

  @fixtures [WithTools, WithoutTools, BothAudiences]

  setup %{conn: conn} do
    :persistent_term.put({WithTools, :enabled}, true)
    for mod <- @fixtures, do: ModuleRegistry.register(mod)
    # The page lists external modules from the discovery cache; put these in it.
    :persistent_term.put({ModuleDiscovery, :external_modules}, @fixtures)

    on_exit(fn ->
      for mod <- @fixtures, do: ModuleRegistry.unregister(mod)
      ModuleDiscovery.clear_cache()
      :persistent_term.erase({WithTools, :enabled})
    end)

    owner = Auth.get_user_by_email("seed-owner@phoenixkit.test")
    %{conn: log_in_user(conn, owner)}
  end

  defp public_api!(state), do: {:ok, _} = Settings.update_setting("api_public_enabled", state)
  defp admin_api!(state), do: {:ok, _} = Settings.update_setting("api_admin_enabled", state)

  test "a module with tools shows API on, one without shows nothing", %{conn: conn} do
    public_api!("true")
    {:ok, view, _html} = live(conn, @modules_path)

    assert has_element?(view, "#module-api-badge-badge_with_tools", "API on")
    refute has_element?(view, "#module-api-badge-badge_without_tools")
  end

  test "the badge links to the API settings", %{conn: conn} do
    {:ok, view, _html} = live(conn, @modules_path)

    href = view |> element("#module-api-badge-badge_with_tools") |> render() |> href_of()
    assert href == Routes.path("/admin/settings/api") <> "#api-modules-card"
  end

  test "the badge follows the module's switch, whatever the API sides are", %{conn: conn} do
    public_api!("true")
    {:ok, _} = Settings.update_setting("api_disabled_modules", "badge_with_tools")

    {:ok, view, _html} = live(conn, @modules_path)

    assert has_element?(view, "#module-api-badge-badge_with_tools", "API off")
    refute has_element?(view, "#module-api-badge-badge_with_tools", "API on")

    public_api!("false")
    {:ok, view, _html} = live(conn, @modules_path)
    assert has_element?(view, "#module-api-badge-badge_with_tools", "API off")
  end

  describe "a module whose switch is on but which nothing can call" do
    test "on a default install, both API sides are off: idle, not on", %{conn: conn} do
      {:ok, view, _html} = live(conn, @modules_path)

      assert has_element?(view, "#module-api-badge-badge_with_tools", "API idle")
      refute has_element?(view, "#module-api-badge-badge_with_tools", "API on")
    end

    test "only the side the module does not serve is on: idle; the side it serves: on",
         %{conn: conn} do
      admin_api!("true")
      {:ok, view, _html} = live(conn, @modules_path)
      assert has_element?(view, "#module-api-badge-badge_with_tools", "API idle")

      public_api!("true")
      {:ok, view, _html} = live(conn, @modules_path)
      assert has_element?(view, "#module-api-badge-badge_with_tools", "API on")
    end

    test "the module itself is disabled: idle", %{conn: conn} do
      public_api!("true")
      :persistent_term.put({WithTools, :enabled}, false)

      {:ok, view, _html} = live(conn, @modules_path <> "?tab=disabled")

      assert has_element?(view, "#module-api-badge-badge_with_tools", "API idle")
    end

    test "a module serving both audiences with only one side on is not idle", %{conn: conn} do
      admin_api!("true")
      {:ok, view, _html} = live(conn, @modules_path)

      assert has_element?(view, "#module-api-badge-badge_both_audiences", "API on")
      refute has_element?(view, "#module-api-badge-badge_both_audiences", "API idle")
    end
  end

  describe "toggling the module on the page" do
    setup do
      public_api!("true")
      :ok
    end

    defp toggle(view), do: render_click(view, "toggle_module", %{"key" => "badge_with_tools"})
    defp open_tab(view, tab), do: render_click(view, "switch_modules_tab", %{"tab" => tab})

    test "the badge follows the toggle in both directions", %{conn: conn} do
      {:ok, view, _html} = live(conn, @modules_path)
      assert has_element?(view, "#module-api-badge-badge_with_tools", "API on")

      toggle(view)
      open_tab(view, "disabled")
      assert has_element?(view, "#module-api-badge-badge_with_tools", "API idle")
      refute has_element?(view, "#module-api-badge-badge_with_tools", "API on")

      toggle(view)
      open_tab(view, "active")
      assert has_element?(view, "#module-api-badge-badge_with_tools", "API on")
      refute has_element?(view, "#module-api-badge-badge_with_tools", "API idle")
    end
  end

  test "a person without the api permission sees the state but gets no link" do
    public_api!("true")
    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")
    {:ok, _} = Permissions.grant_permission(role.uuid, "badge_with_tools")

    {:ok, view, _html} =
      Phoenix.ConnTest.build_conn() |> log_in_user(admin) |> live(@modules_path)

    assert has_element?(view, "span#module-api-badge-badge_with_tools", "API on")
    refute has_element?(view, "a#module-api-badge-badge_with_tools")
  end

  defp href_of(html) do
    [_, href] = Regex.run(~r/href="([^"]+)"/, html)
    href
  end
end
