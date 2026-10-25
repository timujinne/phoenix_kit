defmodule PhoenixKitWeb.Live.Settings.ApiModuleToolsTest do
  @moduledoc """
  Settings -> API: each module's row has a collapsible list of its admin tools, with what a
  person's live session (an assistant) may call by the install's settings alone
  (`PhoenixKit.API.Executor.tool_availability/1` without a scope): available, or closed and
  why. The list follows the module's switch, its "Agent may act" box and the hidden tools of
  "Limits and advanced"; the rights of each person are checked on top of it.
  """
  use PhoenixKitWeb.ConnCase, async: false

  alias PhoenixKit.API.Config
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Users.Permissions
  alias PhoenixKit.Users.Roles
  alias PhoenixKit.Utils.Routes

  @path Routes.path("/admin/settings/api")
  @tools "#api-module-tools-apikeytest"
  @write ~s([id="api-module-tool-apikeytest.set_things"])
  @read ~s([id="api-module-tool-moduletools_reader.list_things"])
  @off ~s([id="api-module-tool-moduletools_off.list_things"])

  # A module whose only admin tool reads.
  defmodule ReaderModule do
    @moduledoc false
    def module_key, do: "moduletools_reader"
    def module_name, do: "Reader module"
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "moduletools_reader.list_things",
          audience: :admin,
          scope: "moduletools_reader.things:read",
          permission: "media",
          handler: {__MODULE__, :run},
          annotations: %{read_only: true}
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  # A module that is switched off.
  defmodule OffModule do
    @moduledoc false
    def module_key, do: "moduletools_off"
    def module_name, do: "Switched-off module"
    def enabled?, do: false

    def api_tools do
      [
        Tool.new!(
          name: "moduletools_off.list_things",
          audience: :admin,
          scope: "moduletools_off.things:read",
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

    for module <- [ReaderModule, OffModule] do
      :ok = ModuleRegistry.register(module)
      on_exit(fn -> ModuleRegistry.unregister(module) end)
    end

    {admin, _token} = create_admin_user()
    role = Roles.get_role_by_name("Admin")
    {:ok, _} = Permissions.grant_permission(role.uuid, "api")

    %{conn: log_in_user(conn, admin)}
  end

  defp reasons(view, tool) do
    view
    |> render()
    |> LazyHTML.from_fragment()
    |> LazyHTML.query("#{tool} [data-reason]")
    |> LazyHTML.attribute("data-reason")
  end

  defp limits(hidden_tools) do
    limits = Config.rate_limits()

    %{
      "disabled_tools" => hidden_tools,
      "mcp_allowed_origins" => "",
      "preauth_fail_per_min" => Integer.to_string(limits.preauth_fail_per_min),
      "admin_per_min" => Integer.to_string(limits.admin_per_min),
      "public_token_per_min" => Integer.to_string(limits.public_token_per_min),
      "public_ip_per_min" => Integer.to_string(limits.public_ip_per_min),
      "new_rows_ip_hour" => Integer.to_string(limits.new_rows_ip_hour),
      "new_rows_global_hour" => Integer.to_string(limits.new_rows_global_hour)
    }
  end

  defp hide_tools(view, hidden_tools) do
    view
    |> form("#api-limits-form", %{"limits" => limits(hidden_tools)})
    |> render_submit()
  end

  test "each module's row lists its admin tools in a collapsible section", %{conn: conn} do
    {:ok, view, _html} = live(conn, @path)

    assert has_element?(view, "#api-module-row-apikeytest details#{@tools} > summary")
    refute has_element?(view, "#{@tools}[open]")
    assert has_element?(view, "#{@tools} summary", "Tools for the assistant: 0 of 3 available")
    assert has_element?(view, "#api-module-tools-note-apikeytest", "Rights are still checked")

    for verb <- ~w(list_things set_things run_jobs) do
      assert has_element?(view, ~s(#{@tools} [id="api-module-tool-apikeytest.#{verb}"]))
    end

    # Public tools are not the assistant's: only the admin ones are listed.
    refute has_element?(view, ~s([id="api-module-tool-apikeytest.public_thing"]))

    assert has_element?(view, @write, "apikeytest.set_things")
    assert has_element?(view, @write, "Writes")
    assert has_element?(view, @write, "Permission: media.manage")
    assert has_element?(view, ~s(#{@write}[data-status="closed"]), "Closed")
    assert has_element?(view, @write, "It writes, and “Agent may act” is off.")
    assert reasons(view, @write) == ["agent_writes_off"]

    assert has_element?(view, @read, "Read only")
    assert has_element?(view, @read, "Permission: media")
    assert has_element?(view, ~s(#{@read}[data-status="available"]), "Available")
    assert reasons(view, @read) == []

    assert has_element?(view, ~s(#{@off}[data-status="closed"]), "The module is switched off.")
    assert reasons(view, @off) == ["module_disabled"]
  end

  test "ticking and unticking “Agent may act” opens and closes the module's writes", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, @path)

    render_click(element(view, "#api-module-session-write-apikeytest"))
    assert has_element?(view, ~s(#{@write}[data-status="available"]), "Available")
    assert reasons(view, @write) == []
    assert has_element?(view, "#{@tools} summary", "Tools for the assistant: 3 of 3 available")
    # Reads do not depend on the box.
    assert has_element?(view, ~s(#{@read}[data-status="available"]))

    render_click(element(view, "#api-module-session-write-apikeytest"))
    assert reasons(view, @write) == ["agent_writes_off"]
    assert has_element?(view, "#{@tools} summary", "Tools for the assistant: 0 of 3 available")
  end

  test "switching a module's API off closes all its tools, and on opens them again", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, @path)

    render_click(element(view, "#api-module-switch-moduletools_reader"))
    assert has_element?(view, ~s(#{@read}[data-status="closed"]), "The module's API is off.")
    assert reasons(view, @read) == ["api_off"]

    render_click(element(view, "#api-module-switch-moduletools_reader"))
    assert has_element?(view, ~s(#{@read}[data-status="available"]))

    render_click(element(view, "#api-module-session-write-apikeytest"))
    render_click(element(view, "#api-module-switch-apikeytest"))
    assert reasons(view, @write) == ["api_off"]
  end

  test "a tool hidden in “Limits and advanced” is closed until it is shown again", %{
    conn: conn
  } do
    {:ok, view, _html} = live(conn, @path)

    hide_tools(view, "moduletools_reader.list_things\napikeytest.set_things")

    assert has_element?(
             view,
             ~s(#{@read}[data-status="closed"]),
             "The tool is hidden in “Limits and advanced”."
           )

    assert reasons(view, @read) == ["tool_hidden"]
    assert reasons(view, @write) == ["tool_hidden", "agent_writes_off"]

    hide_tools(view, "")
    assert has_element?(view, ~s(#{@read}[data-status="available"]))
    assert reasons(view, @write) == ["agent_writes_off"]
  end
end
