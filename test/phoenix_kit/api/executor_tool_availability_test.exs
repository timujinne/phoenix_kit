defmodule PhoenixKit.API.ExecutorToolAvailabilityTest do
  @moduledoc """
  `PhoenixKit.API.Executor.tool_availability/1`: every admin tool of every registered
  module, switched on or off, with what keeps it from a person's live session. Each reason
  alone, the reasons together, the "Agent may act" mark that only opens writes, keys that
  it does not touch, and the available tools of a session that are exactly what
  `visible_for/3` lists with `allow: :all`. Real settings, roles and sessions.
  """
  use PhoenixKit.DataCase, async: false

  import PhoenixKit.Test.ApiHarness

  alias PhoenixKit.Activity.Entry
  alias PhoenixKit.API.Auth, as: ApiAuth
  alias PhoenixKit.API.Executor
  alias PhoenixKit.API.KeyTestSupport
  alias PhoenixKit.ModuleRegistry
  alias PhoenixKit.Settings.Setting
  alias PhoenixKit.Test.ApiSessionTools
  alias PhoenixKit.Users.Auth
  alias PhoenixKit.Users.Auth.SessionRef
  alias PhoenixKit.Users.Auth.User
  alias PhoenixKit.Users.Auth.UserToken
  alias PhoenixKit.Users.Roles

  @read "availtest.list_things"
  @write "availtest.set_thing"
  @module "availtest"

  defmodule AvailTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "availtest"
    def module_name, do: "Availability test tools"
    def enabled?, do: :persistent_term.get({__MODULE__, :enabled}, true)
    def set_enabled(on?), do: :persistent_term.put({__MODULE__, :enabled}, on?)

    def api_tools do
      [
        Tool.new!(
          name: "availtest.list_things",
          audience: :admin,
          scope: "availtest.things:read",
          permission: "dashboard",
          handler: {__MODULE__, :run},
          annotations: %{read_only: true}
        ),
        Tool.new!(
          name: "availtest.set_thing",
          audience: :admin,
          scope: "availtest.things:write",
          permission: "settings",
          handler: {__MODULE__, :run},
          danger: :always
        ),
        Tool.new!(name: "availtest.search", audience: :public, handler: {__MODULE__, :run})
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  # Declares a name AvailTools already has: the registry keeps the first module's.
  defmodule DupTools do
    @moduledoc false
    alias PhoenixKit.API.Tool

    def module_key, do: "availdup"
    def module_name, do: "Availability duplicate"
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "availtest.list_things",
          audience: :admin,
          scope: "availdup.things:read",
          permission: "users",
          handler: {__MODULE__, :run},
          annotations: %{read_only: true}
        )
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  setup do
    setup_api()
    :ok = ModuleRegistry.register(AvailTools)
    :ok = ModuleRegistry.register(ApiSessionTools)
    AvailTools.set_enabled(true)

    on_exit(fn ->
      ModuleRegistry.unregister(AvailTools)
      ModuleRegistry.unregister(ApiSessionTools)
      AvailTools.set_enabled(true)
    end)

    :ok
  end

  # A setting cannot hold an empty value; no row is the empty list.
  defp put_list(key, []), do: Repo.delete_all(from(s in Setting, where: s.key == ^key))
  defp put_list(key, items), do: put_setting(key, Enum.join(items, "\n"))

  defp open_writes(keys), do: put_list("api_session_write_modules", keys)

  defp entry(name, scope \\ nil) do
    entries = Executor.tool_availability(scope)
    assert [entry] = Enum.filter(entries, &(&1.name == name))
    entry
  end

  defp status(name, scope \\ nil), do: entry(name, scope).status

  defp closed_for?({:closed, reasons}, reason), do: reason in reasons
  defp closed_for?(:available, _reason), do: false

  defp person(permissions) do
    user = KeyTestSupport.register_user!()
    {role, _} = KeyTestSupport.role_with(permissions)
    {:ok, _} = Roles.assign_role(user, role.name)
    user
  end

  defp scope_of(%User{} = user), do: KeyTestSupport.scope_of(user)

  defp session!(%User{} = user) do
    token = Auth.generate_user_session_token(user)
    %UserToken{uuid: uuid} = Auth.get_session_token_record(token)
    {uuid, user.uuid}
  end

  describe "the entries" do
    test "describe each admin tool of a module: key, name, kind, permission, scope, danger" do
      assert %{
               module_key: @module,
               module_name: "Availability test tools",
               name: @read,
               kind: :read,
               permission: "dashboard",
               scope: "availtest.things:read",
               danger: nil
             } = entry(@read)

      assert %{kind: :write, permission: "settings", danger: :always} = entry(@write)
    end

    test "list no public tool and none of core's own system tools" do
      names = Enum.map(Executor.tool_availability(), & &1.name)

      refute "availtest.search" in names
      refute Enum.any?(names, &String.starts_with?(&1, "system."))
      assert "testkit.read_items" in names
    end

    test "list a tool once, sorted by module name and then by tool name" do
      entries = Executor.tool_availability()
      keys = Enum.map(entries, &{String.downcase(&1.module_name), &1.name})

      assert keys == Enum.sort(keys)
      assert Enum.uniq_by(entries, &{&1.module_key, &1.name}) == entries
    end
  end

  describe "a name two modules declare" do
    @tag capture_log: true
    test "is listed for the module the registry serves it from, and for a closed one" do
      :ok = ModuleRegistry.register(DupTools)
      on_exit(fn -> ModuleRegistry.unregister(DupTools) end)

      assert %{module_key: @module, status: :available} = entry(@read)

      AvailTools.set_enabled(false)

      assert [
               %{module_key: "availdup", status: :available},
               %{module_key: @module, status: {:closed, [:module_disabled]}}
             ] =
               Executor.tool_availability()
               |> Enum.filter(&(&1.name == @read))
    end
  end

  describe "each reason alone, without a scope" do
    test "a read tool of a module that is on is available" do
      assert status(@read) == :available
    end

    test "a write tool is closed until its module is marked \"Agent may act\"" do
      assert status(@write) == {:closed, [:agent_writes_off]}

      open_writes([@module])

      assert status(@write) == :available
    end

    test ":module_disabled: a switched-off module's tools are listed, closed" do
      AvailTools.set_enabled(false)

      assert status(@read) == {:closed, [:module_disabled]}
    end

    test ":api_off: the module's API is switched off in api_disabled_modules" do
      put_list("api_disabled_modules", [@module])

      assert status(@read) == {:closed, [:api_off]}
      assert status("testkit.read_items") == :available
    end

    test ":tool_hidden: the tool is listed in api_disabled_tools" do
      put_list("api_disabled_tools", [@read])

      assert status(@read) == {:closed, [:tool_hidden]}
      assert status(@write) == {:closed, [:agent_writes_off]}
    end

    test "without a scope there is never :no_permission" do
      statuses = Enum.map(Executor.tool_availability(), & &1.status)

      refute Enum.any?(statuses, &closed_for?(&1, :no_permission))
    end
  end

  describe ":no_permission, with a scope" do
    test "the scope lacks the tool's permission" do
      scope = scope_of(person(["dashboard"]))
      open_writes([@module])

      assert status(@read, scope) == :available
      assert status(@write, scope) == {:closed, [:no_permission]}
    end

    test "the scope holds the permission" do
      scope = scope_of(person(["dashboard", "settings"]))
      open_writes([@module])

      assert status(@read, scope) == :available
      assert status(@write, scope) == :available
    end

    test "the scope lacks the permission of another tool on the same scope" do
      # sessiontest.read_a and read_b share one scope; read_a needs dashboard, read_b users.
      scope = scope_of(person(["dashboard"]))

      assert status("sessiontest.read_a", scope) == {:closed, [:no_permission]}

      both = scope_of(person(["dashboard", "users"]))
      assert status("sessiontest.read_a", both) == :available
    end

    test "a closed module's tool is :no_permission only when its permission is missing" do
      put_list("api_disabled_modules", [@module])

      assert status(@read, scope_of(person(["dashboard"]))) == {:closed, [:api_off]}
      assert status(@read, scope_of(person(["users"]))) == {:closed, [:api_off, :no_permission]}
    end
  end

  describe "reasons together" do
    test "every reason at once comes in a fixed order" do
      AvailTools.set_enabled(false)
      put_list("api_disabled_modules", [@module])
      put_list("api_disabled_tools", [@write])

      assert status(@write, scope_of(person(["dashboard"]))) ==
               {:closed,
                [:module_disabled, :api_off, :tool_hidden, :agent_writes_off, :no_permission]}
    end

    test "a hidden write tool of a module that may not act" do
      put_list("api_disabled_tools", [@write])

      assert status(@write) == {:closed, [:tool_hidden, :agent_writes_off]}

      open_writes([@module])

      assert status(@write) == {:closed, [:tool_hidden]}
    end
  end

  describe "the \"Agent may act\" mark" do
    test "changes the write tools only" do
      scope = scope_of(person(["dashboard", "settings", "users"]))
      before = Executor.tool_availability(scope)

      open_writes([@module, "api_session_tools", "api_test_tools"])
      after_mark = Executor.tool_availability(scope)

      {read_before, write_before} = Enum.split_with(before, &(&1.kind == :read))
      {read_after, write_after} = Enum.split_with(after_mark, &(&1.kind == :read))

      assert read_before == read_after
      assert write_before != write_after

      refute Enum.any?(
               read_before ++ read_after,
               &closed_for?(&1.status, :agent_writes_off)
             )
    end

    test "does not touch what a key may call" do
      {owner, _role} = user_with(["settings"])
      {_key, token} = issue_key(owner, ["availtest.things:write"])

      conn = fn ->
        :post |> api_conn("/", token: token) |> ApiAuth.call(ApiAuth.init(audience: :admin))
      end

      assert status(@write) == {:closed, [:agent_writes_off]}
      assert {:ok, tools, _} = Executor.visible(conn.(), :admin)
      assert @write in Enum.map(tools, & &1.name)

      open_writes([@module])
      assert {:ok, ^tools, _} = Executor.visible(conn.(), :admin)
    end
  end

  test "writes nothing: no setting, no audit entry" do
    open_writes([@module])
    settings = Repo.all(from(s in Setting, order_by: s.key, select: {s.key, s.value}))
    entries = Repo.aggregate(Entry, :count)

    _ = Executor.tool_availability()
    _ = Executor.tool_availability(scope_of(person(["dashboard"])))

    assert Repo.all(from(s in Setting, order_by: s.key, select: {s.key, s.value})) == settings
    assert Repo.aggregate(Entry, :count) == entries
  end

  describe "agrees with visible_for/3, allow: :all" do
    defp available_names(scope) do
      scope
      |> Executor.tool_availability()
      |> Enum.filter(&(&1.status == :available))
      |> Enum.map(& &1.name)
      |> Enum.sort()
    end

    defp visible_names({token_uuid, user_uuid} = ref) do
      assert {:ok, scope} = SessionRef.scope_for_session(token_uuid, user_uuid)
      assert {:ok, tools, _headers} = Executor.visible_for(ref, :admin, allow: :all)
      {scope, tools |> Enum.map(& &1.name) |> Enum.sort()}
    end

    test "for sessions with different rights and settings" do
      cases = [
        {["dashboard"], [], [], []},
        {["dashboard", "settings"], ["api_session_tools"], [], []},
        {["dashboard", "settings", "users"], [@module, "api_session_tools"], [@read], []},
        {["settings", "users"], [@module, "api_test_tools"], [], ["api_session_tools"]},
        {[], [@module], [], []}
      ]

      for {permissions, writes, hidden_tools, hidden_modules} <- cases do
        open_writes(writes)
        put_list("api_disabled_tools", hidden_tools)
        put_list("api_disabled_modules", hidden_modules)

        {scope, visible} = permissions |> person() |> session!() |> visible_names()

        assert available_names(scope) == visible,
               "permissions #{inspect(permissions)}, writes #{inspect(writes)}"
      end
    end

    test "for a session that acts as one of its roles" do
      :ok =
        KeyTestSupport.write_setting(fn ->
          PhoenixKit.Settings.update_boolean_setting("role_switcher_enabled", true)
        end)

      user = KeyTestSupport.register_user!()
      {reader, _} = KeyTestSupport.role_with(["dashboard"])
      {writer, _} = KeyTestSupport.role_with(["settings"])
      {:ok, _} = Roles.assign_role(user, reader.name)
      {:ok, _} = Roles.assign_role(user, writer.name)
      open_writes([@module])

      {token_uuid, _} = ref = session!(user)

      Repo.update_all(from(t in UserToken, where: t.uuid == ^token_uuid),
        set: [active_role_uuid: writer.uuid]
      )

      {scope, visible} = visible_names(ref)

      assert @write in visible
      refute @read in visible
      assert available_names(scope) == visible
    end
  end
end
