defmodule PhoenixKit.ModuleRegistryApiToolsTest do
  @moduledoc """
  The `api_tools/0` callback of `PhoenixKit.Module` and its two readers,
  `ModuleRegistry.all_api_tools/0` (enabled modules, validated, tagged with the module)
  and `ModuleRegistry.disabled_api_tool?/2` (switched-off modules, for `module_disabled`).
  """
  # async: false - `register/1` changes global state.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.API.Tool
  alias PhoenixKit.ModuleRegistry

  defmodule DefaultsModule do
    use PhoenixKit.Module

    @impl PhoenixKit.Module
    def module_key, do: "api_tools_defaults_fake"
    @impl PhoenixKit.Module
    def module_name, do: "API tools defaults fake"
    @impl PhoenixKit.Module
    def enabled?, do: true
    @impl PhoenixKit.Module
    def enable_system, do: :ok
    @impl PhoenixKit.Module
    def disable_system, do: :ok
  end

  defmodule OverridingModule do
    use PhoenixKit.Module

    @impl PhoenixKit.Module
    def module_key, do: "api_tools_overriding_fake"
    @impl PhoenixKit.Module
    def module_name, do: "API tools overriding fake"
    @impl PhoenixKit.Module
    def enabled?, do: true
    @impl PhoenixKit.Module
    def enable_system, do: :ok
    @impl PhoenixKit.Module
    def disable_system, do: :ok

    @impl PhoenixKit.Module
    def api_tools do
      [
        Tool.new!(
          name: "apifake_use.list_things",
          audience: :admin,
          scope: "apifake_use.things:read",
          permission: "apifake_use",
          handler: {__MODULE__, :list}
        )
      ]
    end

    def list(_input, _ctx), do: {:ok, %{}}
  end

  defmodule OnModule do
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "apifake_on.list_things",
          audience: :admin,
          scope: "apifake_on.things:read",
          permission: "apifake_on",
          handler: {__MODULE__, :list}
        ),
        Tool.new!(
          name: "apifake_on.search_things",
          audience: :public,
          handler: {__MODULE__, :list}
        )
      ]
    end

    def list(_input, _ctx), do: {:ok, %{}}
  end

  defmodule OffModule do
    def enabled?, do: false

    def api_tools do
      [
        Tool.new!(
          name: "apifake_off.list_things",
          audience: :admin,
          scope: "apifake_off.things:read",
          permission: "apifake_off",
          handler: {__MODULE__, :list}
        )
      ]
    end

    def list(_input, _ctx), do: {:ok, %{}}
  end

  defmodule NoCallbackModule do
    def enabled?, do: true
  end

  defmodule RaisingModule do
    def enabled?, do: true
    def api_tools, do: raise("boom")
  end

  defmodule BadEntriesModule do
    def enabled?, do: true

    def api_tools do
      [
        %{name: "apifake_bad.not_a_struct"},
        %Tool{name: "apifake_bad.NotAName", audience: :admin, handler: {__MODULE__, :list}},
        Tool.new!(name: "apifake_bad.good_one", audience: :public, handler: {__MODULE__, :list})
      ]
    end
  end

  defmodule PublicWithScopeModule do
    def enabled?, do: true

    def api_tools do
      [
        %Tool{
          name: "apifake_pub.with_scope",
          audience: :public,
          scope: "apifake_pub.things:read",
          handler: {__MODULE__, :run}
        },
        Tool.new!(name: "apifake_pub.plain", audience: :public, handler: {__MODULE__, :run})
      ]
    end
  end

  defmodule BrokenTextModule do
    def enabled?, do: true

    def api_tools do
      [
        %Tool{
          name: "apifake_utf.bad_description",
          audience: :public,
          description: <<0xFF, 0xFE>>,
          handler: {__MODULE__, :run}
        },
        %Tool{
          name: "apifake_utf.bad_scope",
          audience: :admin,
          scope: <<0xFF>>,
          permission: "apifake_utf",
          handler: {__MODULE__, :run}
        },
        Tool.new!(name: "apifake_utf.good_one", audience: :public, handler: {__MODULE__, :run})
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  defmodule DuplicateModule do
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(
          name: "apifake_on.list_things",
          audience: :admin,
          scope: "apifake_dup.things:read",
          permission: "apifake_dup",
          handler: {__MODULE__, :list}
        )
      ]
    end
  end

  defmodule SystemSquatterModule do
    def enabled?, do: true

    def api_tools do
      [
        Tool.new!(name: "system.get_identity", audience: :admin, handler: {__MODULE__, :run}),
        Tool.new!(name: "system.apifake_probe", audience: :public, handler: {__MODULE__, :run}),
        Tool.new!(name: "apifake_sys.good_one", audience: :public, handler: {__MODULE__, :run})
      ]
    end

    def run(_input, _ctx), do: {:ok, %{}}
  end

  # Warn-once flags live in :persistent_term for the life of the VM; the tests below assert
  # the first warning, so every fake starts without one.
  @warn_once_fakes [
    BadEntriesModule,
    BrokenTextModule,
    PublicWithScopeModule,
    RaisingModule,
    SystemSquatterModule
  ]

  setup do
    erase_warn_once_flags()
    on_exit(&erase_warn_once_flags/0)
  end

  defp erase_warn_once_flags do
    for mod <- @warn_once_fakes, kind <- [:bad_api_tool, :api_tools_failed, :system_api_tool] do
      :persistent_term.erase({ModuleRegistry, :warned, {kind, mod}})
    end

    :ok
  end

  defp with_registered(modules, fun) do
    Enum.each(modules, &ModuleRegistry.register/1)

    try do
      fun.()
    after
      Enum.each(modules, &ModuleRegistry.unregister/1)
    end
  end

  defp names(tools), do: tools |> Enum.map(& &1.name) |> Enum.sort()

  describe "use PhoenixKit.Module" do
    test "api_tools/0 defaults to no tools" do
      assert DefaultsModule.api_tools() == []
    end

    test "a module that uses PhoenixKit.Module can override api_tools/0" do
      assert [%Tool{name: "apifake_use.list_things"}] = OverridingModule.api_tools()

      with_registered([OverridingModule], fn ->
        assert ["apifake_use.list_things"] ==
                 ModuleRegistry.all_api_tools()
                 |> Enum.filter(&(&1.module == OverridingModule))
                 |> names()
      end)
    end

    test "api_tools/0 is an optional callback" do
      assert {:api_tools, 0} in PhoenixKit.Module.behaviour_info(:optional_callbacks)
      assert {:api_tools, 0} in PhoenixKit.Module.behaviour_info(:callbacks)
    end
  end

  describe "all_api_tools/0" do
    test "returns the tools of enabled modules, tagged with the module that declared them" do
      with_registered([OnModule], fn ->
        tools = ModuleRegistry.all_api_tools()

        assert ["apifake_on.list_things", "apifake_on.search_things"] ==
                 tools |> Enum.filter(&(&1.module == OnModule)) |> names()

        assert Enum.all?(tools, &match?(%Tool{}, &1))
      end)
    end

    test "leaves out the tools of a disabled module" do
      with_registered([OnModule, OffModule], fn ->
        names = names(ModuleRegistry.all_api_tools())

        assert "apifake_on.list_things" in names
        refute "apifake_off.list_things" in names
      end)
    end

    test "a module without the callback, and one whose callback raises, contribute nothing" do
      log =
        capture_log(fn ->
          with_registered([OnModule, NoCallbackModule, RaisingModule], fn ->
            tools = ModuleRegistry.all_api_tools()

            assert "apifake_on.list_things" in names(tools)
            refute Enum.any?(tools, &(&1.module in [NoCallbackModule, RaisingModule]))
          end)
        end)

      assert log =~ "RaisingModule.api_tools/0 failed"
    end

    test "a callback that raises is reported once, not on every call" do
      first =
        capture_log(fn ->
          with_registered([RaisingModule], fn -> ModuleRegistry.all_api_tools() end)
        end)

      assert first =~ "RaisingModule.api_tools/0 failed: boom"

      later =
        capture_log(fn ->
          with_registered([RaisingModule], fn ->
            ModuleRegistry.all_api_tools()
            ModuleRegistry.disabled_api_tool?("apifake_on.list_things", :admin)
          end)
        end)

      refute later =~ "RaisingModule"
    end

    test "a module cannot declare tools in the system.* namespace" do
      log =
        capture_log(fn ->
          with_registered([SystemSquatterModule], fn ->
            tools = ModuleRegistry.all_api_tools()

            assert ["apifake_sys.good_one"] ==
                     tools |> Enum.filter(&(&1.module == SystemSquatterModule)) |> names()

            refute Enum.any?(tools, &String.starts_with?(&1.name, "system."))
          end)
        end)

      assert log =~ "SystemSquatterModule.api_tools/0 declares system."
      assert log =~ "reserved for core"
    end

    test "drops an entry that is not a valid tool, warns once, keeps the module's good tools" do
      first =
        capture_log(fn ->
          with_registered([BadEntriesModule], fn ->
            assert ["apifake_bad.good_one"] ==
                     ModuleRegistry.all_api_tools()
                     |> Enum.filter(&(&1.module == BadEntriesModule))
                     |> names()
          end)
        end)

      assert first =~ "BadEntriesModule.api_tools/0 returned"

      second =
        capture_log(fn ->
          with_registered([BadEntriesModule], fn -> ModuleRegistry.all_api_tools() end)
        end)

      refute second =~ "BadEntriesModule.api_tools/0 returned"
    end

    test "a public tool that names a scope is dropped as invalid" do
      log =
        capture_log(fn ->
          with_registered([PublicWithScopeModule], fn ->
            assert ["apifake_pub.plain"] ==
                     ModuleRegistry.all_api_tools()
                     |> Enum.filter(&(&1.module == PublicWithScopeModule))
                     |> names()
          end)
        end)

      assert log =~ "scope must be nil for a public tool"
    end

    test "a tool whose text is not valid UTF-8 is dropped, and every tool left encodes" do
      log =
        capture_log(fn ->
          with_registered([BrokenTextModule], fn ->
            tools =
              Enum.filter(ModuleRegistry.all_api_tools(), &(&1.module == BrokenTextModule))

            assert ["apifake_utf.good_one"] == names(tools)

            assert is_binary(
                     JSON.encode!(Enum.map(tools, &Map.take(&1, [:name, :title, :description])))
                   )
          end)
        end)

      assert log =~ "BrokenTextModule.api_tools/0 returned an invalid tool"
      assert log =~ "description must be valid UTF-8"
    end

    test "a name declared twice for one audience keeps the first registered" do
      capture_log(fn ->
        with_registered([OnModule, DuplicateModule], fn ->
          [tool] =
            Enum.filter(
              ModuleRegistry.all_api_tools(),
              &(&1.name == "apifake_on.list_things" and &1.audience == :admin)
            )

          assert tool.module == OnModule
        end)
      end)
    end
  end

  describe "disabled_api_tool?/2" do
    test "is true only for a tool of a switched-off module, for the audience it declares" do
      with_registered([OnModule, OffModule], fn ->
        assert ModuleRegistry.disabled_api_tool?("apifake_off.list_things", :admin)
        refute ModuleRegistry.disabled_api_tool?("apifake_off.list_things", :public)
        refute ModuleRegistry.disabled_api_tool?("apifake_on.list_things", :admin)
        refute ModuleRegistry.disabled_api_tool?("apifake_off.nope", :admin)
      end)
    end
  end

  describe "api_tool_names/1" do
    defp fake_names(audience) do
      audience
      |> ModuleRegistry.api_tool_names()
      |> Enum.filter(&String.starts_with?(&1, "apifake_"))
    end

    test "lists the tools of enabled and of switched-off modules alike" do
      with_registered([OnModule, OffModule], fn ->
        assert ["apifake_off.list_things", "apifake_on.list_things"] == fake_names(:admin)
      end)
    end

    test "keeps only the tools declared for the audience asked" do
      with_registered([OnModule, OffModule], fn ->
        assert ["apifake_on.search_things"] == fake_names(:public)
        refute "apifake_on.search_things" in fake_names(:admin)
        refute "apifake_on.list_things" in fake_names(:public)
      end)
    end

    test "is sorted and has no duplicates" do
      capture_log(fn ->
        with_registered([OnModule, DuplicateModule, OffModule], fn ->
          names = ModuleRegistry.api_tool_names(:admin)

          assert names == names |> Enum.uniq() |> Enum.sort()
          assert 1 == Enum.count(names, &(&1 == "apifake_on.list_things"))
        end)
      end)
    end

    test "drops an invalid tool and a system.* name, as the other readers do" do
      capture_log(fn ->
        with_registered([BadEntriesModule, SystemSquatterModule], fn ->
          assert ["apifake_bad.good_one", "apifake_sys.good_one"] == fake_names(:public)
          assert [] == fake_names(:admin)

          refute Enum.any?(
                   ModuleRegistry.api_tool_names(:public),
                   &String.starts_with?(&1, "system.")
                 )
        end)
      end)
    end

    test "a module whose api_tools/0 raises contributes nothing" do
      capture_log(fn ->
        with_registered([OnModule, RaisingModule], fn ->
          assert ["apifake_on.list_things"] == fake_names(:admin)
        end)
      end)
    end
  end

  describe "api_module_tools/0" do
    test "lists every module with tools, switched on or off, its tools tagged" do
      with_registered([OverridingModule, OnModule, OffModule, NoCallbackModule], fn ->
        entries =
          Enum.filter(
            ModuleRegistry.api_module_tools(),
            &(&1.module in [OverridingModule, OnModule, OffModule, NoCallbackModule])
          )

        assert [
                 %{module: OverridingModule, key: "api_tools_overriding_fake", enabled?: true},
                 %{module: OnModule, key: nil, enabled?: true, tools: on_tools},
                 %{module: OffModule, key: nil, enabled?: false, tools: [off_tool]}
               ] = entries

        assert ["apifake_on.list_things", "apifake_on.search_things"] == names(on_tools)
        assert Enum.all?(on_tools, &(&1.module == OnModule))
        assert %Tool{name: "apifake_off.list_things", module: OffModule} = off_tool
        assert Enum.all?(entries, &is_binary(&1.name))
      end)
    end

    test "drops an invalid tool and a system.* name, as the other readers do" do
      capture_log(fn ->
        with_registered([BadEntriesModule, SystemSquatterModule], fn ->
          tools =
            ModuleRegistry.api_module_tools()
            |> Enum.filter(&(&1.module in [BadEntriesModule, SystemSquatterModule]))
            |> Enum.flat_map(& &1.tools)

          assert ["apifake_bad.good_one", "apifake_sys.good_one"] == names(tools)
        end)
      end)
    end
  end
end
