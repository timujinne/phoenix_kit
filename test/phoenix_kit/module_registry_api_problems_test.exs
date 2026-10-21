defmodule PhoenixKit.ModuleRegistryApiProblemsTest do
  @moduledoc """
  The `api_problems/0` callback of `PhoenixKit.Module` and its reader,
  `ModuleRegistry.all_api_problems/0`: the error codes enabled modules declare,
  validated, never shadowing a code of core.
  """
  # async: false - `register/1` changes global state.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias PhoenixKit.ModuleRegistry

  defmodule DefaultsModule do
    use PhoenixKit.Module

    @impl PhoenixKit.Module
    def module_key, do: "api_problems_defaults_fake"
    @impl PhoenixKit.Module
    def module_name, do: "API problems defaults fake"
    @impl PhoenixKit.Module
    def enabled?, do: true
    @impl PhoenixKit.Module
    def enable_system, do: :ok
    @impl PhoenixKit.Module
    def disable_system, do: :ok
  end

  defmodule OnModule do
    def enabled?, do: true

    def api_problems do
      %{
        pf_quota_spent: %{status: 429, title: "Quota spent", advice: "Wait for the next hour."},
        pf_gone: %{status: 410, title: "Gone", advice: nil}
      }
    end
  end

  defmodule OffModule do
    def enabled?, do: false

    def api_problems, do: %{pf_off_only: %{status: 409, title: "Off only", advice: nil}}
  end

  defmodule NoCallbackModule do
    def enabled?, do: true
  end

  defmodule RaisingModule do
    def enabled?, do: true
    def api_problems, do: raise("boom")
  end

  defmodule NoAdviceKeyModule do
    def enabled?, do: true
    def api_problems, do: %{pf_plain: %{status: 404, title: "Plain"}}
  end

  defmodule CoreShadowModule do
    def enabled?, do: true

    def api_problems do
      %{
        forbidden: %{status: 418, title: "Teapot", advice: "Nope."},
        pf_shadow_ok: %{status: 409, title: "Fine", advice: nil}
      }
    end
  end

  defmodule BadEntriesModule do
    def enabled?, do: true

    def api_problems do
      %{
        :pf_status_low => %{status: 200, title: "Too low", advice: nil},
        :pf_status_high => %{status: 600, title: "Too high", advice: nil},
        :pf_status_text => %{status: "404", title: "Text status", advice: nil},
        :pf_no_title => %{status: 404, advice: nil},
        :pf_blank_title => %{status: 404, title: "", advice: nil},
        :pf_bad_advice => %{status: 404, title: "Bad advice", advice: 5},
        :pf_not_a_map => 404,
        "pf_string_code" => %{status: 404, title: "String code", advice: nil},
        :pf_good => %{status: 404, title: "Good", advice: nil}
      }
    end
  end

  defmodule NotAMapModule do
    def enabled?, do: true
    def api_problems, do: [pf_list: %{status: 404, title: "A list", advice: nil}]
  end

  defmodule FirstDeclarerModule do
    def enabled?, do: true
    def api_problems, do: %{pf_twice: %{status: 404, title: "First", advice: "One."}}
  end

  defmodule SecondDeclarerModule do
    def enabled?, do: true
    def api_problems, do: %{pf_twice: %{status: 409, title: "Second", advice: "Two."}}
  end

  @modules [
    OnModule,
    OffModule,
    NoCallbackModule,
    RaisingModule,
    NoAdviceKeyModule,
    CoreShadowModule,
    BadEntriesModule,
    NotAMapModule,
    FirstDeclarerModule,
    SecondDeclarerModule
  ]

  setup do
    erase_warn_once_flags()
    on_exit(&erase_warn_once_flags/0)
    :ok
  end

  defp erase_warn_once_flags do
    for {{ModuleRegistry, :warned, key} = full, _} <- :persistent_term.get(),
        is_tuple(key),
        elem(key, 0) in [
          :api_problems_failed,
          :bad_api_problem,
          :shadowed_api_problem,
          :duplicate_api_problem
        ] do
      :persistent_term.erase(full)
    end
  end

  defp with_modules(modules, fun) do
    Enum.each(modules, &ModuleRegistry.register/1)

    try do
      fun.()
    after
      Enum.each(modules, &ModuleRegistry.unregister/1)
    end
  end

  test "the callback is optional and `use PhoenixKit.Module` defaults it to an empty map" do
    assert {:api_problems, 0} in PhoenixKit.Module.behaviour_info(:optional_callbacks)
    assert DefaultsModule.api_problems() == %{}
  end

  describe "all_api_problems/0" do
    test "collects the codes of enabled modules, with status, title and advice" do
      with_modules([OnModule, OffModule, NoCallbackModule], fn ->
        problems = ModuleRegistry.all_api_problems()

        assert problems.pf_quota_spent == %{
                 status: 429,
                 title: "Quota spent",
                 advice: "Wait for the next hour."
               }

        assert problems.pf_gone == %{status: 410, title: "Gone", advice: nil}
      end)
    end

    test "leaves out the codes of a module that is switched off" do
      with_modules([OnModule, OffModule], fn ->
        refute Map.has_key?(ModuleRegistry.all_api_problems(), :pf_off_only)
      end)
    end

    test "reads an advice that is missing as nil" do
      with_modules([NoAdviceKeyModule], fn ->
        assert ModuleRegistry.all_api_problems().pf_plain ==
                 %{status: 404, title: "Plain", advice: nil}
      end)
    end

    test "a module whose callback raises contributes nothing and is reported" do
      log =
        capture_log(fn ->
          with_modules([RaisingModule, OnModule], fn ->
            assert %{pf_gone: _} = ModuleRegistry.all_api_problems()
          end)
        end)

      assert log =~ "RaisingModule.api_problems/0 failed"
    end

    test "a module cannot override a code of core: the declaration is dropped with a warning" do
      log =
        capture_log(fn ->
          with_modules([CoreShadowModule], fn ->
            problems = ModuleRegistry.all_api_problems()

            refute Map.has_key?(problems, :forbidden)
            assert %{pf_shadow_ok: %{status: 409}} = problems
          end)
        end)

      assert log =~ "CoreShadowModule"
      assert log =~ "forbidden"
      assert log =~ "core"
    end

    test "an invalid entry is dropped with a warning and the valid ones stay" do
      log =
        capture_log(fn ->
          with_modules([BadEntriesModule], fn ->
            problems = ModuleRegistry.all_api_problems()

            assert Map.keys(problems) == [:pf_good]
          end)
        end)

      for code <- ~w(pf_status_low pf_status_high pf_status_text pf_no_title pf_blank_title
                     pf_bad_advice pf_not_a_map pf_string_code) do
        assert log =~ code, "#{code} was dropped without a warning"
      end

      refute log =~ "pf_good"
    end

    test "something that is not a map is ignored with a warning" do
      log =
        capture_log(fn ->
          with_modules([NotAMapModule], fn ->
            assert ModuleRegistry.all_api_problems() |> Map.keys() |> Enum.member?(:pf_list) ==
                     false
          end)
        end)

      assert log =~ "NotAMapModule.api_problems/0"
    end

    test "a code declared by two modules keeps the first, with a warning" do
      log =
        capture_log(fn ->
          with_modules([FirstDeclarerModule, SecondDeclarerModule], fn ->
            assert ModuleRegistry.all_api_problems().pf_twice.title == "First"
          end)
        end)

      assert log =~ "pf_twice"
    end

    test "warns once per module and code, not on every call" do
      with_modules([CoreShadowModule], fn ->
        first = capture_log(fn -> ModuleRegistry.all_api_problems() end)
        second = capture_log(fn -> ModuleRegistry.all_api_problems() end)

        assert first =~ "forbidden"
        refute second =~ "forbidden"
      end)
    end
  end

  test "the fake modules are all unregistered afterwards" do
    assert Enum.all?(@modules, &(&1 not in ModuleRegistry.all_modules()))
  end
end
