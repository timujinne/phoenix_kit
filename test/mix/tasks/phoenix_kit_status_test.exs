defmodule Mix.Tasks.PhoenixKit.StatusTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.PhoenixKit.Status, as: StatusTask
  alias PhoenixKit.Install.StatusReport

  # `run/1` isn't a unit-test seam (starts the app, needs a real DB) — same
  # reasoning as `Mix.Tasks.PhoenixKit.RepairTest`: exercise the pure decision
  # the task makes. Here that decision is what `--exit-code` reports to a deploy
  # script, so every shape `StatusReport.next_action/3` can emit gets a case.

  describe "exit_code/2 — only a verifiably ready install passes" do
    test "ready with modules queried → 0" do
      assert StatusTask.exit_code({:ready, "Ready"}, []) == 0
      assert StatusTask.exit_code({:ready, "Ready"}, [module_entry(:up_to_date, 1, 1)]) == 0
    end

    test "not installed → 1" do
      assert StatusTask.exit_code({:install, "mix igniter.install phoenix_kit"}, []) == 1
    end

    test "core behind → 1" do
      action = {:update, "mix phoenix_kit.update", ["database is V165, code expects V166"]}
      assert StatusTask.exit_code(action, []) == 1
    end

    test "a module behind → 1" do
      action = {:update, "mix phoenix_kit.update", ["Boards is V01, code expects V02"]}
      assert StatusTask.exit_code(action, [module_entry(:needs_update, 1, 2)]) == 1
    end

    test "a module whose version cannot be read → 1" do
      assert StatusTask.exit_code({:check_modules, ["Boards"]}, [module_entry(:error, 0, nil)]) ==
               1
    end

    test "unreadable core version comment → 1" do
      assert StatusTask.exit_code({:fix_version_comment, "mix phoenix_kit.doctor"}, []) == 1
    end

    test "database unreachable → 1" do
      action = {:fix_connection, "Fix the database connection"}
      assert StatusTask.exit_code(action, :not_queried) == 1
    end
  end

  describe "exit_code/2 — fail-closed when modules were never queried" do
    # The regression this guards: `next_action/3` maps {:up_to_date, _} plus
    # `:not_queried` to {:ready, "Ready"}. Keying the gate on that tuple alone
    # passes a deploy whose module versions were never read — a silent pass, the
    # precise failure `--exit-code` was added to eliminate.
    test "ready but modules not queried → 1, even though the action says Ready" do
      action = StatusReport.next_action({:up_to_date, 166}, :not_queried, "public")

      assert action == {:ready, "Ready"},
             "next_action/3 changed shape — revisit the fail-closed case below"

      assert StatusTask.exit_code(action, :not_queried) == 1
    end

    test "the same action with an empty (but queried) module list → 0" do
      # `[]` and `:not_queried` are deliberately distinct: a core-only install
      # genuinely has no modules and must still pass the gate.
      action = StatusReport.next_action({:up_to_date, 166}, [], "public")

      assert StatusTask.exit_code(action, []) == 0
    end
  end

  describe "exit_code/2 covers every next_action/3 shape" do
    test "no shape falls through to an unintended 0" do
      actions = [
        StatusReport.next_action({:not_installed}, [], "public"),
        StatusReport.next_action({:unreachable, :econnrefused}, :not_queried, "public"),
        StatusReport.next_action({:unknown_version}, [], "public"),
        StatusReport.next_action({:needs_update, 165, 166}, [], "public"),
        StatusReport.next_action({:up_to_date, 166}, [module_entry(:error, 0, nil)], "public"),
        StatusReport.next_action(
          {:up_to_date, 166},
          [module_entry(:needs_update, 1, 2)],
          "public"
        )
      ]

      for action <- actions do
        assert StatusTask.exit_code(action, []) == 1,
               "#{inspect(action)} must not pass the deploy gate"
      end
    end
  end

  # Shape mirrors `PhoenixKit.Migrations.Modules.list/1` entries. `pending/1`
  # and `failed/1` both filter on `:status`, so that is the field that matters
  # here — the versions are along for readability.
  defp module_entry(status, installed, target) do
    %{
      name: "Boards",
      module: Some.Module,
      migration_module: Some.Module.Migrations,
      installed: installed,
      target: target,
      status: status,
      error: nil
    }
  end
end
