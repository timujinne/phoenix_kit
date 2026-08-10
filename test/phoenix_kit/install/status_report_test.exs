defmodule PhoenixKit.Install.StatusReportTest do
  use ExUnit.Case, async: true

  doctest PhoenixKit.Install.StatusReport

  alias PhoenixKit.Install.StatusReport

  describe "next_action/3 — core states" do
    test "never installed points at the installer" do
      assert StatusReport.next_action({:not_installed}, [], "public") ==
               {:install, "mix igniter.install phoenix_kit"}
    end

    test "unreachable database asks for the connection, not a migration" do
      assert {:fix_connection, message} =
               StatusReport.next_action({:unreachable, :econnrefused}, :not_queried, "public")

      refute message =~ "phoenix_kit.update"
    end

    test "everything matching is Ready" do
      assert StatusReport.next_action({:up_to_date, 159}, [], "public") == {:ready, "Ready"}
    end

    # This state reaches `next_action/3` only because `check_installation_status/1`
    # learned to report it, and the clause was missing when it did — `mix
    # phoenix_kit.status` died with a FunctionClauseError on the one anomaly it
    # exists to diagnose. One line here would have caught that; it did not exist.
    test "an unreadable version comment asks for a restamp, not an update" do
      assert {:fix_version_comment, message} =
               StatusReport.next_action({:unknown_version}, [], "public")

      assert message =~ "phoenix_kit.doctor"
      assert message =~ "COMMENT ON TABLE public.phoenix_kit"
    end

    test "the restamp instruction names the prefix it was asked about" do
      assert {:fix_version_comment, message} =
               StatusReport.next_action({:unknown_version}, :not_queried, "auth")

      assert message =~ "COMMENT ON TABLE auth.phoenix_kit"
    end
  end

  describe "next_action/3 — wording of a behind schema" do
    test "states the mismatch, not an available upgrade" do
      {:update, _cmd, reasons} =
        StatusReport.next_action({:needs_update, 159, 160}, [], "public")

      assert reasons == ["database is V159, code expects V160"]
    end

    test "no reason string implies an optional upgrade is on offer" do
      # `status` compares against the running release, never against Hex, so
      # "available"/"newer version" would be a claim it cannot make.
      {:update, _cmd, reasons} =
        StatusReport.next_action(
          {:needs_update, 1, 2},
          [entry("Inbox", 1, 2, :needs_update)],
          "public"
        )

      text = Enum.join(reasons, " ")
      refute text =~ ~r/available/i
      refute text =~ ~r/newer/i
      refute text =~ ~r/upgrade/i
    end

    test "single-digit versions are zero-padded to match the tree" do
      {:update, _cmd, [reason]} = StatusReport.next_action({:needs_update, 1, 9}, [], "public")

      assert reason == "database is V01, code expects V09"
    end
  end

  describe "next_action/3 — modules participate" do
    test "core current but a module behind is NOT Ready" do
      modules = [entry("Boards", 1, 1, :up_to_date), entry("Inbox", 1, 2, :needs_update)]

      assert {:update, "mix phoenix_kit.update", reasons} =
               StatusReport.next_action({:up_to_date, 159}, modules, "public")

      assert reasons == ["module schema behind: Inbox"]
    end

    test "a module with no tables yet counts as behind" do
      modules = [entry("Inbox", 0, 1, :not_installed)]

      assert {:update, _cmd, ["module schema behind: Inbox"]} =
               StatusReport.next_action({:up_to_date, 159}, modules, "public")
    end

    test "core behind AND a module behind report both in one action" do
      modules = [entry("Inbox", 1, 2, :needs_update)]

      assert {:update, _cmd, reasons} =
               StatusReport.next_action({:needs_update, 159, 160}, modules, "public")

      assert reasons == [
               "database is V159, code expects V160",
               "module schema behind: Inbox"
             ]
    end

    test "several behind modules are listed together" do
      modules = [entry("Inbox", 1, 2, :needs_update), entry("Boards", 0, 1, :not_installed)]

      assert {:update, _cmd, [reason]} =
               StatusReport.next_action({:up_to_date, 159}, modules, "public")

      assert reason =~ "Inbox"
      assert reason =~ "Boards"
    end

    test "all modules current leaves core's own reason alone" do
      modules = [entry("Inbox", 2, 2, :up_to_date)]

      assert {:update, _cmd, ["database is V159, code expects V160"]} =
               StatusReport.next_action({:needs_update, 159, 160}, modules, "public")
    end

    test "an unreadable module blocks Ready and names itself" do
      assert {:check_modules, ["Broken"]} =
               StatusReport.next_action({:up_to_date, 159}, [error_entry("Broken")], "public")
    end

    test "an unreadable module is never silently migrated" do
      # It is not `pending` — migrating a module whose installed version we
      # cannot read is worse than leaving it alone.
      modules = [error_entry("Broken"), entry("Inbox", 1, 2, :needs_update)]

      assert {:check_modules, names} =
               StatusReport.next_action({:up_to_date, 159}, modules, "public")

      assert names == ["Broken"]
    end

    test ":not_queried (database unreachable) does not fabricate module reasons" do
      assert StatusReport.next_action({:up_to_date, 159}, :not_queried, "public") ==
               {:ready, "Ready"}
    end
  end

  describe "prefix handling" do
    test "a named schema is threaded into the suggested command" do
      assert {:update, "mix phoenix_kit.update --prefix=auth", _} =
               StatusReport.next_action({:needs_update, 159, 160}, [], "auth")
    end

    test "the default schema needs no flag" do
      assert StatusReport.update_command("public") == "mix phoenix_kit.update"
    end
  end

  describe "describe/1" do
    test "a command with no reasons stays bare" do
      assert StatusReport.describe({:update, "mix phoenix_kit.update", []}) ==
               "mix phoenix_kit.update"
    end

    test "reasons are appended after an em dash and joined with semicolons" do
      assert StatusReport.describe({:update, "cmd", ["a", "b"]}) == "cmd — a; b"
    end

    test "every action shape renders to a non-empty string" do
      actions = [
        {:install, "mix igniter.install phoenix_kit"},
        {:fix_connection, "Fix the database connection"},
        {:update, "mix phoenix_kit.update", ["reason"]},
        {:update, "mix phoenix_kit.update", []},
        {:check_modules, ["Broken"]},
        {:ready, "Ready"}
      ]

      for action <- actions do
        described = StatusReport.describe(action)
        assert is_binary(described) and described != "", "empty render for #{inspect(action)}"
      end
    end
  end

  describe "command/1" do
    test "extracts the runnable command where there is one" do
      assert StatusReport.command({:update, "mix phoenix_kit.update", []}) ==
               "mix phoenix_kit.update"

      assert StatusReport.command({:install, "mix igniter.install phoenix_kit"}) ==
               "mix igniter.install phoenix_kit"
    end

    test "returns nil for actions that are not commands" do
      assert StatusReport.command({:ready, "Ready"}) == nil
      assert StatusReport.command({:check_modules, ["Broken"]}) == nil
      assert StatusReport.command({:fix_connection, "..."}) == nil
    end
  end

  defp entry(name, installed, target, status) do
    %{
      name: name,
      module: SomeModule,
      migration_module: SomeModule.Migrations,
      installed: installed,
      target: target,
      status: status,
      error: nil
    }
  end

  defp error_entry(name) do
    %{
      name: name,
      module: SomeModule,
      migration_module: SomeModule.Migrations,
      installed: 0,
      target: nil,
      status: :error,
      error: "relation does not exist"
    }
  end
end
