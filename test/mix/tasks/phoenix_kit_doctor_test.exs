defmodule Mix.Tasks.PhoenixKit.DoctorTest do
  use ExUnit.Case, async: true

  alias Mix.Tasks.PhoenixKit.Doctor, as: DoctorTask

  # `run/1` isn't a unit-test seam (starts the app, needs a real DB) — same
  # reasoning as `Mix.Tasks.PhoenixKit.StatusTest` and
  # `Mix.Tasks.PhoenixKit.RepairTest`: exercise the pure decision the task
  # makes. Here that decision is what `--exit-code` reports to a deploy script.

  describe "exit_code/1 — only a FAIL gates the run" do
    test "all passing → 0" do
      assert DoctorTask.exit_code([
               {"Repo Detection", {:pass, "PhoenixKit.Repo"}},
               {"DB Connectivity", {:pass, "PostgreSQL 16.2"}}
             ]) == 0
    end

    test "no checks at all → 0" do
      assert DoctorTask.exit_code([]) == 0
    end

    test "any failure → 1" do
      assert DoctorTask.exit_code([
               {"Repo Detection", {:pass, "PhoenixKit.Repo"}},
               {"Module Schema Versions", {:fail, "Behind: Boards V01 (code expects V02)"}},
               {"Update Mode", {:pass, "update_mode=false"}}
             ]) == 1
    end

    test "warnings alone never fail the run" do
      # Deliberate, and the reason the flag is usable at all: several warnings
      # fire on healthy installs — a pool capped by update_mode, an
      # application.ex the child-order check could not locate. Gating on them
      # would make --exit-code permanently red, which is how a task ends up
      # back at "reports a problem and exits 0".
      assert DoctorTask.exit_code([
               {"Pool Configuration", {:warn, "pool_size=2 is very low."}},
               {"Child Start Order", {:warn, "Couldn't locate your application.ex"}},
               {"Update Mode", {:warn, "update_mode=true"}}
             ]) == 0
    end

    test "a failure mixed among warnings still fails" do
      assert DoctorTask.exit_code([
               {"Pool Configuration", {:warn, "pool_size=2 is very low."}},
               {"Schema Drift", {:fail, "3 columns missing"}},
               {"Update Mode", {:warn, "update_mode=true"}}
             ]) == 1
    end

    test "an exception inside a check is a FAIL and gates too" do
      # `run_check/2` rescues into {:fail, "Exception: ..."}, so a crashed check
      # must not be able to pass a deploy.
      assert DoctorTask.exit_code([
               {"Orphaned FK References", {:fail, "Exception: connection not available"}}
             ]) == 1
    end
  end
end
