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

  defmodule ScheduledWorker do
    use Oban.Worker, queue: :scheduled_jobs

    @impl Oban.Worker
    def perform(_job), do: :ok
  end

  defmodule DefaultQueueWorker do
    # No `queue:` — Oban.Job's own "default" applies.
    use Oban.Worker

    @impl Oban.Worker
    def perform(_job), do: :ok
  end

  describe "check_cron_queues/1 — a crontab entry with no queue to run it" do
    test "warns when a crontab worker's queue is not configured" do
      # PhoenixKit's own 2025-12-28 → 1.7.63 bug, reproduced: the entry fires
      # every minute, the queue it declares is absent, so each tick inserts a
      # job that stays :available forever.
      config = [
        queues: [default: 10],
        plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
      ]

      assert {:warn, message} = DoctorTask.check_cron_queues(config)
      assert message =~ "ScheduledWorker"
      assert message =~ "scheduled_jobs"
    end

    test "passes once the queue is configured" do
      config = [
        queues: [default: 10, scheduled_jobs: 1],
        plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
      ]

      assert {:pass, _} = DoctorTask.check_cron_queues(config)
    end

    test "a worker declaring no queue is checked against 'default', not skipped" do
      assert {:warn, message} =
               DoctorTask.check_cron_queues(
                 queues: [emails: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"0 3 * * *", DefaultQueueWorker}]}]
               )

      assert message =~ "default"

      assert {:pass, _} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"0 3 * * *", DefaultQueueWorker}]}]
               )
    end

    test "an entry's own queue opt overrides the worker's, as Oban resolves it" do
      # Cron merges the entry's opts over `worker.__opts__()`, so a worker
      # declaring an unconfigured queue is fine when the entry redirects it —
      # and reporting it would be a false positive.
      assert {:pass, _} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [
                   {Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker, queue: :default}]}
                 ]
               )
    end

    test "queues: false is a node that runs no jobs, not a misconfiguration" do
      # Web-only and test nodes turn queues off wholesale; every entry would
      # look orphaned. Warning there is a false positive by construction.
      assert {:pass, message} =
               DoctorTask.check_cron_queues(
                 queues: false,
                 plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
               )

      assert message =~ "runs no queues"
    end

    test "plugins: false means there is no cron to check" do
      assert {:pass, message} =
               DoctorTask.check_cron_queues(queues: [default: 10], plugins: false)

      assert message =~ "plugins: false"
    end

    test "a module that is not an Oban worker is skipped rather than reported" do
      # A crontab can name something doctor's VM cannot load. Guessing would
      # report a healthy host as broken over a module we merely failed to
      # resolve.
      assert {:pass, _} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", NoSuchWorker.Nowhere}]}]
               )
    end

    test "no Cron plugin, no crontab, and no Oban config at all are all clean" do
      assert {:pass, _} = DoctorTask.check_cron_queues(queues: [default: 10], plugins: [])
      assert {:pass, _} = DoctorTask.check_cron_queues(nil)

      assert {:pass, _} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: []}]
               )
    end

    test "a top-level crontab: key is checked, not just the Cron plugin" do
      # Oban still accepts `crontab:` directly on the Oban config and promotes
      # it into a Cron plugin itself (Oban.Config.crontab_to_plugin/1). Reading
      # only `plugins:` reported a clean bill of health on exactly the config
      # this check exists to catch.
      assert {:warn, message} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 crontab: [{"* * * * *", ScheduledWorker}]
               )

      assert message =~ "ScheduledWorker"
    end

    test "entries from a second Cron plugin are not lost" do
      assert {:warn, message} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [
                   {Oban.Plugins.Cron, crontab: []},
                   {Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}
                 ]
               )

      assert message =~ "ScheduledWorker"
    end

    test "an empty queues list reads the same as queues: false" do
      # Oban's own docs: "Using an empty list or `false` prevents any queues
      # from starting on init." Treating them differently warned on one
      # spelling of a deliberate web-only node and passed the other.
      assert {:pass, message} =
               DoctorTask.check_cron_queues(
                 queues: [],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
               )

      assert message =~ "runs no queues"
    end

    test "testing mode is not a misconfiguration" do
      # `testing: :inline | :manual` makes Oban overwrite queues and plugins
      # with [] itself, so no cron fires and nothing can accumulate.
      for mode <- [:inline, :manual] do
        assert {:pass, message} =
                 DoctorTask.check_cron_queues(
                   testing: mode,
                   queues: [default: 10],
                   plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
                 )

        assert message =~ "testing mode"
      end

      # :disabled is the real default and must still be checked.
      assert {:warn, _} =
               DoctorTask.check_cron_queues(
                 testing: :disabled,
                 queues: [default: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
               )
    end

    test "the warning says what configuring the queue will release" do
      # Draining is not free: the first sweep publishes every overdue
      # scheduled post and sends every overdue broadcast. A host that reads
      # only "add the queue" gets that as a surprise.
      assert {:warn, message} =
               DoctorTask.check_cron_queues(
                 queues: [default: 10],
                 plugins: [{Oban.Plugins.Cron, crontab: [{"* * * * *", ScheduledWorker}]}]
               )

      assert message =~ "backlog"
      assert message =~ "cancel_all_jobs"
    end

    test "every offending worker is named, not just the first" do
      assert {:warn, message} =
               DoctorTask.check_cron_queues(
                 queues: [emails: 10],
                 plugins: [
                   {Oban.Plugins.Cron,
                    crontab: [
                      {"* * * * *", ScheduledWorker},
                      {"0 3 * * *", DefaultQueueWorker}
                    ]}
                 ]
               )

      assert message =~ "ScheduledWorker"
      assert message =~ "DefaultQueueWorker"
    end
  end
end
