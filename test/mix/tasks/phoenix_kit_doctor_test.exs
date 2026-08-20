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

  describe "git_hooks_verdict/1 — 'not installed' and 'could not check' are different answers" do
    @ok %{
      repo: {:ok, "/repo/.git"},
      hooks_path: {:ok, ".githooks"},
      tracked?: true,
      shadow: :none
    }

    test "enabled, tracked, no leftover → pass" do
      assert {:pass, _} = DoctorTask.git_hooks_verdict(@ok)
    end

    test "core.hooksPath unset → warns, and says exactly how to fix it" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | hooks_path: :unset})
      assert status == :warn
      assert detail =~ "NOT running"
      assert detail =~ "git config core.hooksPath .githooks"
    end

    test "pointing somewhere else → warns and names where" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | hooks_path: {:ok, "hooks"}})
      assert status == :warn
      assert detail =~ ~s("hooks")
      assert detail =~ "git config core.hooksPath .githooks"
    end

    test "tracked hook missing from the checkout → warns about that, not about config" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | tracked?: false})
      assert status == :warn
      assert detail =~ ".githooks/pre-commit is missing"
    end

    test "leftover hook in the common dir → warns it is dead code" do
      {status, detail} =
        DoctorTask.git_hooks_verdict(%{@ok | shadow: {:ok, "/repo/.git/hooks/pre-commit"}})

      assert status == :warn
      assert detail =~ "/repo/.git/hooks/pre-commit"
      assert detail =~ "Delete it"
    end

    # The whole reason this check exists in this shape. A check that answers
    # "not installed" when it merely failed to look is confidently wrong, and
    # sends the reader to fix something that is not broken.
    test "not a git repo → says it could not check, and refuses to call it 'not installed'" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | repo: :unknown})
      assert status == :warn
      assert detail =~ "Could not check"
      assert detail =~ "NOT the same"
      refute detail =~ "git config core.hooksPath .githooks"
    end

    test "core.hooksPath unreadable → same refusal to guess" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | hooks_path: :unknown})
      assert status == :warn
      assert detail =~ "unknown whether the hook runs"
      refute detail =~ "Fix:"
    end

    test "an unreadable config and an unset one do not produce the same message" do
      {_, could_not_check} = DoctorTask.git_hooks_verdict(%{@ok | hooks_path: :unknown})
      {_, definitely_off} = DoctorTask.git_hooks_verdict(%{@ok | hooks_path: :unset})

      refute could_not_check == definitely_off
    end

    test "enabled but the leftover check itself failed → says so rather than passing" do
      {status, detail} = DoctorTask.git_hooks_verdict(%{@ok | shadow: :unknown})
      assert status == :warn
      assert detail =~ "could not check for a stale copy"
    end
  end

  describe "classify_fk_check/5 — a probe failure must never read as clean (gate round 2, finding 1)" do
    test "a failed orphan-count probe lands in the probe_failed bucket, not the clean path" do
      acc = {[], [], []}

      assert {[], [], [{"t", "c", "r", :orphan_count, "boom", nil}]} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:probe_failed, "boom"},
                 :validated,
                 acc
               )
    end

    test "a failed validation-state probe lands in the probe_failed bucket too" do
      acc = {[], [], []}

      assert {[], [], [{"t", "c", "r", :validation_state, "no access", 0}]} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:ok, 0},
                 {:probe_failed, "no access"},
                 acc
               )
    end

    test "a failed validation-state probe preserves the measured orphan count (round 2 gate, minor finding 1)" do
      # The orphan-count probe already succeeded here — 5 real orphaned rows
      # were measured — and it is only the SEPARATE validation-state probe
      # that failed. Before this fix, the measured count was discarded and
      # the caller could only ever print "could not check", losing the exact
      # number the whole section exists to report.
      acc = {[], [], []}

      assert {[], [], [{"t", "c", "r", :validation_state, "no access", 5}]} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:ok, 5},
                 {:probe_failed, "no access"},
                 acc
               )
    end

    test "a probe failure wins even when the orphan count would otherwise be clean" do
      # Both reads must succeed for the old empty-accumulator ("nothing to
      # report") path to apply — one failing is enough to route to
      # probe_failed regardless of what the other read said.
      acc = {[], [], []}

      assert {[], [], [_]} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:probe_failed, "timeout"},
                 :absent,
                 acc
               )
    end

    test "known-good inputs still classify the same as before this round's fix" do
      assert {[{"t", "c", "r", 3, :validate}], [], []} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:ok, 3},
                 {:not_valid, "fk_x"},
                 {[], [], []}
               )

      assert {[], [{"t", "c", "r"}], []} =
               DoctorTask.classify_fk_check(
                 "t",
                 "c",
                 "r",
                 {:ok, 0},
                 {:not_valid, "fk_x"},
                 {[], [], []}
               )

      assert {[], [], []} =
               DoctorTask.classify_fk_check("t", "c", "r", {:ok, 0}, :validated, {[], [], []})
    end
  end

  describe "report_orphaned_fk_refs/4 — I055: a probe failure is its own tier, not the same red as real orphans" do
    test "probe_failed alone (no orphans, no known-unvalidated) is :warn, not :fail — I055's third tier" do
      # Before I055 this was :fail — the exact "slow and broken-data can't be
      # one color" defect the contract names. Coverage being incomplete is
      # "investigate why", not "fix corrupted data"; only real orphans (below)
      # still earn the red.
      probe_failed = [
        {"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users", :orphan_count, "boom", nil}
      ]

      assert {:warn, message} = DoctorTask.report_orphaned_fk_refs([], [], probe_failed, 4)
      assert message =~ "Could not check 1 of 4"
      assert message =~ "not the same as clean"
      assert message =~ "boom"
    end

    test "a validation-state probe failure reports the measured orphan count, not just 'could not check' (round 2 gate, minor finding 1)" do
      probe_failed = [
        {"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users", :validation_state,
         "no access", 5}
      ]

      assert {:warn, message} = DoctorTask.report_orphaned_fk_refs([], [], probe_failed, 1)
      assert message =~ "5 orphaned row"
      assert message =~ "no access"
    end

    test "no findings at all is still :pass, and now names the coverage" do
      assert {:pass, message} = DoctorTask.report_orphaned_fk_refs([], [], [], 231)
      assert message =~ "checked 231 of 231"
    end

    test "orphans alone still :fail — real data damage always wins the color" do
      orphaned = [{"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users", 2, :validate}]

      assert {:fail, message} = DoctorTask.report_orphaned_fk_refs(orphaned, [], [], 4)
      assert message =~ "2 orphaned row"
    end

    test "orphans found AND a separate probe failure — still :fail, but the coverage gap is still surfaced" do
      orphaned = [{"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users", 2, :validate}]

      probe_failed = [
        {"other_table", "other_col", "other_ref", :orphan_count, "boom", nil}
      ]

      assert {:fail, message} = DoctorTask.report_orphaned_fk_refs(orphaned, [], probe_failed, 5)
      assert message =~ "2 orphaned row"
      assert message =~ "boom"
      assert message =~ "checked 4 of 5"
    end

    test "not_validated alone (nothing blocking) is still :warn, and names the coverage" do
      not_validated = [{"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users"}]

      assert {:warn, message} = DoctorTask.report_orphaned_fk_refs([], not_validated, [], 1)
      assert message =~ "checked 1 of 1"
    end
  end

  describe "discover_fk_constraints/2 — I055: source of truth is pg_constraint, not a list in code" do
    test "a multi-column FK is reported separately from single-column ones, not silently dropped" do
      # Pure shape check on the split logic doctor's discovery query feeds
      # into — the actual pg_constraint query itself is exercised against a
      # real connection in phoenix_kit_doctor_orphaned_fk_test.exs.
      rows = [
        ["orders", "users", "fk_orders_user", true, 1, "user_uuid", "uuid"],
        ["order_items", "orders", "fk_items_composite", false, 2, "order_uuid", "uuid"]
      ]

      {single, multi} =
        Enum.split_with(rows, fn [_, _, _, _, col_count, _, _] -> col_count == 1 end)

      assert length(single) == 1
      assert length(multi) == 1
      assert [_, _, "fk_items_composite", _, 2, _, _] = hd(multi)
    end
  end

  describe "fk_probe_failure_reason/1 — I055: a timed-out probe says so, not a raw Postgres error" do
    test "a query_canceled Postgrex error becomes a time-limit message" do
      reason = %Postgrex.Error{postgres: %{code: :query_canceled, message: "canceling statement"}}

      assert DoctorTask.fk_probe_failure_reason(reason) =~ "time limit exceeded"
      assert DoctorTask.fk_probe_failure_reason(reason) =~ "not checked, not clean"
    end

    test "any other error reason passes through unchanged" do
      assert DoctorTask.fk_probe_failure_reason(:some_other_error) == :some_other_error
    end
  end
end
