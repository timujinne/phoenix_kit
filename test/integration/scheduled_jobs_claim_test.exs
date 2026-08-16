defmodule PhoenixKit.Integration.ScheduledJobsClaimTest do
  @moduledoc """
  The sweep claims a job before executing it.

  `process_pending_jobs/0` used to be select-then-execute: two overlapping
  sweeps — core's cron worker and a host calling this public function, or two
  nodes — both saw the same rows and both fired the handler, which is
  host-provided and not required to be idempotent. A row is now claimed
  pending → processing with a CAS, only the winner executes, and terminal
  marks are guarded on "processing" so a late mark cannot stomp a reclaimed
  row.
  """
  use PhoenixKit.DataCase, async: true

  alias PhoenixKit.ScheduledJobs
  alias PhoenixKit.ScheduledJobs.ScheduledJob

  defmodule Handler do
    @moduledoc false
    @behaviour PhoenixKit.ScheduledJobs.Handler

    @impl true
    def job_type, do: "claim_test"

    @impl true
    def resource_type, do: "claim_resource"

    @impl true
    def execute(resource_uuid, args) do
      # execute_job runs in the sweep's own process, so the test process
      # receives its own messages — a counting mailbox, no ETS needed.
      send(self(), {:executed, resource_uuid})

      case args do
        %{"outcome" => "error"} -> {:error, :boom}
        _ -> :ok
      end
    end
  end

  defp job!(attrs) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    defaults = %{
      job_type: "claim_test",
      handler_module: to_string(Handler),
      resource_type: "claim_resource",
      resource_uuid: Ecto.UUID.generate(),
      scheduled_at: DateTime.add(now, -60, :second),
      status: "pending"
    }

    Repo.insert!(struct!(ScheduledJob, Map.merge(defaults, Map.new(attrs))))
  end

  defp reload(job), do: Repo.get(ScheduledJob, job.uuid)

  test "a due job executes once, and a second sweep finds nothing" do
    job = job!(%{})

    assert {:ok, %{executed: 1, failed: 0}} = ScheduledJobs.process_pending_jobs()
    assert_receive {:executed, _}

    assert {:ok, %{executed: 0, failed: 0}} = ScheduledJobs.process_pending_jobs()
    refute_receive {:executed, _}

    assert reload(job).status == "executed"
  end

  test "a job already claimed by another sweep is not executed" do
    job = job!(%{status: "processing"})

    assert {:ok, %{executed: 0, failed: 0}} = ScheduledJobs.process_pending_jobs()
    refute_receive {:executed, _}

    # And it was not reclaimed either — its claim is fresh.
    assert reload(job).status == "processing"
  end

  test "a stale claim is reclaimed and the job runs again" do
    stale = DateTime.utc_now() |> DateTime.add(-7200, :second) |> DateTime.truncate(:second)
    job = job!(%{status: "processing", updated_at: stale, attempts: 0, max_attempts: 3})

    assert {:ok, %{executed: 1, failed: 0}} = ScheduledJobs.process_pending_jobs()
    assert_receive {:executed, _}

    reloaded = reload(job)
    assert reloaded.status == "executed"
    # The reclaim charged one attempt — a crashing handler cannot retry free.
    assert reloaded.attempts == 1
  end

  test "a stale claim with spent attempts goes to failed, not back to pending" do
    stale = DateTime.utc_now() |> DateTime.add(-7200, :second) |> DateTime.truncate(:second)
    job = job!(%{status: "processing", updated_at: stale, attempts: 2, max_attempts: 3})

    assert {:ok, %{executed: 0, failed: 0}} = ScheduledJobs.process_pending_jobs()
    refute_receive {:executed, _}

    reloaded = reload(job)
    assert reloaded.status == "failed"
    assert reloaded.last_error == "stale processing reclaim"
  end

  test "a failing handler returns the job to pending while attempts remain" do
    job = job!(%{args: %{"outcome" => "error"}, attempts: 0, max_attempts: 3})

    assert {:ok, %{executed: 0, failed: 1}} = ScheduledJobs.process_pending_jobs()
    assert_receive {:executed, _}

    reloaded = reload(job)
    assert reloaded.status == "pending"
    assert reloaded.attempts == 1
  end

  test "a failing handler with spent attempts fails permanently" do
    job = job!(%{args: %{"outcome" => "error"}, attempts: 2, max_attempts: 3})

    assert {:ok, %{executed: 0, failed: 1}} = ScheduledJobs.process_pending_jobs()

    assert reload(job).status == "failed"
  end

  test "cancel_job on an in-flight job refuses instead of crashing" do
    job = job!(%{status: "processing"})

    # The old clauses matched only the four settled statuses — a "processing"
    # row raised FunctionClauseError.
    assert {:error, :in_progress} = ScheduledJobs.cancel_job(job)
  end
end
