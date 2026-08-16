defmodule PhoenixKit.Integration.ScheduledJobs.ProcessScheduledJobsWorkerTest do
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.ScheduledJobs.ScheduledJob
  alias PhoenixKit.ScheduledJobs.Workers.ProcessScheduledJobsWorker

  defmodule Handler do
    @moduledoc false
    @behaviour PhoenixKit.ScheduledJobs.Handler

    @impl true
    def job_type, do: "test_job"

    @impl true
    def resource_type, do: "test_resource"

    @impl true
    def execute(_resource_uuid, _args), do: :ok
  end

  setup do
    level = Logger.level()
    on_exit(fn -> Logger.configure(level: level) end)
    :ok
  end

  # Inserted rather than scheduled: create_changeset/2 requires a future
  # scheduled_at, and a job the sweep will pick up has to already be due.
  defp due_job! do
    Repo.insert!(%ScheduledJob{
      job_type: "test_job",
      # to_string/1, not inspect/1: execute_job/1 resolves this with
      # String.to_existing_atom, so it needs the "Elixir."-prefixed form that
      # schedule_job/5 writes.
      handler_module: to_string(Handler),
      resource_type: "test_resource",
      resource_uuid: Ecto.UUID.generate(),
      scheduled_at:
        DateTime.utc_now() |> DateTime.add(-60, :second) |> DateTime.truncate(:second),
      status: "pending"
    })
  end

  describe "perform/1 with work waiting" do
    test "runs at :debug — the level that used to kill the sweep" do
      # Regression: perform/1 logged `job.id`, but ScheduledJob's key is
      # `:uuid`. Logger.debug defers evaluation, so at :info the mistake was
      # invisible; at :debug it raised KeyError before any work happened, and
      # max_attempts: 1 discarded the sweep rather than retrying it — so a host
      # on debug logging published nothing, silently, for as long as it ran.
      job = due_job!()
      Logger.configure(level: :debug)

      assert :ok = ProcessScheduledJobsWorker.perform(%Oban.Job{args: %{}})

      assert Repo.get(ScheduledJob, job.uuid).status == "executed"
    end

    test "runs at :info too" do
      job = due_job!()
      Logger.configure(level: :info)

      assert :ok = ProcessScheduledJobsWorker.perform(%Oban.Job{args: %{}})

      assert Repo.get(ScheduledJob, job.uuid).status == "executed"
    end

    test "runs at :debug with nothing pending" do
      Logger.configure(level: :debug)

      assert :ok = ProcessScheduledJobsWorker.perform(%Oban.Job{args: %{}})
    end
  end
end
