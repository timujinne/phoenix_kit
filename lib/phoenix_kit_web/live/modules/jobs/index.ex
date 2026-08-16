defmodule PhoenixKitWeb.Live.Modules.Jobs.Index do
  @moduledoc """
  LiveView for viewing jobs.

  Provides a simple read-only view of all Oban jobs with filtering by queue and state.
  """

  use PhoenixKitWeb, :live_view

  # Filter (queue, state, worker) and page live in the query string — a
  # filtered list is a real URL: shareable, reload-proof, and Back returns to
  # the previous query instead of leaving the page. `filter_queue`,
  # `filter_state`, and `filter_worker` default to "all", which is therefore
  # what gets omitted from the URL.
  use PhoenixKitWeb.Live.UrlState,
    params: [
      filter_queue: [default: "all", url_key: "queue"],
      filter_state: [default: "all", url_key: "state"],
      filter_worker: [default: "all", url_key: "worker"],
      current_page: [default: 1, cast: :integer, min: 1, url_key: "page"]
    ],
    page_param: :current_page

  import Ecto.Query

  alias PhoenixKit.Jobs, as: JobsModule
  alias PhoenixKit.ScheduledJobs.ScheduledJob
  alias PhoenixKit.Settings
  alias PhoenixKit.Utils.Json
  alias PhoenixKit.Utils.Pagination
  alias PhoenixKit.Utils.Routes

  @per_page 25
  @refresh_interval 30_000

  def mount(_params, _session, socket) do
    # Check if module is enabled
    if JobsModule.enabled?() do
      project_title = Settings.get_project_title()

      if connected?(socket) do
        Process.send_after(self(), :refresh, @refresh_interval)
      end

      # :filter_queue, :filter_state, :filter_worker, and :current_page are
      # assigned from the query string by UrlState before mount/3 runs —
      # re-assigning them here would overwrite a shared link's state with the
      # defaults.
      socket =
        socket
        |> assign(:page_title, "Jobs")
        |> assign(:project_title, project_title)
        |> assign(:url_path, Routes.path("/admin/jobs"))
        |> assign(:hidden_workers, load_hidden_workers())
        |> assign(:per_page, @per_page)
        |> assign(:selected_job, nil)
        |> assign(:selected_scheduled_job, nil)
        |> assign(:active_tab, "oban")
        |> load_stats()
        |> load_scheduled_jobs()

      {:ok, socket}
    else
      {:ok,
       socket
       |> put_flash(:error, "Jobs module is not enabled. Enable it from the Modules page.")
       |> redirect(to: Routes.path("/admin/modules"))}
    end
  end

  # The list is loaded here rather than in mount/3: UrlState calls this after
  # mount and on every change to the query string, so one code path serves the
  # first render, a shared link, and the Back button alike.
  #
  # Deliberately not annotated with @impl — a single @impl anywhere in a module
  # makes Elixir demand it on every other callback too, and this LiveView's
  # mount/handle_event/handle_info carry none.
  def handle_url_state(_state, socket), do: load_jobs(socket)

  def handle_event("filter_queue", %{"queue" => queue}, socket) do
    {:noreply, push_url_state(socket, filter_queue: queue)}
  end

  def handle_event("filter_state", %{"state" => state}, socket) do
    {:noreply, push_url_state(socket, filter_state: state)}
  end

  def handle_event("filter_worker", %{"worker" => worker}, socket) do
    {:noreply, push_url_state(socket, filter_worker: worker)}
  end

  def handle_event("toggle_hide_worker", %{"worker" => worker}, socket) do
    hidden = socket.assigns.hidden_workers

    new_hidden =
      if worker in hidden do
        List.delete(hidden, worker)
      else
        [worker | hidden]
      end

    save_hidden_workers(new_hidden)

    # hidden_workers is settings-backed (not a URL param), so we reload the
    # list directly rather than routing through push_url_state.
    socket =
      socket
      |> assign(:hidden_workers, new_hidden)
      |> load_jobs()

    {:noreply, socket}
  end

  def handle_event("clear_hidden_workers", _params, socket) do
    save_hidden_workers([])

    socket =
      socket
      |> assign(:hidden_workers, [])
      |> load_jobs()

    {:noreply, socket}
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {page, ""} when page > 0 -> {:noreply, push_url_state(socket, current_page: page)}
      _ -> {:noreply, socket}
    end
  end

  def handle_event("show_job", %{"id" => id}, socket) do
    job = load_job(String.to_integer(id))
    {:noreply, assign(socket, :selected_job, job)}
  end

  def handle_event("close_job", _params, socket) do
    {:noreply, assign(socket, :selected_job, nil)}
  end

  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, :active_tab, tab)}
  end

  def handle_event("show_scheduled_job", %{"id" => id}, socket) do
    job = load_scheduled_job(id)
    {:noreply, assign(socket, :selected_scheduled_job, job)}
  end

  def handle_event("close_scheduled_job", _params, socket) do
    {:noreply, assign(socket, :selected_scheduled_job, nil)}
  end

  def handle_info(:refresh, socket) do
    Process.send_after(self(), :refresh, @refresh_interval)

    socket =
      socket
      |> load_jobs()
      |> load_stats()
      |> load_scheduled_jobs()

    {:noreply, socket}
  end

  defp load_jobs(socket) do
    repo = PhoenixKit.Config.get_repo()
    filter_queue = socket.assigns.filter_queue
    filter_state = socket.assigns.filter_state
    filter_worker = socket.assigns.filter_worker
    hidden_workers = socket.assigns.hidden_workers
    page = socket.assigns.current_page
    per_page = socket.assigns.per_page

    base_query =
      from(j in "oban_jobs",
        select: %{
          id: j.id,
          queue: j.queue,
          worker: j.worker,
          state: j.state,
          attempt: j.attempt,
          max_attempts: j.max_attempts,
          inserted_at: j.inserted_at,
          scheduled_at: j.scheduled_at,
          attempted_at: j.attempted_at,
          completed_at: j.completed_at
        }
      )

    query =
      base_query
      |> maybe_filter_queue(filter_queue)
      |> maybe_filter_state(filter_state)
      |> maybe_filter_worker(filter_worker)
      |> maybe_exclude_hidden_workers(hidden_workers, filter_worker)

    total_count = repo.aggregate(query, :count, :id)
    total_pages = Pagination.total_pages(total_count, per_page)

    jobs =
      query
      |> order_by([j], desc: j.inserted_at)
      |> limit(^per_page)
      |> offset(^((page - 1) * per_page))
      |> repo.all()

    socket
    |> assign(:jobs, jobs)
    |> assign(:total_count, total_count)
    |> assign(:total_pages, total_pages)
  end

  defp load_job(id) do
    repo = PhoenixKit.Config.get_repo()

    from(j in "oban_jobs",
      where: j.id == ^id,
      select: %{
        id: j.id,
        queue: j.queue,
        worker: j.worker,
        state: j.state,
        args: j.args,
        meta: j.meta,
        tags: j.tags,
        errors: j.errors,
        attempt: j.attempt,
        max_attempts: j.max_attempts,
        priority: j.priority,
        inserted_at: j.inserted_at,
        scheduled_at: j.scheduled_at,
        attempted_at: j.attempted_at,
        completed_at: j.completed_at,
        discarded_at: j.discarded_at,
        cancelled_at: j.cancelled_at
      }
    )
    |> repo.one()
  end

  defp load_scheduled_jobs(socket) do
    repo = PhoenixKit.Config.get_repo()

    scheduled_jobs =
      from(j in ScheduledJob,
        order_by: [desc: j.inserted_at],
        limit: 50
      )
      |> repo.all()

    assign(socket, :scheduled_jobs, scheduled_jobs)
  end

  defp load_scheduled_job(id) do
    repo = PhoenixKit.Config.get_repo()
    repo.get(ScheduledJob, id)
  end

  defp load_stats(socket) do
    repo = PhoenixKit.Config.get_repo()

    stats_query =
      from(j in "oban_jobs",
        group_by: [j.state],
        select: {j.state, count(j.id)}
      )

    stats =
      stats_query
      |> repo.all()
      |> Enum.into(%{})

    queue_query =
      from(j in "oban_jobs",
        group_by: [j.queue],
        select: {j.queue, count(j.id)}
      )

    queues =
      queue_query
      |> repo.all()
      |> Enum.into(%{})

    worker_query =
      from(j in "oban_jobs",
        group_by: [j.worker],
        select: {j.worker, count(j.id)}
      )

    workers =
      worker_query
      |> repo.all()
      |> Enum.sort_by(fn {name, _} -> name end)

    socket
    |> assign(:stats, stats)
    |> assign(:queue_stats, queues)
    |> assign(:worker_stats, workers)
  end

  defp maybe_filter_queue(query, "all"), do: query
  defp maybe_filter_queue(query, queue), do: where(query, [j], j.queue == ^queue)

  defp maybe_filter_state(query, "all"), do: query
  defp maybe_filter_state(query, state), do: where(query, [j], j.state == ^state)

  defp maybe_filter_worker(query, "all"), do: query
  defp maybe_filter_worker(query, worker), do: where(query, [j], j.worker == ^worker)

  # Only exclude hidden workers when viewing "all" workers
  defp maybe_exclude_hidden_workers(query, [], _filter_worker), do: query

  defp maybe_exclude_hidden_workers(query, _hidden, filter_worker) when filter_worker != "all",
    do: query

  defp maybe_exclude_hidden_workers(query, hidden_workers, "all") do
    where(query, [j], j.worker not in ^hidden_workers)
  end

  defp load_hidden_workers do
    Settings.get_setting("jobs_hidden_workers", "")
    |> String.split(",", trim: true)
  end

  defp save_hidden_workers(workers) do
    Settings.update_setting("jobs_hidden_workers", Enum.join(workers, ","))
  end

  defp state_badge_class(state) do
    case state do
      "completed" -> "badge-success"
      "available" -> "badge-info"
      "scheduled" -> "badge-warning"
      "executing" -> "badge-primary"
      "retryable" -> "badge-warning"
      "discarded" -> "badge-error"
      "cancelled" -> "badge-ghost"
      _ -> "badge-ghost"
    end
  end

  defp scheduled_job_badge_class(status) do
    case status do
      "pending" -> "badge-warning"
      # Claimed by a sweep and currently executing — same colour as Oban's
      # "executing" above, because it is the same phase of life.
      "processing" -> "badge-primary"
      "executed" -> "badge-success"
      "failed" -> "badge-error"
      "cancelled" -> "badge-ghost"
      _ -> "badge-ghost"
    end
  end

  defp format_datetime(nil), do: "-"

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M:%S")
  end

  defp format_json(nil), do: "-"

  defp format_json(data) when is_map(data) or is_list(data) do
    Json.encode_pretty!(data)
  end

  defp format_json(data), do: inspect(data)

  defp short_worker_name(worker) when is_binary(worker) do
    worker
    |> String.split(".")
    |> List.last()
  end

  defp short_worker_name(_), do: "-"
end
