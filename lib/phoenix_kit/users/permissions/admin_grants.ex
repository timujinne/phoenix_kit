defmodule PhoenixKit.Users.Permissions.AdminGrants do
  @moduledoc """
  Boot-time grant of permission keys to the Admin role, with retry and a way to
  wait for it.

  Started by `PhoenixKit.Supervisor`. On start it runs
  `PhoenixKit.Users.Permissions.auto_grant_new_keys_to_admin/0` and
  `backfill_media_sub_permissions/0`, then waits for `PhoenixKit.Dashboard.Registry`
  to finish loading its tabs (which register and grant their own keys).

  A key that hits a database error is not dropped until the next restart: it
  is kept as pending and tried again after a backoff (1 second, doubled on each
  attempt, 6 attempts by default: about 63 seconds in all). The retry is a server-side timer rather than
  a retry on the next access because nothing reads these grants lazily — a
  request that needs the key would simply be denied — and because a transient
  failure (pool exhaustion, a database restart) usually clears within seconds.
  Each grant is idempotent and sets its `auto_granted_perm:<key>` flag only on
  success, so a retry never overrides an Owner's later revocation. A failure
  reported later from outside the sweep (`Permissions.auto_grant_to_admin_roles/1`
  called by the tab registry or by `register_custom_key/2`) joins the same retry.

  Only a database error (an exception or an exit) is retried. A rejected
  changeset, or a missing sandbox owner (a test suite that already switched to
  `:manual`), would fail again, so it is logged once and counted as failed.
  Each key logs at error level on its first pass, at warning on a retry, and
  giving up logs one error with the keys still missing.

  A key given up on stays reported (by `await/2`) until the next restart: the
  server cannot see a grant made behind its back.

  The server is `:permanent`: every step that touches the database rescues, so
  it does not crash-loop and take `PhoenixKit.Supervisor` with it.

  `PhoenixKit.Users.Permissions.await_admin_grants/1` waits for the result; the
  retries take about 63 seconds, so a shorter timeout can return `:timeout`
  while they are still running.
  """

  use GenServer

  require Logger

  alias PhoenixKit.Dashboard.Registry
  alias PhoenixKit.Users.Permissions

  @default_base_ms 1_000
  @default_attempts 6

  @doc """
  Options: `:name`, `:retry_base_ms` (first backoff, default #{@default_base_ms}),
  `:max_attempts` (default #{@default_attempts}) and `:sync_registry` (default `true`),
  `:sweep_fun` and `:registry_fun` (test seams for the sweep and the registry wait).
  """
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc false
  def child_spec(opts) do
    %{id: Keyword.get(opts, :name, __MODULE__), start: {__MODULE__, :start_link, [opts]}}
  end

  @doc """
  Queues a key (or `:media_subs`) whose grant just failed for a retry. A no-op
  when the server is not running.
  """
  @spec report_failure(String.t() | :media_subs, GenServer.server()) :: :ok
  def report_failure(key, server \\ __MODULE__) do
    if running?(server), do: GenServer.cast(server, {:failed, key}), else: :ok
  end

  @doc "See `PhoenixKit.Users.Permissions.await_admin_grants/1`."
  @spec await(timeout(), GenServer.server()) ::
          :ok | {:error, :timeout | {:failed, list()} | {:exit, term()}}
  def await(timeout \\ 5_000, server \\ __MODULE__) do
    if running?(server) do
      try do
        GenServer.call(server, :await, timeout)
      catch
        :exit, {:timeout, _} -> {:error, :timeout}
        :exit, {:noproc, _} -> :ok
        :exit, reason -> {:error, {:exit, reason}}
      end
    else
      :ok
    end
  end

  defp running?(server) when is_atom(server), do: Process.whereis(server) != nil
  defp running?(server), do: is_pid(server) and Process.alive?(server)

  @impl true
  def init(opts) do
    state = %{
      pending: MapSet.new(),
      dropped: MapSet.new(),
      attempts: 0,
      timer: nil,
      initial_done?: false,
      status: :running,
      waiters: [],
      base_ms: Keyword.get(opts, :retry_base_ms, @default_base_ms),
      max_attempts: Keyword.get(opts, :max_attempts, @default_attempts),
      sync_registry?: Keyword.get(opts, :sync_registry, true),
      sweep_fun: Keyword.get(opts, :sweep_fun, &Permissions.sweep_admin_grants/1),
      registry_fun: Keyword.get(opts, :registry_fun, &Registry.await_initialized/1)
    }

    {:ok, state, {:continue, :sweep}}
  end

  @impl true
  def handle_continue(:sweep, state) do
    {retry, dropped} = sweep(:error, state)

    # Wait for the tab load too, which registers (and grants) its own keys.
    retry =
      if state.sync_registry? and state.registry_fun.(30_000) != :ok,
        do: [:registry | retry],
        else: retry

    # Failures the registry reported while loading are already in the mailbox
    # ahead of this message.
    send(self(), :initial_done)

    {:noreply,
     %{
       state
       | pending: MapSet.union(state.pending, MapSet.new(retry)),
         dropped: MapSet.union(state.dropped, MapSet.new(dropped))
     }}
  end

  @impl true
  def handle_info(:initial_done, state), do: {:noreply, evaluate(%{state | initial_done?: true})}

  def handle_info(:retry, state) do
    {pending, dropped} =
      Enum.reduce(state.pending, {MapSet.new(), state.dropped}, fn item, {keep, drop} ->
        {retry, dropped} = retry(item, state)
        {Enum.into(retry, keep), Enum.into(dropped, drop)}
      end)

    {:noreply, evaluate(%{state | timer: nil, pending: pending, dropped: dropped})}
  end

  def handle_info(_msg, state), do: {:noreply, state}

  @impl true
  def handle_cast({:failed, key}, state) do
    # A fresh failure restarts the backoff, also after the retries ran out.
    state =
      if state.status == :running or state.timer != nil,
        do: state,
        else: %{state | attempts: 0, status: :running}

    {:noreply, evaluate(%{state | pending: MapSet.put(state.pending, key)})}
  end

  @impl true
  def handle_call(:await, from, state) do
    cond do
      not state.initial_done? -> {:noreply, %{state | waiters: [from | state.waiters]}}
      MapSet.size(state.pending) == 0 and MapSet.size(state.dropped) == 0 -> {:reply, :ok, state}
      state.status == :failed -> {:reply, {:error, {:failed, failed_list(state)}}, state}
      true -> {:noreply, %{state | waiters: [from | state.waiters]}}
    end
  end

  # One sweep pass, split into the keys worth retrying and the ones that are
  # not. Never raises: a crash here would restart the server in a loop.
  defp sweep(level, state) do
    failures = state.sweep_fun.(report: false, level: level)

    media =
      case Permissions.backfill_media_subs(report: false, level: level) do
        :ok -> []
        {:error, reason} -> [{:media_subs, reason}]
      end

    split(failures ++ media)
  rescue
    error ->
      Logger.error("[Permissions] Admin grant sweep crashed: #{Exception.message(error)}")
      {[:sweep], []}
  catch
    :exit, reason ->
      Logger.error("[Permissions] Admin grant sweep crashed: #{inspect(reason)}")
      {[:sweep], []}
  end

  defp split(failures) do
    {retry, dropped} =
      Enum.split_with(failures, fn {_key, reason} ->
        Permissions.retriable_grant_error?(reason)
      end)

    {Enum.map(retry, &elem(&1, 0)), Enum.map(dropped, &elem(&1, 0))}
  end

  # Each retry answers `{keys_to_retry, keys_given_up}`.
  defp retry(:sweep, state), do: sweep(:warning, state)

  defp retry(:registry, state) do
    if state.registry_fun.(5_000) == :ok, do: {[], []}, else: {[:registry], []}
  end

  defp retry(:media_subs, _state) do
    classify(:media_subs, Permissions.backfill_media_subs(report: false, level: :warning))
  end

  defp retry(key, _state) do
    classify(key, Permissions.grant_to_admin_once(key, report: false, level: :warning))
  end

  defp classify(_key, :ok), do: {[], []}

  defp classify(key, {:error, reason}) do
    if Permissions.retriable_grant_error?(reason), do: {[key], []}, else: {[], [key]}
  end

  # Decides what to do after any change: done, schedule the next attempt, or
  # give up (once, loudly) when the attempts ran out.
  defp evaluate(%{initial_done?: false} = state), do: state

  defp evaluate(state) do
    cond do
      MapSet.size(state.pending) == 0 and MapSet.size(state.dropped) == 0 ->
        reply_all(%{state | timer: nil, status: :ready, attempts: 0}, :ok)

      MapSet.size(state.pending) == 0 ->
        reply_all(%{state | status: :failed}, {:error, {:failed, failed_list(state)}})

      state.timer != nil ->
        state

      state.attempts >= state.max_attempts ->
        if state.status != :failed do
          Logger.error(
            "[Permissions] Giving up auto-granting to the Admin role after " <>
              "#{state.max_attempts} retries; still missing: #{inspect(failed_list(state))}. " <>
              "They are tried again at the next boot."
          )
        end

        reply_all(%{state | status: :failed}, {:error, {:failed, failed_list(state)}})

      true ->
        delay = state.base_ms * Integer.pow(2, state.attempts)
        timer = Process.send_after(self(), :retry, delay)
        %{state | timer: timer, attempts: state.attempts + 1, status: :running}
    end
  end

  defp reply_all(state, reply) do
    Enum.each(state.waiters, &GenServer.reply(&1, reply))
    %{state | waiters: []}
  end

  defp failed_list(state),
    do: Enum.sort_by(MapSet.union(state.pending, state.dropped), &to_string/1)
end
