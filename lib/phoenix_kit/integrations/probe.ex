defmodule PhoenixKit.Integrations.Probe do
  @moduledoc """
  Runs a connection check in an isolated process under a hard deadline.

  Connection checks talk to the network, and the libraries behind them bound
  neither their runtime nor their crashes:

    * `:gen_smtp_client.open/1` runs in the **calling** process and, past the TCP
      connect, waits on a hard-coded `?TIMEOUT` of 1_200_000 ms — the `timeout`
      option bounds only `connect`. A tarpit relay parks the caller for twenty
      minutes.
    * ExAws retries transport errors with backoff, which adds up to minutes.

  Every call site is a LiveView callback, so the check must be watched in **both**
  directions, and getting only one of them right is worse than getting neither:

    * **The check must not kill the caller.** `Task.async/1` links, and a LiveView
      does not trap exits, so a raise or an abnormal exit inside the check killed
      the operator's page outright — before `Task.yield/2` could hand back
      `{:exit, reason}`, which is why that clause never ran.
    * **The caller must not lose the check.** With a bare `spawn_monitor/1` the
      deadline lives in the caller's `receive/after`, so when the LiveView goes
      away mid-check — the operator hit refresh — nothing is left to fire it. The
      check stays parked in gen_smtp for twenty minutes holding its socket, and,
      being unlinked, it is now unreachable rather than merely slow. That is the
      first hazard relocated, not removed.

  So: **link, monitor, and unlink before dying** — which is exactly what
  LiveView's own `start_async` does (phoenix_live_view/async.ex: `Task.start_link/1`,
  then a monitor on top, then the work wrapped in `try/after Process.unlink/1`).
  The link reaps the check when the
  caller dies; the monitor delivers the result and the crash reason; unlinking
  before dying keeps the check's own failure from travelling back up the link. At
  the deadline the caller unlinks *before* killing, because `:kill` is untrappable
  — the check cannot unlink itself, and the link would carry `:killed` straight
  back.

  The one signal a link necessarily carries is an untrappable `:kill` of the check
  process by a third party. Nothing holds its pid, so nothing can; `Task` and
  LiveView accept the same exposure.
  """

  use Gettext, backend: PhoenixKitWeb.Gettext

  require Logger

  @typedoc """
  What a check has to say beyond pass or fail, split by how long it stays true.

    * `:fact` — a standing property of this connection: the account it belongs
      to, the bot it is, a permission it lacks. It stays true until the
      credentials or the account change, so it is stored on the connection and
      shown with it.
    * `:reading` — a figure at the moment of the check: a balance, remaining
      credits, a send quota. It is out of date as soon as anything runs, so it
      is reported once, to whoever asked for the check, and never stored.
      Somewhere that wants a current figure asks for a check of its own
      (`PhoenixKit.Integrations.reading/2`).

  A bare string is read as a `:fact`, which is what validators returned before
  the two were told apart.
  """
  @type note :: %{optional(:fact) => String.t(), optional(:reading) => String.t()}

  @typedoc """
  Talks to the network; answers `:ok`, `{:ok, note}` when it succeeded but has
  something to say as well (see `t:note/0`), `{:error, message}` when it was
  actively rejected, or `{:inconclusive, message}` when the check could not
  reach a yes/no verdict at all (a response neither a pass nor a rejection) —
  distinct from `:error` so a caller can tell "definitely wrong" apart from
  "could not tell". A check that has no way to tell at all answers `:unverified`.
  """
  @type check ::
          (-> :ok
              | {:ok, String.t() | note()}
              | :unverified
              | {:error, String.t()}
              | {:inconclusive, String.t()})

  @default_deadline 15_000

  @doc """
  Runs `check` in an isolated process, bounded by `deadline` milliseconds.

  Returns what `check` returned. If it crashes, exits, or overruns the deadline,
  returns `{:error, message}` — either way the caller is left standing, and the
  check does not outlive it.
  """
  @spec run(check(), timeout()) ::
          :ok
          | {:ok, String.t() | note()}
          | :unverified
          | {:error, String.t()}
          | {:inconclusive, String.t()}
  def run(check, deadline \\ deadline()) when is_function(check, 0) do
    parent = self()
    ref = make_ref()

    # Gettext keeps the locale in the process dictionary, which a spawned process
    # does not inherit. Without this the operator reads half the failures in their
    # own language and half in English.
    locale = Gettext.get_locale(PhoenixKitWeb.Gettext)

    # The check waits for `:go` so it cannot finish — or die — before the monitor
    # is in place. `spawn_link/1` establishes the link atomically; `Process.link/1`
    # from inside the child would leave a window in which the caller could die
    # unwatched, which is the whole hazard.
    pid =
      spawn_link(fn ->
        receive do
          {:go, ^ref} ->
            try do
              Gettext.put_locale(PhoenixKitWeb.Gettext, locale)
              send(parent, {ref, check.()})
            after
              # Runs on success and on any exception or exit, so our own failure
              # never reaches the caller through the link. Only an untrappable
              # :kill skips it.
              Process.unlink(parent)
            end
        end
      end)

    monitor = Process.monitor(pid)
    send(pid, {:go, ref})

    receive do
      {^ref, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^pid, reason} ->
        Logger.warning("Connection check crashed: #{inspect(reason)}")
        {:error, gettext("Could not reach the service")}
    after
      deadline ->
        # Unlink first: :kill is untrappable, so the check cannot run its `after`
        # and unlink itself, and the link would deliver :killed to us.
        Process.unlink(pid)
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])
        flush(ref)
        {:error, gettext("The service did not respond in time")}
    end
  end

  # A result that lands in the instant the deadline fires must not be left behind
  # in the caller's mailbox: the caller is a LiveView, and it would log the stray
  # reply as an unexpected message.
  defp flush(ref) do
    receive do
      {^ref, _result} -> :ok
    after
      0 -> :ok
    end
  end

  defp deadline do
    Application.get_env(:phoenix_kit, :integration_check_deadline, @default_deadline)
  end
end
