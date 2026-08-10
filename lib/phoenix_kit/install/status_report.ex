defmodule PhoenixKit.Install.StatusReport do
  @moduledoc """
  Decides what `mix phoenix_kit.status` should tell the operator to do next.

  Extracted from the status task for the same reason `PhoenixKit.Install.StatusTree`
  was: it is pure decision logic that could otherwise only be observed by
  pointing the task at a live database in each of five states, so in practice
  it went unverified.

  The task keeps the ANSI styling; this module returns plain data.

  ## Why the wording matters

  `status` compares the schema in the database against the version compiled
  into the **running release** (`PhoenixKit.Migrations.Postgres.current_version/0`).
  It never asks Hex what exists. So it can never report "a newer PhoenixKit is
  available" — it can only report that the database disagrees with the code
  already querying it, which surfaces as runtime errors on whatever the newer
  version added.

  That is why nothing here says "update available": there is no optional
  upgrade being offered, only a mismatch to reconcile.
  """

  alias PhoenixKit.Migrations.Modules, as: MigrationModules

  @typedoc """
  What the operator should do.

    * `{:install, command}` — PhoenixKit has never been installed
    * `{:fix_connection, message}` — the database could not be reached
    * `{:fix_version_comment, message}` — installed, but the version comment is
      missing or unreadable; the fix is a restamp by hand, not an update
    * `{:update, command, reasons}` — schema behind the code; `reasons` says how
    * `{:check_modules, names}` — a module's version could not be read
    * `{:ready, message}` — database and code agree
  """
  @type action ::
          {:install, String.t()}
          | {:fix_connection, String.t()}
          | {:fix_version_comment, String.t()}
          | {:update, String.t(), [String.t()]}
          | {:check_modules, [String.t()]}
          | {:ready, String.t()}

  @doc """
  Picks the action for a given installation status and module list.

  `modules` is a `PhoenixKit.Migrations.Modules.list/1` result, or
  `:not_queried` when the database was unreachable and nothing was asked.

  ## Examples

      iex> alias PhoenixKit.Install.StatusReport
      iex> StatusReport.next_action({:up_to_date, 159}, [], "public")
      {:ready, "Ready"}

      iex> alias PhoenixKit.Install.StatusReport
      iex> StatusReport.next_action({:needs_update, 159, 160}, [], "public")
      {:update, "mix phoenix_kit.update", ["database is V159, code expects V160"]}
  """
  @spec next_action(tuple(), [map()] | :not_queried, String.t()) :: action()
  def next_action(installation_status, modules, prefix)

  def next_action({:not_installed}, _modules, _prefix) do
    {:install, "mix igniter.install phoenix_kit"}
  end

  def next_action({:unreachable, _reason}, _modules, _prefix) do
    {:fix_connection, "Fix the database connection, then re-run mix phoenix_kit.status"}
  end

  # Installed, but the version comment is missing or not a plain integer. The
  # action is a restamp, not an update: every other task reads that comment, so
  # until it says something true none of them can act safely. `doctor` first,
  # because it is what establishes the real version to stamp.
  def next_action({:unknown_version}, _modules, prefix) do
    {:fix_version_comment,
     "mix phoenix_kit.doctor — then COMMENT ON TABLE #{prefix}.phoenix_kit IS '<version>'"}
  end

  # Core behind. Modules fold into the SAME action rather than being ignored:
  # one `mix phoenix_kit.update` fixes both, and an operator told only
  # "database is behind" would fix core, re-run, and meet a second finding that
  # was already knowable here.
  def next_action({:needs_update, current, target}, modules, prefix) do
    {:update, update_command(prefix), [core_reason(current, target) | module_reasons(modules)]}
  end

  def next_action({:up_to_date, _version}, :not_queried, _prefix) do
    {:ready, "Ready"}
  end

  def next_action({:up_to_date, _version}, modules, prefix) do
    failed = MigrationModules.failed(modules)
    pending = MigrationModules.pending(modules)

    cond do
      # An unreadable module is NOT pending — migrating a module whose version
      # we cannot read would be worse than leaving it. But it must not report
      # "Ready" either: its tables may well be behind, and "1 unreadable ❌"
      # one line above "Next: Ready" tells the operator there is nothing to do.
      failed != [] -> {:check_modules, Enum.map(failed, & &1.name)}
      pending != [] -> {:update, update_command(prefix), module_reasons(pending)}
      true -> {:ready, "Ready"}
    end
  end

  @doc """
  The command an action asks for, or `nil` when it isn't a command.

      iex> PhoenixKit.Install.StatusReport.command({:update, "mix phoenix_kit.update", []})
      "mix phoenix_kit.update"
  """
  @spec command(action()) :: String.t() | nil
  def command({:install, command}), do: command
  def command({:update, command, _reasons}), do: command
  def command(_action), do: nil

  @doc """
  Plain-text rendering, no ANSI — what the task colours and prints.

      iex> PhoenixKit.Install.StatusReport.describe({:ready, "Ready"})
      "Ready"

      iex> PhoenixKit.Install.StatusReport.describe(
      ...>   {:update, "mix phoenix_kit.update", ["database is V159, code expects V160"]}
      ...> )
      "mix phoenix_kit.update — database is V159, code expects V160"
  """
  @spec describe(action()) :: String.t()
  def describe({:install, command}), do: command
  def describe({:fix_connection, message}), do: message
  def describe({:ready, message}), do: message
  def describe({:update, command, []}), do: command
  def describe({:update, command, reasons}), do: command <> " — " <> Enum.join(reasons, "; ")

  def describe({:check_modules, names}) do
    "Check the unreadable module(s): " <>
      Enum.join(names, ", ") <> " (schema version unknown — run with --verbose)"
  end

  @doc "The `mix phoenix_kit.update` invocation for a prefix."
  @spec update_command(String.t()) :: String.t()
  def update_command("public"), do: "mix phoenix_kit.update"
  def update_command(prefix), do: "mix phoenix_kit.update --prefix=#{prefix}"

  defp core_reason(current, target) do
    "database is V#{pad(current)}, code expects V#{pad(target)}"
  end

  # Accepts a raw module list, an already-filtered pending list, or
  # `:not_queried` (database unreachable, so nothing was asked).
  defp module_reasons(:not_queried), do: []

  defp module_reasons(modules) when is_list(modules) do
    case MigrationModules.pending(modules) do
      [] -> []
      pending -> ["module schema behind: " <> Enum.map_join(pending, ", ", & &1.name)]
    end
  end

  defp pad(version) when is_integer(version) and version < 10, do: "0#{version}"
  defp pad(version), do: to_string(version)
end
