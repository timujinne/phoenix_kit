defmodule PhoenixKit.Migrations.Modules do
  @moduledoc """
  Discovers the schema version of every installed PhoenixKit module that owns
  its migrations.

  Modules that ship their own tables implement `c:PhoenixKit.Module.migration_module/0`,
  returning a coordinator with `current_version/0` (what the code needs) and
  `migrated_version_runtime/1` (what the database has). Examples in the wild:
  `phoenix_kit_inbox`, `phoenix_kit_boards`, `phoenix_kit_web_analytics`,
  `phoenix_kit_legal`, `phoenix_kit_stats`.

  This module is the shared read side of that contract. `mix phoenix_kit.status`
  uses it to *report* per-module versions and `mix phoenix_kit.update` uses it
  to decide what to *migrate* — before this existed each task had its own copy
  of the discovery logic, and only `update` had it at all, which is why
  `status` never mentioned modules.

  Everything here is read-only and defensive: a module whose coordinator raises,
  exits, or reports a non-integer version is recorded as `:error` with the
  message, never crashing the caller. A broken third-party module must not take
  down `mix phoenix_kit.status`.

  ## Example

      iex> PhoenixKit.Migrations.Modules.list()
      [
        %{
          name: "Inbox",
          module: PhoenixKitInbox,
          migration_module: PhoenixKitInbox.Migrations,
          installed: 1,
          target: 1,
          status: :up_to_date,
          error: nil
        }
      ]
  """

  @typedoc """
  Where one module's schema stands.

    * `:not_installed` — the code is present but its tables have never been
      created (installed version 0). The next `mix phoenix_kit.update` creates
      them.
    * `:needs_update` — tables exist at an older version than the code expects.
    * `:up_to_date` — database matches exactly what the code needs.
    * `:ahead_of_code` — database is NEWER than what the code expects: the
      schema was migrated by a later release than the one now running (a
      rollback/downgrade, or a dependency pinned backwards). Deliberately not
      folded into `:up_to_date` — that would hide the downgrade from callers
      that branch on this value, exactly the failure this type exists to
      surface.
    * `:error` — the module's coordinator raised, exited, or reported a
      non-integer version; the `:error` field has the message.
  """
  @type status :: :not_installed | :needs_update | :up_to_date | :ahead_of_code | :error

  @type entry :: %{
          name: String.t(),
          module: module(),
          migration_module: module(),
          installed: non_neg_integer(),
          target: non_neg_integer() | nil,
          status: status(),
          error: String.t() | nil
        }

  @doc """
  Every discovered module that owns migrations, sorted by display name.

  Returns `[]` when module discovery itself fails (no beam files, app not
  loaded) rather than raising — callers are CLI tasks that should degrade to
  "no modules" instead of blowing up.

  ## Options

    * `:prefix` — Postgres schema the install lives in. Defaults to `"public"`.
  """
  @spec list(keyword()) :: [entry()]
  def list(opts \\ []) do
    prefix = Keyword.get(opts, :prefix, "public")

    discover()
    |> Enum.map(&describe(&1, prefix))
    |> Enum.sort_by(& &1.name)
  end

  @doc """
  Classifies one module's installed version against the version its code wants.

  Public because it is the whole read-side decision — `mix phoenix_kit.status`
  renders it and `mix phoenix_kit.update` migrates off it — and a private
  version could only be tested through a hand-built entry that supplied the
  answer, which is no test at all.

  Both versions must be integers. A coordinator that reports anything else
  (`nil` for "no version comment found" is the tempting one) is `:error`, never
  silently `:up_to_date`: under Erlang term ordering `nil >= 2` is `true`, so an
  unguarded comparison would mark a module with no tables as current and skip
  its migration forever.

  `installed > target` is `:ahead_of_code`, never `:up_to_date` — collapsing
  the two would silently hide a database that is newer than the code now
  running (a downgrade) behind the same status a healthy install reports.

      iex> alias PhoenixKit.Migrations.Modules
      iex> {Modules.classify(2, 2), Modules.classify(3, 2)}
      {:up_to_date, :ahead_of_code}
      iex> {Modules.classify(0, 1), Modules.classify(1, 5)}
      {:not_installed, :needs_update}
      iex> Modules.classify(nil, 2)
      :error
  """
  @spec classify(term(), term()) :: status()
  def classify(installed, target)
      when is_integer(installed) and is_integer(target) and installed == target,
      do: :up_to_date

  def classify(installed, target)
      when is_integer(installed) and is_integer(target) and installed > target,
      do: :ahead_of_code

  def classify(0, target) when is_integer(target), do: :not_installed

  def classify(installed, target) when is_integer(installed) and is_integer(target),
    do: :needs_update

  def classify(_installed, _target), do: :error

  @doc """
  Filters a `list/1` result down to the entries a `mix phoenix_kit.update` run
  would act on — those needing their tables created or upgraded.

  A pure filter, deliberately: an earlier version also accepted options and did
  its own `list/1`, which made `pending([])` ambiguous — an empty *entry list*
  and empty *options* are the same term, so "nothing to filter" silently became
  "go query the database". Callers that want both compose them:

      Modules.list(prefix: prefix) |> Modules.pending()
  """
  @spec pending([entry()]) :: [entry()]
  def pending(entries) when is_list(entries) do
    Enum.filter(entries, &(&1.status in [:not_installed, :needs_update]))
  end

  @doc """
  Filters a `list/1` result down to entries whose coordinator raised. Surfaced
  separately so tasks can warn about a broken module instead of quietly
  omitting it from the report.

  Pure filter, same reasoning as `pending/1`.
  """
  @spec failed([entry()]) :: [entry()]
  def failed(entries) when is_list(entries) do
    Enum.filter(entries, &(&1.status == :error))
  end

  # ── internals ───────────────────────────────────────────────────────────────

  # Beam-file scanning, so this works under `--no-start` like the tasks need.
  #
  # `catch :exit` alongside `rescue` throughout this module is not belt-and-
  # braces: per CLAUDE.md an unreachable database *raises* on an unowned
  # checkout but *exits* on a dead pool, and these coordinators run queries.
  # A rescue-only guard turns a dead pool into a crashed `mix phoenix_kit.status`
  # — precisely the failure this module exists to prevent.
  defp discover do
    PhoenixKit.ModuleDiscovery.discover_external_modules()
    |> Enum.flat_map(fn mod ->
      if Code.ensure_loaded?(mod) and function_exported?(mod, :migration_module, 0) do
        case mod.migration_module() do
          nil -> []
          migration_mod -> [{mod, migration_mod}]
        end
      else
        []
      end
    end)
  rescue
    _ -> []
  catch
    :exit, _ -> []
  end

  defp describe({mod, migration_mod}, prefix) do
    installed = migration_mod.migrated_version_runtime(prefix: prefix)
    target = migration_mod.current_version()

    case classify(installed, target) do
      :error ->
        %{
          base(mod, migration_mod)
          | error:
              "coordinator reported a non-integer version " <>
                "(installed: #{inspect(installed)}, target: #{inspect(target)})"
        }

      status ->
        %{
          base(mod, migration_mod)
          | installed: installed,
            target: target,
            status: status
        }
    end
  rescue
    # A third-party coordinator that raises is reported, not propagated —
    # `mix phoenix_kit.status` must still describe everything else.
    error -> %{base(mod, migration_mod) | error: Exception.message(error)}
  catch
    :exit, reason -> %{base(mod, migration_mod) | error: "exited: #{inspect(reason)}"}
  end

  # Built by a function rather than bound in the body because a `rescue`
  # clause cannot see variables bound in the `do` block it guards.
  defp base(mod, migration_mod) do
    %{
      name: display_name(mod),
      module: mod,
      migration_module: migration_mod,
      installed: 0,
      target: nil,
      status: :error,
      error: nil
    }
  end

  defp display_name(mod) do
    case function_exported?(mod, :module_name, 0) && mod.module_name() do
      name when is_binary(name) -> name
      _ -> inspect(mod)
    end
  rescue
    _ -> inspect(mod)
  catch
    :exit, _ -> inspect(mod)
  end
end
