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
    entries
    |> Enum.filter(&(&1.status in [:not_installed, :needs_update]))
    |> order_by_dependencies()
  end

  @doc """
  Orders entries so a module comes after every module it depends on.

  Module chains reference each other's tables — `phoenix_kit_projects` carries
  foreign keys into `phoenix_kit_staff`'s and `phoenix_kit_entities`'s,
  `phoenix_kit_ecommerce` into `phoenix_kit_billing`'s — and `mix phoenix_kit.update`
  runs the chains in the order of this list. While core still created every
  module's tables that never mattered; once core stops, a chain whose referenced
  table does not exist yet fails.

  The dependency is the OTP application graph: a module depends on every other
  listed module whose application it (transitively) lists in `applications` or
  `optional_applications`, which is what its `mix.exs` deps say. No callback and
  no module change. Entries with no relation keep their input order (the name
  order of `list/1`), so the result is stable. A cycle cannot be ordered; its
  members keep their input order rather than raising.
  """
  @spec order_by_dependencies([entry()]) :: [entry()]
  def order_by_dependencies(entries) when is_list(entries) do
    order_by_dependencies(entries, application_dependencies(entries))
  end

  @doc false
  # `deps` maps a module to the modules it must come after. Split from
  # `order_by_dependencies/1` so the sort is testable without real applications.
  @spec order_by_dependencies([entry()], %{module() => [module()]}) :: [entry()]
  def order_by_dependencies(entries, deps) when is_list(entries) and is_map(deps) do
    sort_entries(entries, deps, [], [])
  end

  defp sort_entries([], _deps, _done, acc), do: Enum.reverse(acc)

  defp sort_entries(remaining, deps, done, acc) do
    ready? = fn entry ->
      deps |> Map.get(entry.module, []) |> Enum.all?(&(&1 in done))
    end

    # The first entry whose dependencies are all placed; on a cycle, the first one.
    next = Enum.find(remaining, ready?) || hd(remaining)

    sort_entries(
      List.delete(remaining, next),
      deps,
      [next.module | done],
      [next | acc]
    )
  end

  # Only edges between the listed modules matter, so a dependency that is up to
  # date (not listed) or that has no migrations imposes nothing.
  defp application_dependencies(entries) do
    app_to_module =
      for entry <- entries,
          app = Application.get_application(entry.module),
          into: %{},
          do: {app, entry.module}

    for entry <- entries, into: %{} do
      case Application.get_application(entry.module) do
        nil ->
          {entry.module, []}

        app ->
          reachable = app |> reachable_apps(MapSet.new()) |> MapSet.delete(app)

          {entry.module, for(a <- reachable, mod = app_to_module[a], mod != nil, do: mod)}
      end
    end
  end

  defp reachable_apps(app, seen) do
    if MapSet.member?(seen, app) do
      seen
    else
      Application.load(app)

      [:applications, :optional_applications]
      |> Enum.flat_map(&(Application.spec(app, &1) || []))
      |> Enum.reduce(MapSet.put(seen, app), &reachable_apps/2)
    end
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

  @doc """
  Filters a `list/1` result down to entries whose database is newer than the
  code now running — a rollback, or a dependency pinned backwards. Surfaced
  separately from `pending/1` so callers don't fold a genuine problem into
  "nothing to do" just because it isn't something `mix phoenix_kit.update`
  would act on.

  Pure filter, same reasoning as `pending/1`.
  """
  @spec ahead_of_code([entry()]) :: [entry()]
  def ahead_of_code(entries) when is_list(entries) do
    Enum.filter(entries, &(&1.status == :ahead_of_code))
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
