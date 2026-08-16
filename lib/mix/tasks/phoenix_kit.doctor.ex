defmodule Mix.Tasks.PhoenixKit.Doctor do
  @moduledoc """
  Diagnoses PhoenixKit installation, migration, and runtime issues.

  Runs a comprehensive suite of checks covering database connectivity, pool
  configuration, PgBouncer detection, migration state, lock conflicts, and
  application configuration. Prints a clear pass/fail report with actionable
  remediation steps.

  ## Usage

      $ mix phoenix_kit.doctor
      $ mix phoenix_kit.doctor --prefix=auth
      $ mix phoenix_kit.doctor --exit-code

  ## Options

    * `--prefix` - Database schema prefix. When omitted, resolves from
      `config :phoenix_kit, :prefix`, then `"public"` — the same resolution
      `mix phoenix_kit.update` / `--status` use, so a prefixed install is
      diagnosed against the schema it actually lives in.
    * `--exit-code` - Exit non-zero when any check FAILED. Without it this task
      prints "N failures" and still exits 0, so a deploy script that runs it
      cannot act on the result — the same silent success `mix phoenix_kit.status
      --exit-code` exists to remove. Warnings never fail the run; they are
      advisory by construction and several fire on healthy installs. Off by
      default so deploys that run this purely for its report keep passing.

  ## Checks Performed

    1. **Repo Detection** — Can we find and start the Ecto repo?
    2. **DB Connectivity** — Can we execute a simple query?
    3. **Pool Configuration** — Pool size, checkout timeout, queue settings
    4. **PgBouncer Detection** — Is PgBouncer between app and PostgreSQL?
    5. **Migration State** — PhoenixKit version (COMMENT), schema_migrations alignment
    6. **Module Schema Versions** — Modules owning their own chain, vs what their code expects
    7. **Schema Drift** — Columns a migration should have added but the DB lacks
    8. **Pending Migrations** — Migration files not yet recorded in schema_migrations
    9. **UUID Column Types** — Detects varchar uuid columns that crash Ecto on startup
   10. **UUID Primary Keys** — Detects primary keys that are not the expected uuid type
   11. **NULL UUIDs in FK Sources** — Detects NULL uuids that cause infinite backfill loops
   12. **Orphaned FK References** — Detects orphaned rows that block FK constraint creation
   13. **Lock Conflicts** — Any blocked or long-running queries?
   14. **Orphaned Connections** — Idle-in-transaction or stuck connections
   15. **Oban Configuration** — Queues and plugins that consume pool connections
   16. **Oban Cron Queues** — Does every crontab worker have its queue configured?
   17. **PhoenixKit Supervisor** — What's running (update_mode vs full)?
   18. **Child Start Order** — Does the Repo start before PhoenixKit/Oban in application.ex?
   19. **Update Mode** — Is update_mode active?
   20. **daisyUI Version** — Is the host's vendored daisyUI recent enough?
   21. **User Dashboard (deprecated)** — Is the host still on the retired dashboard?
   22. **Sitemap Discoverability** — Is the sitemap actually reachable?
   23. **Crawler Visibility** — noindex on a production-looking host, or a
       staging-looking host left indexable
   24. **Demo Auth Pages** — Are the demo auth routes still exposed?
   25. **Manifest Repair (dry-run)** — `PhoenixKit.Migrations.Repair.verify/1`
       runs read-only against the generated
       `PhoenixKit.Migrations.ExpectedSchema` manifest as an additional,
       non-fatal check (never `:fail`). Passes and says so if the manifest
       has been removed or overridden away in this checkout.
  """

  use Mix.Task

  alias PhoenixKit.Install.ChildOrder
  alias PhoenixKit.Install.PrefixConfig
  alias PhoenixKit.Migrations.ExpectedSchema.Resolver
  alias PhoenixKit.Migrations.Modules, as: MigrationModules
  alias PhoenixKit.Migrations.Postgres
  alias PhoenixKit.Migrations.Repair
  alias PhoenixKit.Migrations.Repair.Report
  alias PhoenixKit.Modules.Crawlers
  alias PhoenixKit.Modules.Crawlers.Bots
  alias PhoenixKit.Modules.Sitemap.RouteResolver
  alias PhoenixKit.Utils.Routes

  @shortdoc "Diagnoses PhoenixKit installation, migration, and runtime issues"

  @switches [prefix: :string, exit_code: :boolean]
  @aliases [p: :prefix]

  # The longest timeout/1 any worker PhoenixKit ships declares
  # (Storage.Workers.SyncFilesJob). A Lifeline rescue_after at or below this is
  # unsafe by construction — see check_lifeline_plugin/2.
  @lifeline_min_rescue_after :timer.minutes(30)

  @impl Mix.Task
  def run(argv) do
    {opts, _argv, _errors} = OptionParser.parse(argv, switches: @switches, aliases: @aliases)

    # Start app with minimal footprint (same approach as phoenix_kit.update)
    Mix.Task.run("app.config")

    # Resolve the prefix AFTER app.config loads config, so a configured
    # non-public prefix is honored — same resolution the updater/status use
    # (--prefix flag → config :phoenix_kit, :prefix → "public"). Reading
    # opts[:prefix] || "public" here queries the version marker at public and
    # reports a prefixed install as "not installed".
    prefix = PrefixConfig.resolve_prefix(opts)

    # Snapshot the host's Oban config BEFORE cap_repo_pool_size/1 zeroes its
    # queues/plugins (it does that to conserve connections in update_mode) —
    # otherwise the Oban Configuration check reports "0 queues, 0 plugins".
    oban_config = Application.get_env(Mix.Project.config()[:app], Oban)

    cap_repo_pool_size(2)
    Application.put_env(:phoenix_kit, :update_mode, true)
    Mix.Task.run("app.start")

    header("PhoenixKit Doctor")

    results = [
      run_check("Repo Detection", fn -> check_repo_detection() end),
      run_check("DB Connectivity", fn -> check_db_connectivity() end),
      run_check("Pool Configuration", fn -> check_pool_config() end),
      run_check("PgBouncer Detection", fn -> check_pgbouncer() end),
      run_check("Migration State", fn -> check_migration_state(prefix) end),
      run_check("Module Schema Versions", fn -> check_module_schema_versions(prefix) end),
      run_check("Schema Drift", fn -> check_schema_drift(prefix) end),
      run_check("Pending Migrations", fn -> check_pending_migrations() end),
      run_check("UUID Column Types", fn -> check_uuid_column_types(prefix) end),
      run_check("UUID Primary Keys", fn -> check_uuid_primary_keys(prefix) end),
      run_check("NULL UUIDs in FK Sources", fn -> check_null_uuids(prefix) end),
      run_check("Orphaned FK References", fn -> check_orphaned_fk_refs(prefix) end),
      run_check("Lock Conflicts", fn -> check_lock_conflicts() end),
      run_check("Orphaned Connections", fn -> check_orphaned_connections() end),
      run_check("Oban Configuration", fn -> check_oban_config(oban_config) end),
      run_check("Oban Cron Queues", fn -> check_cron_queues(oban_config) end),
      run_check("PhoenixKit Supervisor", fn -> check_supervisor_state() end),
      run_check("Child Start Order", fn -> check_child_order() end),
      run_check("Update Mode", fn -> check_update_mode() end),
      run_check("daisyUI Version", fn -> check_daisyui() end),
      run_check("User Dashboard (deprecated)", fn -> check_user_dashboard_deprecation() end),
      run_check("Sitemap Discoverability", fn -> check_sitemap_serving() end),
      run_check("Crawler Visibility", fn -> check_crawler_visibility(prefix) end),
      run_check("Demo Auth Pages", fn -> check_demo_routes() end),
      run_check("Manifest Repair (dry-run)", fn -> check_manifest_repair(prefix) end)
    ]

    IO.puts("")
    summary(results)
    maybe_halt(results, opts[:exit_code] || false)
  end

  @doc """
  The process exit status `--exit-code` should produce: `1` when any check
  failed, `0` otherwise.

  Public because `run/1` is not a unit-test seam (it starts the app and needs a
  real database) — this is the pure decision behind the flag, in the same shape
  as `Mix.Tasks.PhoenixKit.Status.exit_code/2` and
  `Mix.Tasks.PhoenixKit.Repair.exit_code/1`.

  Only `:fail` gates. A `:warn` is advisory by construction — several fire on
  perfectly healthy installs (a capped pool under `update_mode`, an unreadable
  `application.ex`) — and gating on them would make the flag unusable, which is
  how a task ends up back at "reports a problem and exits 0".
  """
  @spec exit_code([{String.t(), {:pass | :warn | :fail, String.t()}}]) :: 0 | 1
  def exit_code(results) do
    if Enum.any?(results, fn {_name, {status, _detail}} -> status == :fail end), do: 1, else: 0
  end

  # Printing "N failures" and exiting 0 makes this task unusable as a deploy
  # gate — and it now owns a check (Module Schema Versions) whose whole point is
  # to catch an install nothing else reports on. Opt-in for the same reason
  # `mix phoenix_kit.status --exit-code` is: an existing pipeline that runs
  # doctor for its report must not start failing on an upgrade.
  #
  # `exit({:shutdown, code})` rather than `Mix.raise/1`, matching
  # `mix phoenix_kit.repair`: the failures are already printed above in full,
  # and re-raising would bury them under a second copy.
  defp maybe_halt(_results, false), do: :ok

  defp maybe_halt(results, true) do
    case exit_code(results) do
      0 -> :ok
      1 -> exit({:shutdown, 1})
    end
  end

  # ── Check implementations (return {:pass|:warn|:fail, detail}) ──────

  defp check_repo_detection do
    app = Mix.Project.config()[:app]
    repos = Application.get_env(app, :ecto_repos, [])

    if repos == [] do
      {:fail, "No :ecto_repos configured for :#{app}"}
    else
      repo = hd(repos)

      info =
        Enum.join(
          [
            "app: :#{app}",
            "repo: #{inspect(repo)}",
            "adapter: #{inspect(repo.__adapter__())}"
          ],
          ", "
        )

      {:pass, info}
    end
  end

  defp check_db_connectivity do
    repo = get_repo!()

    case repo.query("SELECT 1 AS ok", [], timeout: 5_000) do
      {:ok, %{rows: [[1]]}} ->
        {:pass, "Connected"}

      {:error, %{message: msg}} ->
        {:fail, "Query failed: #{msg}"}

      {:error, reason} ->
        {:fail, "Query failed: #{inspect(reason)}"}
    end
  end

  defp check_pool_config do
    app = Mix.Project.config()[:app]
    repo = get_repo!()
    config = Application.get_env(app, repo, [])

    pool_size = config[:pool_size] || 10
    queue_target = config[:queue_target] || 50
    queue_interval = config[:queue_interval] || 1000

    info =
      Enum.join(
        [
          "pool_size: #{pool_size}",
          "queue_target: #{queue_target}ms",
          "queue_interval: #{queue_interval}ms"
        ],
        ", "
      )

    cond do
      pool_size > 20 ->
        {:warn, "pool_size=#{pool_size} is high — may saturate PgBouncer. #{info}"}

      pool_size < 2 ->
        {:warn, "pool_size=#{pool_size} is very low. #{info}"}

      true ->
        {:pass, info}
    end
  end

  defp check_pgbouncer do
    app = Mix.Project.config()[:app]
    repo = get_repo!()
    config = Application.get_env(app, repo, [])

    port =
      cond do
        config[:port] -> config[:port]
        config[:url] -> extract_port_from_url(config[:url])
        true -> 5432
      end

    hostname = config[:hostname] || extract_host_from_url(config[:url]) || "localhost"

    if port != 5432 or String.contains?(to_string(hostname), "pgbouncer") do
      {:warn,
       "Likely PgBouncer (port=#{port}, host=#{hostname}). " <>
         "DDL migrations should use @disable_ddl_transaction true"}
    else
      {:pass, "Direct PostgreSQL (port=#{port}, host=#{hostname})"}
    end
  end

  defp check_migration_state(prefix) do
    repo = get_repo!()
    escaped_prefix = String.replace(prefix, "'", "\\'")

    # Source 1: COMMENT ON TABLE (set by each V*.up migration)
    comment_version = get_comment_version(repo, escaped_prefix)

    # Source 2: migrated_version_runtime (what phoenix_kit.status uses)
    runtime_version =
      try do
        opts = %{prefix: prefix, escaped_prefix: escaped_prefix}
        Postgres.migrated_version_runtime(opts)
      rescue
        _ -> :error
      end

    # Source 3: Code's latest version
    latest_version = Postgres.current_version()

    lines = [
      "COMMENT ON TABLE: V#{comment_version}",
      "migrated_version_runtime: #{if runtime_version == :error, do: "ERROR", else: "V#{runtime_version}"}",
      "Code latest: V#{latest_version}"
    ]

    info = Enum.join(lines, "\n       ")

    # Detect discrepancies
    discrepancy =
      runtime_version != :error and runtime_version != comment_version

    cond do
      discrepancy ->
        {:warn,
         "DISCREPANCY between version sources!\n       #{info}\n       " <>
           "The COMMENT was updated by a migration that didn't commit to schema_migrations " <>
           "(killed process or missing @disable_ddl_transaction true)."}

      comment_version == 0 ->
        {:warn, "PhoenixKit not installed.\n       #{info}"}

      comment_version < latest_version ->
        {:warn, "Needs migration.\n       #{info}"}

      comment_version == latest_version ->
        {:pass, info}

      true ->
        {:warn, "DB version > code version.\n       #{info}"}
    end
  end

  # Columns a given migration version adds. If the version marker claims that
  # version (or higher) but the column is missing at the prefix, the install
  # drifted — the marker is ahead of the actual schema (e.g. a version renumber
  # that crossed an upgrade, or an earlier prefix-confused migration run). A
  # query that selects the column then crashes at runtime, and re-running the
  # migrator is a no-op because the marker already covers that version.
  @expected_columns [
    {150, "phoenix_kit_users_tokens", "browser"},
    {150, "phoenix_kit_users_tokens", "os"}
  ]

  # Core's marker says nothing about a module that owns its own chain, so every
  # check above can pass while a module's tables sit versions behind the code
  # querying them. That gap presents as an undefined-column 500 on the module's
  # admin page — no migration error, and `doctor` previously gave the install a
  # clean bill of health, which is the worst possible moment to be reassuring.
  defp check_module_schema_versions(prefix) do
    modules = MigrationModules.list(prefix: prefix)

    failed = MigrationModules.failed(modules)
    pending = MigrationModules.pending(modules)

    cond do
      modules == [] ->
        {:pass, "No installed module owns migrations."}

      pending != [] ->
        {:fail,
         "Behind: #{describe_module_versions(pending)}#{unreadable_suffix(failed)}. " <>
           "Run mix phoenix_kit.update --yes (mix ecto.migrate alone does not write these)."}

      failed != [] ->
        {:warn,
         "Version unreadable for #{Enum.map_join(failed, ", ", & &1.name)} — " <>
           "their tables may be behind and nothing can tell. See mix phoenix_kit.status --verbose."}

      true ->
        {:pass, "#{length(modules)} module(s), all at the version their code expects."}
    end
  end

  defp describe_module_versions(entries) do
    Enum.map_join(entries, ", ", fn entry ->
      "#{entry.name} V#{entry.installed} (code expects V#{entry.target})"
    end)
  end

  # Behind and unreadable are not alternatives — one run can hold both, and the
  # `cond` above reaches the `failed` branch only when nothing is pending. Left
  # to it, an install with one module behind and another whose coordinator
  # raised reported only the first, and the unreadable module vanished from the
  # report entirely. It is the one an operator cannot discover any other way,
  # which is why `StatusReport.next_action/3` and the status tree both surface
  # it first; the severity stays `:fail` because a behind module is actionable.
  defp unreadable_suffix([]), do: ""

  defp unreadable_suffix(failed),
    do: "; version unreadable for #{Enum.map_join(failed, ", ", & &1.name)}"

  defp check_schema_drift(prefix) do
    repo = get_repo!()
    escaped_prefix = String.replace(prefix, "'", "\\'")
    marker = get_comment_version(repo, escaped_prefix)

    if marker == 0 do
      {:pass, "PhoenixKit not installed at prefix #{inspect(prefix)} — nothing to check."}
    else
      missing =
        @expected_columns
        |> Enum.filter(fn {min_version, _t, _c} -> marker >= min_version end)
        |> Enum.reject(fn {_v, table, column} ->
          column_exists?(repo, escaped_prefix, table, column)
        end)

      report_schema_drift(missing, marker, prefix)
    end
  end

  defp report_schema_drift([], marker, _prefix),
    do: {:pass, "Columns expected at V#{marker} are present."}

  defp report_schema_drift(missing, marker, prefix) do
    names = Enum.map_join(missing, ", ", fn {v, t, c} -> "#{t}.#{c} (V#{v})" end)
    lowest = missing |> Enum.map(fn {v, _t, _c} -> v end) |> Enum.min()
    p = if prefix == "public", do: "public.", else: "#{prefix}."

    {:fail,
     "Marker says V#{marker} but these columns are missing: #{names}. The install drifted " <>
       "(marker ahead of schema). Roll the marker back one version and re-run the migrator — " <>
       "the column adds are idempotent (add_if_not_exists), so this is safe:\n" <>
       "       COMMENT ON TABLE #{p}phoenix_kit IS '#{lowest - 1}';\n" <>
       "       mix phoenix_kit.update#{prefix_flag(prefix)}"}
  end

  defp column_exists?(repo, escaped_prefix, table, column) do
    query = """
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_schema = '#{escaped_prefix}'
      AND table_name = '#{table}'
      AND column_name = '#{column}'
    )
    """

    case repo.query(query, [], log: false) do
      {:ok, %{rows: [[true]]}} -> true
      _ -> false
    end
  end

  defp prefix_flag("public"), do: ""
  defp prefix_flag(prefix), do: " --prefix=#{prefix}"

  defp check_pending_migrations do
    repo = get_repo!()
    migrations_path = Path.join(["priv", "repo", "migrations"])

    migration_files =
      if File.dir?(migrations_path) do
        migrations_path
        |> File.ls!()
        |> Enum.filter(&String.ends_with?(&1, ".exs"))
        |> Enum.map(fn f ->
          case Integer.parse(f) do
            {version, _rest} -> {version, f}
            :error -> nil
          end
        end)
        |> Enum.reject(&is_nil/1)
        |> Enum.sort()
      else
        []
      end

    recorded =
      case repo.query("SELECT version FROM schema_migrations ORDER BY version", []) do
        {:ok, %{rows: rows}} -> Enum.map(rows, fn [v] -> v end) |> MapSet.new()
        _ -> MapSet.new()
      end

    pending =
      Enum.reject(migration_files, fn {version, _name} -> MapSet.member?(recorded, version) end)

    phoenix_kit_pending =
      Enum.filter(pending, fn {_v, name} -> String.contains?(name, "phoenix_kit") end)

    # Also check for duplicate PhoenixKit migration files (same version range)
    pk_files =
      Enum.filter(migration_files, fn {_v, name} -> String.contains?(name, "phoenix_kit") end)

    duplicates = find_duplicate_migration_ranges(pk_files)

    detail_parts = []

    detail_parts =
      if pending != [] do
        pk_names = Enum.map_join(phoenix_kit_pending, "\n       ", fn {_v, n} -> n end)

        detail_parts ++
          [
            "#{length(pending)} pending (#{length(phoenix_kit_pending)} PhoenixKit):\n       #{pk_names}"
          ]
      else
        detail_parts ++ ["All #{length(migration_files)} files recorded in schema_migrations"]
      end

    detail_parts =
      if duplicates != "" do
        detail_parts ++ ["DUPLICATE ranges detected:\n       #{duplicates}"]
      else
        detail_parts
      end

    detail = Enum.join(detail_parts, "\n       ")

    cond do
      duplicates != "" ->
        {:warn, detail}

      pending == [] ->
        {:pass, detail}

      true ->
        {:warn, detail}
    end
  end

  defp find_duplicate_migration_ranges(pk_files) do
    # Extract version ranges from filenames like "phoenix_kit_update_v49_to_v71.exs"
    ranges =
      Enum.map(pk_files, fn {_v, name} ->
        case Regex.run(~r/phoenix_kit_\w+_v(\d+)_to_v(\d+)/, name) do
          [_, from, to] -> {String.to_integer(from), String.to_integer(to), name}
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    # Find overlapping ranges
    overlaps =
      for {from1, to1, name1} <- ranges,
          {from2, to2, name2} <- ranges,
          name1 < name2,
          max(from1, from2) < min(to1, to2),
          do: "#{name1} overlaps #{name2}"

    Enum.join(overlaps, "\n       ")
  end

  # A missing primary key is what the varchar column actually COST, and the type
  # check could not see it: a table can have a perfectly typed uuid column and
  # still have no key. Reported by a host whose phoenix_kit_email_events had
  # both problems and whose doctor run named only the first.
  defp check_uuid_primary_keys(prefix) do
    repo = get_repo!()

    query = """
    SELECT t.table_name
    FROM information_schema.tables t
    WHERE t.table_schema = $1
      AND t.table_name LIKE 'phoenix\\_kit\\_%'
      AND t.table_type = 'BASE TABLE'
      AND EXISTS (
        SELECT 1 FROM information_schema.columns c
        WHERE c.table_name = t.table_name
          AND c.table_schema = t.table_schema
          AND c.column_name = 'uuid'
      )
      AND NOT EXISTS (
        SELECT 1
        FROM pg_constraint pc
        JOIN pg_class pcl ON pcl.oid = pc.conrelid
        JOIN pg_namespace pn ON pn.oid = pcl.relnamespace
        WHERE pcl.relname = t.table_name
          AND pn.nspname = t.table_schema
          AND pc.contype = 'p'
      )
    ORDER BY t.table_name
    """

    case repo.query(query, [prefix], log: false) do
      {:ok, %{rows: []}} ->
        {:pass, "Every phoenix_kit table with a uuid column has a primary key"}

      {:ok, %{rows: rows}} ->
        tables = Enum.map_join(rows, "\n       ", fn [t] -> t end)

        {:fail,
         "#{length(rows)} table(s) have a uuid column but NO primary key:\n       #{tables}\n       " <>
           "Fix: mix phoenix_kit.repair_uuid  (or upgrade — V163 repairs this automatically)"}

      _ ->
        {:warn, "Could not check (phoenix_kit tables may not exist yet)"}
    end
  end

  # Pre-migration: check for varchar/text uuid columns that should be native uuid type.
  # A varchar uuid column on phoenix_kit_settings crashes the Ecto schema loader on startup,
  # blocking migrations from even running.
  defp check_uuid_column_types(prefix) do
    repo = get_repo!()
    escaped_prefix = String.replace(prefix, "'", "\\'")

    query = """
    SELECT table_name, data_type
    FROM information_schema.columns
    WHERE table_name LIKE 'phoenix_kit_%'
      AND column_name = 'uuid'
      AND table_schema = '#{escaped_prefix}'
      AND data_type IN ('character varying', 'text', 'character')
    ORDER BY table_name
    """

    case repo.query(query, [], log: false) do
      {:ok, %{rows: []}} ->
        {:pass, "All uuid columns are native uuid type"}

      {:ok, %{rows: rows}} ->
        tables =
          Enum.map_join(rows, "\n       ", fn [table, dtype] ->
            "#{table} (#{dtype})"
          end)

        # The remedy is a task, not a single ALTER. The ALTER alone restores the
        # TYPE and leaves the column nullable, without a UUIDv7 default and
        # without a primary key — anyone following it literally ends up in a
        # state that still fails this doctor. Reported by a host who did.
        {:fail,
         "#{length(rows)} table(s) have a varchar uuid column:\n       #{tables}\n       " <>
           "These break any Ecto schema that maps to them, and cannot carry a uuid primary key.\n       " <>
           "Fix: mix phoenix_kit.repair_uuid  (or upgrade — V163 repairs this automatically)"}

      _ ->
        {:warn, "Could not check (phoenix_kit tables may not exist yet)"}
    end
  end

  # Pre-migration: check for NULL uuid values in tables that are FK sources.
  # NULL source UUIDs cause the V56 batched backfill loop to run forever.
  defp check_null_uuids(prefix) do
    repo = get_repo!()
    escaped_prefix = String.replace(prefix, "'", "\\'")

    # Key FK source tables whose uuid column must not be NULL
    source_tables = [
      "phoenix_kit_users",
      "phoenix_kit_user_roles",
      "phoenix_kit_entities",
      "phoenix_kit_email_logs",
      "phoenix_kit_shop_carts",
      "phoenix_kit_shop_products",
      "phoenix_kit_shop_categories",
      "phoenix_kit_shop_shipping_methods",
      "phoenix_kit_payment_options",
      "phoenix_kit_billing_profiles",
      "phoenix_kit_orders",
      "phoenix_kit_invoices",
      "phoenix_kit_payment_methods",
      "phoenix_kit_subscriptions",
      "phoenix_kit_subscription_types",
      "phoenix_kit_subscription_plans",
      "phoenix_kit_referral_codes",
      "phoenix_kit_ai_endpoints",
      "phoenix_kit_ai_prompts",
      "phoenix_kit_sync_connections"
    ]

    problems =
      Enum.reduce(source_tables, [], fn table, acc ->
        exists_query = """
        SELECT EXISTS (
          SELECT FROM information_schema.columns
          WHERE table_name = '#{table}'
            AND column_name = 'uuid'
            AND table_schema = '#{escaped_prefix}'
        )
        """

        case repo.query(exists_query, [], log: false) do
          {:ok, %{rows: [[true]]}} ->
            table_name = prefix_table_name(table, prefix)

            count_query = "SELECT count(*)::integer FROM #{table_name} WHERE uuid IS NULL"

            case repo.query(count_query, [], log: false) do
              {:ok, %{rows: [[count]]}} when count > 0 ->
                [{table, count} | acc]

              _ ->
                acc
            end

          _ ->
            acc
        end
      end)

    if problems == [] do
      {:pass, "No NULL uuids in FK source tables"}
    else
      detail =
        Enum.map_join(Enum.reverse(problems), "\n       ", fn {table, count} ->
          "#{table}: #{count} rows with NULL uuid"
        end)

      {:fail,
       "NULL uuids found (will cause infinite loop in V56 backfill):\n       #{detail}\n       " <>
         "Fix: UPDATE <table> SET uuid = gen_random_uuid() WHERE uuid IS NULL"}
    end
  end

  # Pre-migration: check for orphaned FK references (rows pointing to deleted parents).
  # Orphaned refs cause V56's add_constraints to fail when adding FK constraints.
  defp check_orphaned_fk_refs(prefix) do
    repo = get_repo!()
    escaped_prefix = String.replace(prefix, "'", "\\'")

    # Check the most common orphaned FK pattern: user_uuid → users.uuid
    fk_checks = [
      {"phoenix_kit_users_tokens", "user_uuid", "phoenix_kit_users", "uuid"},
      {"phoenix_kit_user_role_assignments", "user_uuid", "phoenix_kit_users", "uuid"},
      {"phoenix_kit_admin_notes", "user_uuid", "phoenix_kit_users", "uuid"},
      {"phoenix_kit_email_events", "email_log_uuid", "phoenix_kit_email_logs", "uuid"}
    ]

    problems =
      Enum.reduce(fk_checks, [], fn {table, fk_col, ref_table, ref_col}, acc ->
        # Check both tables and columns exist
        table_name = prefix_table_name(table, prefix)
        ref_name = prefix_table_name(ref_table, prefix)

        check_query = """
        SELECT EXISTS (
          SELECT FROM information_schema.columns
          WHERE table_name = '#{table}' AND column_name = '#{fk_col}' AND table_schema = '#{escaped_prefix}'
        ) AND EXISTS (
          SELECT FROM information_schema.columns
          WHERE table_name = '#{ref_table}' AND column_name = '#{ref_col}' AND table_schema = '#{escaped_prefix}'
        )
        """

        case repo.query(check_query, [], log: false) do
          {:ok, %{rows: [[true]]}} ->
            orphan_query = """
            SELECT count(*)::integer FROM #{table_name} t
            WHERE t.#{fk_col} IS NOT NULL
            AND NOT EXISTS (SELECT 1 FROM #{ref_name} r WHERE r.#{ref_col} = t.#{fk_col})
            """

            case repo.query(orphan_query, [], log: false) do
              {:ok, %{rows: [[count]]}} when count > 0 ->
                [{table, fk_col, ref_table, count} | acc]

              _ ->
                acc
            end

          _ ->
            acc
        end
      end)

    if problems == [] do
      {:pass, "No orphaned FK references found"}
    else
      detail =
        Enum.map_join(Enum.reverse(problems), "\n       ", fn {table, fk_col, ref, count} ->
          "#{table}.#{fk_col} → #{ref}: #{count} orphaned rows"
        end)

      {:fail,
       "Orphaned FK refs found (will block FK constraint creation):\n       #{detail}\n       " <>
         "Fix: DELETE FROM <table> t WHERE NOT EXISTS (SELECT 1 FROM <ref> r WHERE r.uuid = t.<fk_col>)"}
    end
  end

  defp check_lock_conflicts do
    repo = get_repo!()

    query = """
    SELECT count(*) FROM pg_stat_activity
    WHERE datname = current_database()
      AND pid != pg_backend_pid()
      AND wait_event_type = 'Lock'
    """

    case repo.query(query, []) do
      {:ok, %{rows: [[0]]}} ->
        {:pass, "No lock conflicts"}

      {:ok, %{rows: [[count]]}} ->
        detail_query = """
        SELECT pid, age(now(), query_start)::text, left(query, 80)
        FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid != pg_backend_pid()
          AND wait_event_type = 'Lock'
        ORDER BY query_start LIMIT 5
        """

        details =
          case repo.query(detail_query, []) do
            {:ok, %{rows: rows}} ->
              Enum.map_join(rows, "\n       ", fn [pid, dur, q] ->
                "PID #{pid} (#{dur}): #{q}"
              end)

            _ ->
              "Could not fetch details"
          end

        {:fail, "#{count} queries waiting on locks:\n       #{details}"}

      _ ->
        {:warn, "Could not check (may not have pg_stat_activity access)"}
    end
  end

  defp check_orphaned_connections do
    repo = get_repo!()

    query = """
    SELECT state, count(*)::integer, max(age(now(), state_change))::text
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND pid != pg_backend_pid()
    GROUP BY state ORDER BY state
    """

    case repo.query(query, []) do
      {:ok, %{rows: rows}} ->
        info =
          Enum.map_join(rows, ", ", fn [state, count, oldest] ->
            "#{state || "null"}: #{count} (oldest: #{oldest})"
          end)

        idle_in_tx =
          Enum.find(rows, fn [state, _, _] ->
            state in ["idle in transaction", "idle in transaction (aborted)"]
          end)

        if idle_in_tx do
          [_state, count, oldest] = idle_in_tx

          {:fail,
           "#{count} idle-in-transaction (oldest: #{oldest}). " <>
             "These block DDL. Kill: SELECT pg_terminate_backend(pid) ... All: #{info}"}
        else
          {:pass, info}
        end

      _ ->
        {:warn, "Could not query pg_stat_activity"}
    end
  end

  # Reports the Oban config snapshotted in run/1 BEFORE cap_repo_pool_size/1
  # zeroed its queues/plugins — reading it live here would always show 0/0.
  defp check_oban_config(nil), do: {:pass, "Oban not configured"}

  defp check_oban_config(config) when is_list(config) do
    # `queues: false` / `plugins: false` is Oban's documented way to disable
    # either wholesale (standard in test config, and used by hosts that run
    # jobs on a separate node) — normalize so this check reports instead of
    # raising into run_check/2's rescue as a bogus FAIL.
    raw_plugins = Keyword.get(config, :plugins, [])
    queues = config |> Keyword.get(:queues, []) |> normalize_oban_list()
    plugins = normalize_oban_list(raw_plugins)

    base =
      "#{length(queues)} queues, #{length(plugins)} plugins. Each active queue uses 1 pool connection."

    # Plugins off on purpose (web-only node, test config). Nagging about
    # Lifeline here is a false positive, and the remedy it recommends would
    # rewrite config.exs for a node that must not run plugins at all.
    if raw_plugins == false do
      {:pass, base <> " Oban plugins are disabled on this node (plugins: false)."}
    else
      check_lifeline_plugin(plugins, base)
    end
  end

  defp check_oban_config(_other), do: {:pass, "Oban configured (non-keyword config)"}

  defp normalize_oban_list(value) when is_list(value), do: value
  defp normalize_oban_list(_value), do: []

  # Lifeline's presence is necessary but not sufficient: it rescues purely by
  # elapsed time with no liveness check, so a rescue_after at or below the
  # longest job the host can run re-executes that job concurrently with the
  # still-live original. Oban's own docs advertise :timer.minutes(5) as the
  # "more aggressive period" example, so a too-low value is an easy thing for a
  # host to copy in — validate the value, not just the entry.
  defp check_lifeline_plugin(plugins, base) do
    case lifeline_entry(plugins) do
      nil ->
        {:warn,
         base <>
           " Oban.Plugins.Lifeline is not configured — a job orphaned in :executing by a hard " <>
           "crash (kill -9, OOM, node failure) is never rescued back to :available. Run " <>
           "mix phoenix_kit.update to add {Oban.Plugins.Lifeline, rescue_after: :timer.minutes(60)}."}

      {:ok, rescue_after}
      when is_integer(rescue_after) and rescue_after <= @lifeline_min_rescue_after ->
        {:warn,
         base <>
           " Oban.Plugins.Lifeline is configured with rescue_after: #{div(rescue_after, 60_000)} " <>
           "minutes, at or below the longest job PhoenixKit ships " <>
           "(Storage.Workers.SyncFilesJob, #{div(@lifeline_min_rescue_after, 60_000)} minutes). " <>
           "Lifeline rescues purely by elapsed time and never checks whether the executing node " <>
           "is alive, so a job still running at that mark is rescued and executes a second time " <>
           "concurrently. Raise it above your longest-running job (60 minutes is Oban's default)."}

      _ ->
        {:pass, base}
    end
  end

  # `{:ok, rescue_after}` where rescue_after is nil when unset — an unset value
  # means Oban's own 60-minute default, which is safe.
  defp lifeline_entry(plugins) do
    Enum.find_value(plugins, fn
      Oban.Plugins.Lifeline -> {:ok, nil}
      {Oban.Plugins.Lifeline, opts} when is_list(opts) -> {:ok, Keyword.get(opts, :rescue_after)}
      {Oban.Plugins.Lifeline, _opts} -> {:ok, nil}
      _ -> nil
    end)
  end

  # A cron entry inserts a job whether or not anything is configured to run it,
  # and Oban only fetches for queues this node lists in `queues:`. So a crontab
  # worker whose queue is missing produces one job per tick that stays
  # :available forever — Pruner deletes terminal states only, so nothing ever
  # clears them.
  #
  # PhoenixKit shipped exactly this between 2025-12-28 and 1.7.63: the
  # ProcessScheduledJobsWorker entry went into the generated config without its
  # :scheduled_jobs queue. Hosts installed in that window are still affected,
  # because the installer's *upgrade* path only ever added the entry — one such
  # host was found with 21,337 orphaned rows and climbing at ~1,440/day.
  #
  # Checking the whole crontab rather than that one worker is the point: the
  # next instance of this mistake is then a warning on the next doctor run
  # instead of something a host has to discover by reading its own oban_jobs
  # table.
  @doc """
  Reports crontab entries whose queue this node does not run.

  Public so it can be unit-tested directly against config keyword lists, for
  the same reason as `exit_code/1`: it is the pure decision inside a task whose
  `run/1` needs a live app and a database.
  """
  @spec check_cron_queues(keyword() | nil | term()) :: {:pass | :warn, String.t()}
  def check_cron_queues(nil), do: {:pass, "Oban not configured"}

  def check_cron_queues(config) when is_list(config) do
    raw_queues = Keyword.get(config, :queues, [])
    raw_plugins = Keyword.get(config, :plugins, [])
    queues = normalize_oban_list(raw_queues)

    cond do
      # `testing: :inline | :manual` makes Oban itself overwrite both plugins
      # and queues with [] (Oban.Config.normalize_opts/1), so no cron ever
      # fires and nothing can accumulate. Reading the host's declared values
      # and warning would describe a config Oban is not going to use.
      Keyword.get(config, :testing, :disabled) in [:inline, :manual] ->
        {:pass, "Oban is in testing mode — it runs no queues and no plugins."}

      # `plugins: false` is Oban's documented way to turn plugins off
      # wholesale: no Cron, so no entries to check.
      raw_plugins == false ->
        {:pass, "Oban plugins are disabled on this node (plugins: false)."}

      # Oban documents an empty list and `false` as the same thing — "prevents
      # any queues from starting on init". A web-only node says one or the
      # other, and there every entry would look orphaned, so the honest answer
      # is "not applicable" rather than a warning per crontab line.
      raw_queues == false or queues == [] ->
        {:pass, "Oban runs no queues on this node — jobs are executed elsewhere."}

      true ->
        config
        |> crontab_entries()
        |> check_entry_queues(queues)
    end
  end

  def check_cron_queues(_other), do: {:pass, "Oban configured (non-keyword config)"}

  # `flat_map` rather than "find the Cron plugin", and the top-level key as
  # well as the plugin: Oban still accepts `crontab:` directly on the Oban
  # config and promotes it into a Cron plugin itself
  # (`Oban.Config.crontab_to_plugin/1`). A host using that form has entries the
  # plugins list never mentions, and stopping at the first Cron plugin would
  # have missed them entirely — reporting a clean bill of health on precisely
  # the config this check exists to catch.
  defp crontab_entries(config) do
    plugin_entries =
      config
      |> Keyword.get(:plugins, [])
      |> normalize_oban_list()
      |> Enum.flat_map(fn
        {Oban.Plugins.Cron, opts} when is_list(opts) -> Keyword.get(opts, :crontab, [])
        _ -> []
      end)

    plugin_entries ++ Keyword.get(config, :crontab, [])
  end

  defp check_entry_queues([], _queues),
    do: {:pass, "No Oban.Plugins.Cron crontab entries to check."}

  defp check_entry_queues(entries, queues) do
    configured = MapSet.new(Keyword.keys(queues), &to_string/1)

    orphans =
      for entry <- entries,
          {:ok, worker, queue} <- [entry_queue(entry)],
          not MapSet.member?(configured, queue),
          uniq: true,
          do: {worker, queue}

    case orphans do
      [] ->
        {:pass, "#{length(entries)} crontab entries, every queue configured."}

      orphans ->
        detail =
          Enum.map_join(orphans, ", ", fn {worker, queue} ->
            "#{inspect(worker)} → #{queue}"
          end)

        {:warn,
         "#{length(entries)} crontab entries. These fire into queues this node does not run, so " <>
           "each tick inserts a job nothing will execute and Pruner never clears it (terminal " <>
           "states only): #{detail}. Add the queue to `queues:` in config.exs, or drop the " <>
           "crontab entry — `mix phoenix_kit.update` adds the ones PhoenixKit ships. Check what " <>
           "has already collected first (`SELECT count(*) FROM oban_jobs WHERE state = " <>
           "'available'`): configuring the queue releases the whole backlog at once, and for " <>
           "ProcessScheduledJobsWorker that first sweep publishes every overdue scheduled post " <>
           "and sends every overdue broadcast. `Oban.cancel_all_jobs/1` over the queue clears " <>
           "them without running them."}
    end
  end

  # Mirrors Oban.Plugins.Cron.build_changeset/4: the entry's own opts win over
  # the worker's, and a worker declaring no queue falls back to Oban.Job's
  # "default". (Cron uses Worker.merge_opts/2, whose only special case is
  # :unique — for :queue it is a plain Keyword.merge.)
  #
  # Queues compare as strings because Oban accepts either form — `queue: :foo`
  # in a worker and `foo: 10` in `queues:` are the same queue — and it avoids
  # minting atoms from config while checking it.
  defp entry_queue({expr, worker}), do: entry_queue({expr, worker, []})

  defp entry_queue({_expr, worker, opts}) when is_atom(worker) and is_list(opts) do
    # A crontab may name a worker from a dependency that is not loaded in the
    # doctor's VM. Skipping is right: we cannot read its queue, and guessing
    # would report a host as broken for a module we simply failed to load.
    if Code.ensure_loaded?(worker) and function_exported?(worker, :__opts__, 0) do
      queue =
        worker.__opts__()
        |> Keyword.merge(opts)
        |> Keyword.get(:queue, :default)

      {:ok, worker, to_string(queue)}
    else
      :skip
    end
  end

  defp entry_queue(_other), do: :skip

  defp check_supervisor_state do
    case Process.whereis(PhoenixKit.Supervisor) do
      nil ->
        {:warn, "PhoenixKit.Supervisor not running"}

      pid ->
        children = Supervisor.which_children(pid)
        names = Enum.map(children, fn {id, _, _, _} -> id end)
        {:pass, "#{length(children)} children: #{inspect(names)}"}
    end
  end

  # Reads the host application.ex and verifies the Repo starts BEFORE
  # PhoenixKit.Supervisor and Oban — a child listed before the Repo crashes the
  # app at boot (PhoenixKit reads Settings from the DB; Oban needs the pool).
  # The runtime supervisor check above can't catch this (by the time doctor
  # runs, everything has already started), so we read the source order.
  defp check_child_order do
    repo = get_repo!()

    case host_application_source() do
      {:ok, path, source} ->
        where = Path.relative_to_cwd(path)

        case ChildOrder.check(source, repo) do
          {:ok, detail} ->
            {:pass, "#{detail} (#{where})"}

          {:misordered, mods} ->
            names = Enum.map_join(mods, ", ", &inspect/1)

            {:fail,
             "#{names} start BEFORE #{inspect(repo)} in #{where}. PhoenixKit.Supervisor " <>
               "reads Settings from the database and Oban needs the connection pool, so both " <>
               "must be listed AFTER your Repo. Move #{inspect(repo)} above them in the " <>
               "children list to fix the boot crash."}

          :no_repo_in_children ->
            {:warn,
             "Couldn't find #{inspect(repo)} in the children list of #{where} — verify " <>
               "PhoenixKit.Supervisor and Oban are started after your Repo."}

          :no_children ->
            {:warn, "Couldn't locate a children list in #{where} to verify start order."}
        end

      :error ->
        {:warn, "Couldn't locate your application.ex to verify child start order."}
    end
  end

  defp check_update_mode do
    update_mode = Application.get_env(:phoenix_kit, :update_mode, false)

    if update_mode do
      {:warn, "update_mode=true (doctor runs in update_mode to minimize DB connections)"}
    else
      {:pass, "update_mode=false (normal operation)"}
    end
  end

  # ── Helpers ──────────────────────────────────────────────────────────

  defp get_repo! do
    app = Mix.Project.config()[:app]

    case Application.get_env(app, :ecto_repos, []) do
      [repo | _] -> repo
      [] -> raise "No :ecto_repos configured for :#{app}"
    end
  end

  # Locate the host's application.ex — first via the compiled application
  # module's source path, then the conventional lib/<app>/application.ex.
  defp host_application_source do
    app = Mix.Project.config()[:app]

    candidates =
      [
        case Application.spec(app, :mod) do
          {mod, _args} -> module_source(mod)
          _ -> nil
        end,
        Path.join(["lib", "#{app}", "application.ex"])
      ]
      |> Enum.reject(&is_nil/1)

    Enum.find_value(candidates, :error, fn path ->
      case File.read(path) do
        {:ok, source} -> {:ok, path, source}
        _ -> nil
      end
    end)
  end

  defp module_source(mod) do
    with {:module, _} <- Code.ensure_loaded(mod),
         source when not is_nil(source) <- mod.module_info(:compile)[:source] do
      to_string(source)
    else
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp cap_repo_pool_size(pool_size) do
    app = Mix.Project.config()[:app]
    repos = Application.get_env(app, :ecto_repos, [])

    Enum.each(repos, fn repo ->
      current = Application.get_env(app, repo, [])
      updated = Keyword.put(current, :pool_size, pool_size)
      Application.put_env(app, repo, updated)
    end)

    # Disable Oban queues to save connections
    case Application.get_env(app, Oban) do
      nil ->
        :ok

      config ->
        updated = config |> Keyword.put(:queues, []) |> Keyword.put(:plugins, [])
        Application.put_env(app, Oban, updated)
    end
  rescue
    _ -> :ok
  end

  defp get_comment_version(repo, escaped_prefix) do
    table_query = """
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_name = 'phoenix_kit' AND table_schema = '#{escaped_prefix}'
    )
    """

    case repo.query(table_query, [], log: false) do
      {:ok, %{rows: [[true]]}} ->
        version_query = """
        SELECT pg_catalog.obj_description(pg_class.oid, 'pg_class')
        FROM pg_class
        LEFT JOIN pg_namespace ON pg_namespace.oid = pg_class.relnamespace
        WHERE pg_class.relname = 'phoenix_kit'
        AND pg_namespace.nspname = '#{escaped_prefix}'
        """

        case repo.query(version_query, [], log: false) do
          {:ok, %{rows: [[version]]}} when is_binary(version) -> String.to_integer(version)
          _ -> 0
        end

      _ ->
        0
    end
  end

  defp prefix_table_name(table_name, "public"), do: "public.#{table_name}"
  defp prefix_table_name(table_name, prefix), do: "#{prefix}.#{table_name}"

  defp extract_port_from_url(nil), do: nil

  defp extract_port_from_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{port: port} when is_integer(port) -> port
      _ -> nil
    end
  end

  defp extract_port_from_url(_), do: nil

  defp extract_host_from_url(nil), do: nil

  defp extract_host_from_url(url) when is_binary(url) do
    case URI.parse(url) do
      %URI{host: host} when is_binary(host) -> host
      _ -> nil
    end
  end

  defp extract_host_from_url(_), do: nil

  # The host owns assets/vendor/daisyui.js (scaffolded by phx.new, upgraded
  # manually). PhoenixKit's modals rely on daisyUI >= the minimum for correct
  # modal scrollbar-gutter handling — this check is where a host finds out
  # it's behind (install/update print the same warning).
  defp check_daisyui do
    alias PhoenixKit.Install.DaisyUI

    minimum = DaisyUI.minimum_version()

    case DaisyUI.check() do
      :ok ->
        {:pass, "daisyUI #{DaisyUI.installed_version(DaisyUI.host_path())} (>= #{minimum})"}

      {:outdated, version} ->
        {:warn,
         "Vendored daisyUI is #{version}; PhoenixKit is designed against #{minimum}+ " <>
           "(modal scrollbar-gutter handling). Update assets/vendor/daisyui.js + " <>
           "daisyui-theme.js from https://github.com/saadeghi/daisyui/releases and rebuild assets."}

      :unversioned ->
        {:warn,
         "assets/vendor/daisyui.js carries no version marker — cannot verify it against " <>
           "PhoenixKit's designed-for minimum (#{minimum})."}

      :missing ->
        {:warn,
         "No assets/vendor/daisyui.js — custom daisyUI setup? PhoenixKit is designed " <>
           "against daisyUI #{minimum}+; make sure your setup matches."}
    end
  end

  # The user dashboard (/dashboard) is deprecated. It still works unchanged, so
  # this is advisory: WARN while it's enabled (a heads-up that it's going away
  # in favor of the unified /admin panel), PASS once a host has disabled it.
  # install/update print the same advisory (see PhoenixKit.Install.Deprecations).
  defp check_user_dashboard_deprecation do
    if PhoenixKit.Config.user_dashboard_enabled?() do
      {:warn,
       "The user dashboard (/dashboard) is deprecated. It still works and needs no " <>
         "action now, but will be removed in a future release — its functionality is " <>
         "moving into the unified admin panel (/admin), which shows sections per the " <>
         "viewer's permissions."}
    else
      {:pass, "User dashboard disabled — nothing to migrate."}
    end
  end

  # Three demo LiveViews (/test-current-user, /test-redirect-if-auth,
  # /test-ensure-auth) were written into every host by early versions of the
  # installer. They were never documented, never refreshed by
  # `mix phoenix_kit.update`, and `phoenix_kit_hello_world` does the job they
  # were for — properly, and as a versioned package. The generator is gone, but
  # deleting it does nothing for the hosts that already have them, which is what
  # this check is for. One of the three publicly reports whether you are logged
  # in, so this is worth saying out loud rather than leaving to archaeology.
  @demo_routes ["/test-current-user", "/test-redirect-if-auth", "/test-ensure-auth"]

  defp check_demo_routes do
    case RouteResolver.get_router() do
      nil ->
        {:pass, "No router resolved — nothing to check."}

      router ->
        paths = MapSet.new(router.__routes__(), & &1.path)

        case Enum.filter(@demo_routes, &MapSet.member?(paths, &1)) do
          [] ->
            {:pass, "No demo auth pages routed."}

          found ->
            {:warn,
             "This app still routes PhoenixKit's old demo auth pages: #{Enum.join(found, ", ")}. " <>
               "They were scaffolded by an early installer, are undocumented and unmaintained, " <>
               "and one of them reports publicly whether the visitor is logged in. Remove the " <>
               "demo scope from your router and delete the matching " <>
               "*Web.PhoenixKitLive.Test*Live modules. For a worked example of a PhoenixKit " <>
               "module, use phoenix_kit_hello_world instead."}
        end
    end
  rescue
    _ -> {:pass, "Could not introspect routes — skipping."}
  end

  # The two crawler-visibility footguns, in both directions: a production host
  # carrying the global noindex directive (the silent SEO killer — the switch
  # was for staging and someone shipped it), and a staging-looking host that is
  # indexable (Google will happily index a dev box; both directions have
  # happened here). Heuristic on the hostname, so it PASSes with a note when
  # the host cannot be determined rather than guessing.
  #
  # Settings are read via direct SQL, NOT PhoenixKit.Settings: the doctor runs
  # in update_mode, which short-circuits every Settings read to its default —
  # through that API this check would report "disabled" on every install.
  defp check_crawler_visibility(prefix) do
    cond do
      crawler_setting?(prefix, "crawlers_module_enabled", false) == false ->
        {:pass, "Crawlers module disabled — no directives active."}

      crawler_setting?(prefix, "crawlers_no_index", false) ->
        case host_flavor(prefix) do
          {:staging, host} ->
            {:pass, "Global noindex is ON for #{host}, which looks like staging — as intended."}

          {:production, host} ->
            {:warn,
             "The global noindex directive is ON and #{host} does not look like a staging " <>
               "host. If this is production, every page is telling search engines to drop " <>
               "it. Turn it off in Settings → Crawlers."}

          :unknown ->
            {:pass,
             "Global noindex is ON (host undetermined — if this deployment is " <>
               "production, turn it off in Settings → Crawlers)."}
        end

      true ->
        case host_flavor(prefix) do
          {:staging, host} ->
            {:warn,
             "#{host} looks like a staging/dev deployment and is INDEXABLE — search " <>
               "engines will index it. Consider the noindex toggle in Settings → Crawlers."}

          _ ->
            blocked =
              Enum.reject(
                Bots.group_keys(),
                &crawler_setting?(prefix, Crawlers.group_setting_key(&1), true)
              )

            summary =
              case blocked do
                [] -> "all bot groups allowed"
                keys -> "blocked bot groups: #{Enum.join(keys, ", ")}"
              end

            {:pass, "Site indexable, noindex off; #{summary}."}
        end
    end
  rescue
    _ -> {:pass, "Crawler settings unreadable (no database?) — skipping."}
  catch
    :exit, _ -> {:pass, "Crawler settings unreadable (no database?) — skipping."}
  end

  # A boolean settings row, read straight from the table (see moduledoc of the
  # check above for why). Missing row → the given default.
  defp crawler_setting?(prefix, key, default) do
    repo = get_repo!()
    p = if prefix == "public", do: "public.", else: "#{prefix}."

    case repo.query!("SELECT value FROM #{p}phoenix_kit_settings WHERE key = $1", [key]) do
      %{rows: [[value] | _]} -> value == "true"
      _ -> default
    end
  end

  # :staging / :production by hostname shape, :unknown when no URL is
  # configured. Label-based matching, not substring — "device.com" must not
  # read as a dev box, while "max-dev2.example" must. The site_url setting is
  # read via SQL (update_mode, as above) with the endpoint config as fallback.
  defp host_flavor(prefix) do
    url = configured_site_url(prefix) || endpoint_url()

    with url when is_binary(url) and url != "" <- url,
         %URI{host: host} when is_binary(host) and host != "" <- URI.parse(url) do
      # DNS names are case-insensitive; the label list is lowercase.
      host = String.downcase(host)
      if staging_host?(host), do: {:staging, host}, else: {:production, host}
    else
      _ -> :unknown
    end
  rescue
    _ -> :unknown
  end

  defp configured_site_url(prefix) do
    repo = get_repo!()
    p = if prefix == "public", do: "public.", else: "#{prefix}."

    case repo.query!("SELECT value FROM #{p}phoenix_kit_settings WHERE key = 'site_url'", []) do
      %{rows: [[value] | _]} when is_binary(value) and value != "" -> value
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp endpoint_url do
    Routes.base_url()
  rescue
    _ -> nil
  end

  @staging_labels ~w(localhost local staging stage dev develop development test testing demo preview sandbox)

  defp staging_host?(host) do
    cond do
      host in ["localhost", "127.0.0.1", "0.0.0.0", "[::1]"] -> true
      String.ends_with?(host, ".local") -> true
      String.contains?(host, "ngrok") or String.ends_with?(host, "lvh.me") -> true
      ip_address?(host) -> true
      true -> host |> String.split([".", "-"]) |> Enum.any?(&staging_label?/1)
    end
  end

  defp staging_label?(label) do
    # Strip a trailing ordinal so "dev2" and "staging3" match while "device"
    # (whose stem is not in the list) does not.
    base = String.replace(label, ~r/\d+$/, "")
    base != "" and base in @staging_labels
  end

  defp ip_address?(host) do
    match?({:ok, _}, :inet.parse_address(String.to_charlist(host)))
  end

  # Which layer answers GET /sitemap.xml, and whether robots.txt points at it.
  #
  # Three layers can claim that path and nothing tells a host which one won:
  # Plug.Static runs before the router, host routes declared before
  # `phoenix_kit_routes()` bind first, and PhoenixKit is last. A host that
  # reported "the sitemap 404s" had simply never been told any of that.
  defp check_sitemap_serving do
    case {static_sitemap_file(), sitemap_route_owner()} do
      {path, _} when is_binary(path) ->
        {:warn,
         "#{path} exists, and Plug.Static runs before the router — that file is served, " <>
           "not PhoenixKit's generated sitemap. Delete it to use the generated one."}

      {nil, nil} ->
        {:warn,
         "No route answers GET /sitemap.xml. PhoenixKit declares one, so either " <>
           "phoenix_kit_routes() is missing from your router or a host route matched " <>
           "first and was removed."}

      {nil, owner} ->
        {:pass, "GET /sitemap.xml is served by #{inspect(owner)}." <> robots_hint()}
    end
  end

  defp static_sitemap_file do
    Enum.find(["priv/static/sitemap.xml", "priv/static/sitemap.xml.gz"], &File.exists?/1)
  end

  # Same router the sitemap source itself introspects, so what this reports is
  # what actually generates.
  defp sitemap_route_owner do
    case RouteResolver.get_router() do
      nil ->
        nil

      router ->
        case Enum.find(router.__routes__(), &(&1.verb == :get and &1.path == "/sitemap.xml")) do
          %{plug: plug} -> plug
          _ -> nil
        end
    end
  rescue
    _ -> nil
  end

  # robots.txt is host policy — PhoenixKit deliberately does not generate one.
  # Without a Sitemap: line, crawlers only find the sitemap by guessing.
  defp robots_hint do
    path = "priv/static/robots.txt"

    cond do
      not File.exists?(path) ->
        " No priv/static/robots.txt — consider adding one with a `Sitemap:` line."

      File.read!(path) =~ ~r/^\s*sitemap:/im ->
        ""

      true ->
        " priv/static/robots.txt has no `Sitemap:` line — add " <>
          "`Sitemap: https://yourdomain/sitemap.xml` so crawlers find it."
    end
  rescue
    _ -> ""
  end

  # Additional, non-fatal check (task ask, spec §6.1's third manifest
  # consumer): when the generated manifest exists, run
  # `PhoenixKit.Migrations.Repair.verify/1` (read-only) against it and fold
  # the result into doctor's report. Deliberately capped at `:warn` — this
  # check exists to surface repair-relevant information during a routine
  # diagnostic pass, not to make `mix phoenix_kit.doctor` fail a deploy gate
  # over something `mix phoenix_kit.repair` itself reports in full. Wrapped
  # in its own rescue (on top of `run_check/2`'s) so a bug in this brand-new
  # code path can never turn into a `:fail` here either.
  defp check_manifest_repair(prefix) do
    case Resolver.resolve() do
      {:error, :not_generated} ->
        {:pass, Resolver.not_generated_message()}

      {:ok, _module} ->
        manifest_repair_result(prefix)
    end
  rescue
    e -> {:warn, "Manifest repair check raised: #{Exception.message(e)}"}
  end

  defp manifest_repair_result(prefix) do
    case Repair.verify(prefix: prefix) do
      {:ok, report} ->
        summary = Report.summary(report)

        if Report.exit_code(report) == 0 do
          {:pass, "clean — #{summary.total} finding(s), all info-level"}
        else
          {:warn,
           "#{summary.total} finding(s): #{inspect(summary.by_severity)} — run mix phoenix_kit.repair for details"}
        end

      {:error, reason} ->
        {:warn, Repair.error_message(reason)}
    end
  end

  # ── Display ─────────────────────────────────────────────────────────

  defp header(title) do
    IO.puts("\n#{IO.ANSI.bright()}#{IO.ANSI.cyan()}#{title}#{IO.ANSI.reset()}")
    IO.puts(String.duplicate("─", 60))
  end

  defp run_check(name, fun) do
    result =
      try do
        fun.()
      rescue
        e -> {:fail, "Exception: #{Exception.message(e)}"}
      end

    display_check(name, result)
    {name, result}
  end

  defp display_check(name, {:pass, detail}) do
    IO.puts("  #{IO.ANSI.green()}PASS#{IO.ANSI.reset()} #{name}")
    if detail, do: IO.puts("       #{IO.ANSI.faint()}#{detail}#{IO.ANSI.reset()}")
  end

  defp display_check(name, {:warn, detail}) do
    IO.puts("  #{IO.ANSI.yellow()}WARN#{IO.ANSI.reset()} #{name}")
    if detail, do: IO.puts("       #{IO.ANSI.yellow()}#{detail}#{IO.ANSI.reset()}")
  end

  defp display_check(name, {:fail, detail}) do
    IO.puts("  #{IO.ANSI.red()}FAIL#{IO.ANSI.reset()} #{name}")
    if detail, do: IO.puts("       #{IO.ANSI.red()}#{detail}#{IO.ANSI.reset()}")
  end

  defp summary(results) do
    pass = Enum.count(results, fn {_, {status, _}} -> status == :pass end)
    warn = Enum.count(results, fn {_, {status, _}} -> status == :warn end)
    fail = Enum.count(results, fn {_, {status, _}} -> status == :fail end)
    total = length(results)

    IO.puts(
      "#{IO.ANSI.bright()}Summary#{IO.ANSI.reset()}: #{pass}/#{total} passed, #{warn} warnings, #{fail} failures"
    )

    if fail > 0 do
      IO.puts(
        "#{IO.ANSI.red()}Fix the FAIL items above before running migrations.#{IO.ANSI.reset()}"
      )
    end
  end
end
