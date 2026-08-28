# Test helper for PhoenixKit test suite

# Refuse before anything else touches the database — see
# PhoenixKit.Test.LiveDatabaseGuard's moduledoc for why this exists
# alongside (not instead of) an external wrapper script some hosts
# already use for the same purpose.
db_name =
  Application.get_env(:phoenix_kit, PhoenixKit.Test.Repo)[:database] || "phoenix_kit_test"

PhoenixKit.Test.LiveDatabaseGuard.check!(db_name)

# Check if the test database exists before trying to connect.
# Uses `psql -lqt` for a fast check that avoids Postgrex connection hangs.
# Falls back to attempting connection directly if psql is unavailable (e.g., CI).

db_check =
  try do
    case System.cmd("psql", ["-lqt"], stderr_to_stdout: true) do
      {output, 0} ->
        exists =
          output
          |> String.split("\n")
          |> Enum.any?(fn line ->
            line |> String.split("|") |> List.first("") |> String.trim() == db_name
          end)

        if exists, do: :exists, else: :not_found

      _ ->
        # psql not available (CI without postgresql-client) — try connecting directly
        :try_connect
    end
  rescue
    # psql binary not found on this system — try connecting directly
    ErlangError -> :try_connect
  end

# Started before the repo block: the Owner seed below promotes through
# `ensure_first_user_is_owner/1`, which broadcasts on the internal pubsub —
# without the manager running, the seed raises and the rescue silently
# excludes the whole integration half as "no database".
{:ok, _pid} = PhoenixKit.PubSub.Manager.start_link([])

repo_available =
  if db_check == :not_found do
    IO.puts("""
    \n⚠  Test database "#{db_name}" not found — integration tests will be excluded.
       Run `mix test.setup` to create the test database.
    """)

    false
  else
    try do
      {:ok, _} = PhoenixKit.Test.Repo.start_link()

      # Use `ensure_current/2` — it picks up newly-shipped Vxxx
      # migrations on every boot. The previous fixed-version
      # migration-file approach was vulnerable to the
      # outer-Ecto-tracking staleness trap; see
      # `PhoenixKit.Migration.ensure_current/2` moduledoc for the bug
      # story.
      PhoenixKit.Migration.ensure_current(PhoenixKit.Test.Repo, log: false)

      # A COMMITTED Owner, seeded before the sandbox goes manual. Without one,
      # every async test's first `register_user` sees a committed owner-count
      # of 0 and takes FOR NO KEY UPDATE on the one committed Owner role row
      # (Roles.ensure_first_user_is_owner/1), holding it to test end — an
      # app-wide registration convoy queuing every concurrent test on a single
      # tuple lock, and the standing suspect for the suite's rare 40P01.
      # With an Owner already committed, that path short-circuits unlocked.
      #
      # Idempotent so a reused database does not grow a second seed. Tests
      # asserting first-user bootstrap semantics delete this seed's role
      # assignment inside their own sandbox transaction, where the count goes
      # to 0 for them alone.
      # Seeded by direct insert + the bootstrap promoter, NOT register_user:
      # registration consults the rate limiter, whose ETS table is not alive
      # at helper time, and its raise here would trip the rescue below and
      # silently exclude the whole integration half as "no database".
      if PhoenixKit.Users.Roles.count_active_owners() == 0 do
        seed =
          PhoenixKit.Users.Auth.get_user_by_email("seed-owner@phoenixkit.test") ||
            %PhoenixKit.Users.Auth.User{}
            |> Ecto.Changeset.change(%{
              email: "seed-owner@phoenixkit.test",
              hashed_password: Bcrypt.hash_pwd_salt("SeedOwnerPassword123!"),
              confirmed_at: DateTime.utc_now() |> DateTime.truncate(:second),
              is_active: true
            })
            |> PhoenixKit.Test.Repo.insert!()

        {:ok, _} = PhoenixKit.Users.Roles.ensure_first_user_is_owner(seed)
      end

      Ecto.Adapters.SQL.Sandbox.mode(PhoenixKit.Test.Repo, :manual)
      true
    rescue
      e ->
        IO.puts("""
        \n⚠  Could not connect to test database — integration tests will be excluded.
           Run `mix test.setup` to create the test database.
           Error: #{Exception.message(e)}
        """)

        false
    catch
      :exit, reason ->
        IO.puts("""
        \n⚠  Could not connect to test database — integration tests will be excluded.
           Run `mix test.setup` to create the test database.
           Error: #{inspect(reason)}
        """)

        false
    end
  end

Application.put_env(:phoenix_kit, :test_repo_available, repo_available)

# With no reachable database, `PhoenixKit.Test.Repo` still STARTS — only its
# connections fail — so `Settings.repo_available?/0` stays true and every
# settings read on the unit half queues against a dead pool for ~4s before
# falling back to its default. That is the documented "unit tests still need
# PostgreSQL" trap in AGENTS.md; it makes a DB-less `mix test` take minutes and
# times out anything that resolves a path (`Routes.path/1` reads two settings).
#
# `:update_mode` is consulted ONLY by `PhoenixKit.Settings` (plus mix tasks and
# the supervisor, neither of which runs here) and short-circuits the query to
# `nil`, which is the same value the 4s stall eventually produces. So the
# outcome of every read is unchanged; only its cost is. `:repo` stays
# configured, so nothing outside Settings sees a different world.
#
# Applied only in the run where the database is already known to be unusable —
# when it is reachable nothing here changes.
unless repo_available do
  Application.put_env(:phoenix_kit, :update_mode, true)
end

# Start minimal services needed for tests
{:ok, _pid} = PhoenixKit.ModuleRegistry.start_link([])
{:ok, _pid} = PhoenixKit.Users.RateLimiter.Backend.start_link([])

# Start the LV endpoint once for the whole test run. `PhoenixKitWeb.ConnCase`
# previously did this per-test via `start_supervised`, but that ties the
# endpoint's lifetime to a single test pid — when an async test finishes,
# ExUnit tears down its supervisor and any concurrent test loses the
# `PhoenixKitWeb.Endpoint` ETS config table mid-request, surfacing as
# `:ets.lookup(PhoenixKitWeb.Endpoint, :secret_key_base)` ArgumentErrors.
# A single Application-level start avoids that race entirely.
case Process.whereis(PhoenixKitWeb.Endpoint) do
  nil -> {:ok, _} = PhoenixKitWeb.Endpoint.start_link()
  _pid -> :ok
end

# Exclude integration tests when DB is not available
exclude = if repo_available, do: [], else: [:integration]

ExUnit.start(exclude: exclude)
