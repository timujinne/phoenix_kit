defmodule PhoenixKit.Test.LiveDatabaseGuard do
  @moduledoc """
  `config/test.exs` honors `PGDATABASE` — precisely so the suite CAN target
  an already-provisioned database on a role without `CREATEDB` (a shared or
  managed Postgres instance, most often). That is legitimate and must keep
  working: this guard does NOT require any particular test database name.
  What it refuses is a database name that *looks like* a non-test
  environment — because a shell that leaks an environment-tagged
  `PGDATABASE` (say, `myapp_dev`) into every process turns a bare `mix
  test` run, in any working directory, into a silent migrate-and-seed of
  the real, live database. Some hosts already guard against this with an
  external wrapper script that checks the resolved database name before
  invoking `mix test` — but a wrapper living outside the repo only
  protects a caller who remembers to use it, and can only ever check for
  the one name (or few names) it was written against. This guard is the
  same idea, generalized to travel with the repo itself, to any host,
  checking a whole class of dangerous-looking names rather than a fixed
  list.

  Two layers, checked in order:

  1. **Built-in suffix pattern** (`@dangerous_suffixes`) — refuses a
     database name ending in `_dev`, `_development`, `_prod`,
     `_production`, or `_staging` (case-insensitive). These are the
     near-universal Rails/Phoenix/Django convention for naming an
     environment's database (e.g. `phoenix_kit_dev`, `myapp_production`,
     `shop_staging`), so this fires with zero configuration on any host
     that follows it.

  2. **Optional extra denylist**, read from the `PHOENIX_KIT_TEST_DB_DENYLIST`
     environment variable (comma-separated exact names, case-insensitive) —
     for a live database whose name doesn't happen to match the pattern
     above. Empty by default: nothing is refused beyond the pattern unless
     a host opts in. This is an env var rather than app config on purpose —
     it lets a host declare its own known-live names (e.g. in its shell
     profile or process supervisor) without editing a tracked file, the
     same way `PGDATABASE` itself already reaches this repo.

  **What this does NOT do:** refuse a name for merely NOT ending in
  `_test`. An arbitrary pre-provisioned scratch database name (the exact
  case `PGDATABASE`-honoring exists for) — `ci_runner_42`, `pk_scratch_7`,
  a UUID-suffixed throwaway — passes through untouched, because nothing
  about that name resembles a non-test environment. A rule that instead
  *required* a `_test` suffix would refuse that legitimate case outright,
  which is why this guard does not use one. The residual risk this leaves
  is real and is not hidden: a host whose live database is named with no
  recognizable environment suffix (e.g. bare `acme`, or `acme_main`) is
  NOT caught by the built-in pattern and must add it to
  `PHOENIX_KIT_TEST_DB_DENYLIST` itself — nothing here can guess a name
  that carries no signal of what it is.

  Deliberately NOT the `phoenix_kit_crm`/`phoenix_kit_entities`
  `SchemaOwnerGuard` pattern (a `schema_migrations` ownership-marker
  comment, stamped by a package after its own migrations succeed): that
  mechanism only catches a database another *tracked, guard-wearing*
  package has already stamped — confirmed against a scratch database
  built to look exactly like an untouched live one, that it reads a
  database it has never seen, comment-less `schema_migrations` included,
  as `:ok`. A live dev database populated by ordinary `mix ecto.migrate` is
  exactly that shape: nothing has ever stamped it, so a marker check alone
  would wave it through. This guard instead judges the NAME itself.
  """

  @dangerous_suffixes ~w(_dev _development _prod _production _staging)

  defmodule LiveDatabaseError do
    defexception [:message]
  end

  @doc """
  Raises `LiveDatabaseError` if `database` looks like a non-test
  environment's database (see moduledoc). Takes the already-resolved name
  (what `config/test.exs` put in `Application.get_env/2`), not
  `PGDATABASE` itself — the config file's own fallback-when-unset logic is
  the single source of truth for what the suite will actually connect to,
  and duplicating it here would drift the moment either copy changed.
  """
  @spec check!(String.t()) :: :ok
  def check!(database) when is_binary(database) do
    downcased = String.downcase(database)

    cond do
      database == "" ->
        :ok

      Enum.any?(@dangerous_suffixes, &String.ends_with?(downcased, &1)) ->
        raise LiveDatabaseError, message: refusal_message(database, :suffix)

      downcased in extra_denylist() ->
        raise LiveDatabaseError, message: refusal_message(database, :denylist)

      true ->
        :ok
    end
  end

  defp extra_denylist do
    "PHOENIX_KIT_TEST_DB_DENYLIST"
    |> System.get_env("")
    |> String.split(",", trim: true)
    |> Enum.map(&(&1 |> String.trim() |> String.downcase()))
    |> Enum.reject(&(&1 == ""))
    |> MapSet.new()
  end

  defp refusal_message(database, :suffix) do
    """
    Test database resolved to #{inspect(database)}, whose name ends in a \
    suffix (#{Enum.join(@dangerous_suffixes, ", ")}) this guard treats as a \
    non-test environment, not a database a test suite may migrate and seed. \
    Point PGDATABASE at an isolated test database instead \
    (see PhoenixKit.Test.LiveDatabaseGuard's moduledoc).\
    """
  end

  defp refusal_message(database, :denylist) do
    """
    Test database resolved to #{inspect(database)}, which PHOENIX_KIT_TEST_DB_DENYLIST \
    names as a live database this host must never let a test suite touch. \
    Point PGDATABASE at an isolated test database instead \
    (see PhoenixKit.Test.LiveDatabaseGuard's moduledoc).\
    """
  end
end
