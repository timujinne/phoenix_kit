defmodule PhoenixKit.Migrations.Postgres.V161 do
  @moduledoc """
  V161: Case-insensitive `phoenix_kit_users.username` via `citext`.

  V08 created `username` as `:string` (`VARCHAR(255)`, `v08.ex:38`) with a
  partial unique index on non-null values
  (`phoenix_kit_users_username_uidx`). Postgres resolves comparison
  semantics from the *column's* type, not from how the Ecto schema declares
  the field — so despite the schema, every lookup (`Auth.get_user_by_username/1`
  → bare `Repo.get_by(User, username: ...)`, the `unsafe_validate_unique`
  changeset check, and the unique index itself) has always been exact-match.
  Two accounts differing only by case — `alice` / `Alice` — could both
  register, and `get_user_by_username("ALICE")` would find neither.

  `email` already gets this for free — it's been `citext` since V01
  (`v01.ex:49`) and is explicitly out of scope here (already correct,
  verified live). This migration brings `username` to the same shape: one
  `ALTER COLUMN ... TYPE citext` fixes writes, reads, and the uniqueness
  constraint at once, and makes it structurally impossible for future code
  to reintroduce case-sensitive comparison by accident — the same fix
  already applied to the CRM party email columns in V151.

  ## Pre-check

  Before any DDL, `up/1` scans for existing rows that would collide once
  comparison becomes case-insensitive (`GROUP BY lower(username) HAVING
  count(*) > 1`, mirroring V106's down-step pre-check). `username` is
  nullable, and `GROUP BY` folds every `NULL` into one group — the scan
  filters `WHERE username IS NOT NULL` so two username-less accounts don't
  register as a false collision and abort the upgrade. If a real collision
  is found, `up/1` raises and names the offending value before touching the
  schema; operators resolve it (rename or merge) and re-run.

  The pre-check is **best-effort, not a lock**. `@disable_ddl_transaction`
  means it runs as its own statement, separate from the `ALTER`, so on a
  live system two concurrent registrations of `alice` and `Alice` can still
  slip into that window — the old varchar index is case-sensitive and
  admits both. The real guard is the index rebuild inside the `ALTER`,
  which then fails with Postgres' generic `duplicate key value violates
  unique constraint` instead of the readable message above. Nothing is
  corrupted and the column is left unconverted; a re-run catches the pair
  through the pre-check. Closing that window would mean holding pre-check
  and `ALTER` in one transaction — exactly the long `ACCESS EXCLUSIVE` that
  `@disable_ddl_transaction` exists to avoid — so the gap is deliberate.

  ## Cost: catalog-only, no table rewrite

  `varchar` → `citext` is binary-coercible in Postgres — confirmed against
  `pg_cast` rather than assumed:

      SELECT castmethod, castfunc, castcontext FROM pg_cast
      WHERE castsource = 'varchar'::regtype AND casttarget = 'citext'::regtype;
      -- castmethod = 'b' (binary coercion), castfunc = 0, castcontext = 'a'

  `castmethod = 'b'` means Postgres reinterprets the on-disk bytes as-is —
  no per-row validation pass, no **table** rewrite. The `username` B-tree
  index is a different story: verified live against a throwaway table that
  `ALTER COLUMN ... TYPE citext` DOES rebuild any index on that column
  (`relfilenode` changes) — expected and necessary, since citext orders and
  compares values differently from `varchar` (`lower()`-based, not raw
  byte order), and it's exactly what makes
  `phoenix_kit_users_username_uidx` start rejecting case-variant
  duplicates right after the `ALTER` (confirmed on the same probe:
  inserting `'ALICE'` against an existing `'alice'` row raised
  `unique_violation` immediately post-conversion). So the honest cost
  statement is: no table heap rewrite, but the index rebuild's cost scales
  with the number of non-null `username` values — cheap in absolute terms,
  not a zero-cost catalog flip. The pre-check adds a second pass of the
  same order: `GROUP BY lower(username)` has no index to use, so it is a
  full scan of every non-null `username`. It takes no locks and runs before
  any DDL, so it lengthens the migration without lengthening the outage. The `ALTER TABLE` holds an `ACCESS
  EXCLUSIVE` lock for that (brief) duration, which is why this migration
  keeps `@disable_ddl_transaction true` (core convention — `v154.ex:30`,
  `v159.ex:36`) so the lock is never held for the length of a whole
  migration transaction.

  The `ALTER COLUMN` itself is idempotent, guarded by a `udt_name` check on
  `information_schema.columns` (same shape as V151's email conversion,
  `v151.ex:97-113`), and `prefix` is honored throughout.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.Helpers

  @disable_ddl_transaction true

  def up(opts) do
    prefix = Map.get(opts, :prefix, "public")
    escaped_prefix = Map.get(opts, :escaped_prefix, prefix)
    p = prefix_str(prefix)

    # Pre-check: a case-insensitive collision must be resolved BEFORE the
    # column becomes citext, or the existing unique index would reject one
    # of the colliding rows mid-migration with a generic Postgres error.
    # `WHERE username IS NOT NULL` is required: GROUP BY treats every NULL
    # as equal, so without the filter any two username-less users would
    # look like a duplicate and abort the upgrade for no reason.
    case repo().query!(
           "SELECT lower(username) FROM #{p}phoenix_kit_users " <>
             "WHERE username IS NOT NULL GROUP BY lower(username) HAVING count(*) > 1 LIMIT 1",
           [],
           log: false
         ) do
      %{rows: []} ->
        :ok

      %{rows: [[duplicate]]} ->
        raise """
        Cannot apply V161: username #{inspect(duplicate)} (case-insensitive) \
        is shared by more than one user. Resolve the collision — rename or \
        merge the accounts — before upgrading. Converting `username` to \
        `citext` makes comparison case-insensitive, and the existing unique \
        index (`phoenix_kit_users_username_uidx`) would then reject one of \
        these rows outright.\
        """
    end

    # no-op when citext is already installed (core dependency since V01)
    Helpers.ensure_extension!("citext")

    execute("""
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = '#{escaped_prefix}'
        AND table_name = 'phoenix_kit_users'
        AND column_name = 'username'
        AND udt_name <> 'citext'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_users
        ALTER COLUMN username TYPE citext;
      END IF;
    END $$;
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '161'")
  end

  @doc """
  Reverts `username` to `VARCHAR(255)` (its V08 shape).

  No pre-check needed on the way down: while the column is still `citext`,
  the unique index already refuses any new case-variant duplicate from
  appearing, so there is nothing for a rollback to collide with.
  """
  def down(opts) do
    prefix = Map.get(opts, :prefix, "public")
    escaped_prefix = Map.get(opts, :escaped_prefix, prefix)
    p = prefix_str(prefix)

    execute("""
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = '#{escaped_prefix}'
        AND table_name = 'phoenix_kit_users'
        AND column_name = 'username'
        AND udt_name = 'citext'
      ) THEN
        ALTER TABLE #{p}phoenix_kit_users
        ALTER COLUMN username TYPE VARCHAR(255);
      END IF;
    END $$;
    """)

    execute("COMMENT ON TABLE #{p}phoenix_kit IS '160'")
  end

  defp prefix_str("public"), do: "public."
  defp prefix_str(prefix), do: "#{prefix}."
end
