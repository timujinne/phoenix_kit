defmodule PhoenixKit.Migrations.Postgres.V176 do
  @moduledoc """
  V176: validate existing NOT VALID foreign keys. Never deletes a row.

  ## Where this comes from

  Andi's A002 checked its own premise before writing code: the cascade
  `UUIDFKColumns.@fk_constraints` declares for
  `phoenix_kit_users_tokens.user_uuid` and
  `phoenix_kit_user_role_assignments.user_uuid` already exists and already
  works — deleting a user with raw SQL, bypassing every application code
  path, cascades correctly on any schema at V164+ (verified in a rolled-back
  transaction on a live install). The orphans a prior cleanup removed were
  rows created BEFORE the constraint existed (17-24 July; the FK repair
  landed 10 August) — exactly what `NOT VALID` records: pre-existing rows
  were never checked, new violations have been impossible since. What never
  happened is validating it, because nothing in core ever does.

  `convalidated` appears exactly once anywhere in this codebase before this
  file — inside V164, about constraints IT just created, and V164's own
  moduledoc says plainly: "re-running it does not retry them … VALIDATE each
  by hand." Nobody's hand ever did, and `mix phoenix_kit.doctor`'s Orphaned
  FK check does not report this state at all — it looks for orphan ROWS,
  which a NOT VALID constraint with zero *current* violations has none of.

  Filed as V175 originally; renumbered to V176 when upstream took V175 for
  an unrelated Buckets change (`phoenix_kit_buckets.integration_uuid`) while
  this branch was still in review. No content changed in the move beyond
  the version number itself and the COMMENT ON TABLE stamps.

  ## What this does

  For every `{table, uuid_fk, ref_table, ref_col, _on_delete}` in
  `UUIDFKColumns.fk_constraints/0` (the exact list, not a copy — same reason
  V164 shares it rather than re-declaring): if a foreign key of that exact
  shape exists — matched by shape (referencing column -> referenced column),
  not by name, so a constraint V164 adopted under a different name is still
  found — and is `NOT VALID`:

    * **zero orphaned rows right now** → `VALIDATE CONSTRAINT`. The count is
      checked FIRST specifically so this never attempts a `VALIDATE` already
      known to fail — that is a full table scan under `SHARE UPDATE
      EXCLUSIVE` for nothing.
    * **one or more orphaned rows** → left exactly as it is. **Nothing here
      ever deletes a row or nulls out a reference to force a constraint
      through** — the same policy V164 states for itself, for the same
      reason: this runs against other people's already-deployed data, not
      data this call created moments earlier. A warning names the
      table/column and the real orphan count
      (`PhoenixKit.Migrations.Repair.Probe.orphan_count/6`, reused, never a
      guess), then a one-line end-of-run summary — the per-constraint
      warnings are easy to lose in a deploy log (same reasoning as V164's
      `report_not_valid_fks/1`).

  Already-valid constraints, and declarations whose table/column (or the
  referenced table/column) is absent — an uninstalled feature module, same
  case V164 skips — are silently left alone: nothing to report, this version
  has no business with either.

  Idempotent: a constraint this pass validates reads `convalidated = true`
  on every later run and is skipped instantly (one shape probe, no table
  scan). A constraint left `NOT VALID` because of orphans is re-checked
  fresh on every run — the count is a live read, not cached — so once an
  operator resolves the rows a re-run validates it with no further action.

  ## down/1

  A repair, not a feature — same precedent as V164/V174: rolling back does
  not un-validate a constraint that is now genuinely clean. Comment restamp
  only, back to V175 (the Buckets version immediately below this one in the
  renumbered chain).
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Repair.Probe
  alias PhoenixKit.Migrations.UUIDFKColumns

  def up(%{prefix: prefix} = opts) do
    escaped_prefix = Map.get(opts, :escaped_prefix, prefix)

    # See V164's identical note: the immediate queries below must see
    # whatever V164 (or any earlier version in this same chain run) just
    # queued — this chain shares one command buffer per invocation.
    flush()

    still_not_valid =
      for {table, uuid_fk, ref_table, ref_col, _on_delete} <- UUIDFKColumns.fk_constraints(),
          label = validate_one(repo(), table, uuid_fk, ref_table, ref_col, prefix, escaped_prefix),
          not is_nil(label) do
        label
      end

    report_still_not_valid(still_not_valid)

    execute("COMMENT ON TABLE #{prefix_table_name("phoenix_kit", prefix)} IS '176'")
  end

  def down(%{prefix: prefix} = _opts) do
    # Repair, not a feature — never un-validates a constraint on rollback
    # (V57/V164/V174's precedent). Comment restamp only.
    execute("COMMENT ON TABLE #{prefix_table_name("phoenix_kit", prefix)} IS '175'")
  end

  # ── Validate one declared FK ─────────────────────────────────────────
  #
  # Exposed (not `defp`) and `@doc false` so the test suite can drive this
  # exact function against a real NOT VALID constraint with real orphaned
  # rows behind it. By the time any test runs, the chain has already applied
  # every version — to empty tables, where V164 validates cleanly on the
  # spot — so testing "through the migrator" from a fresh DB would prove
  # nothing (same reasoning `V174Test` documents for `repair_statements/1`).
  #
  # `repo` is an explicit module argument throughout this section, never
  # `Ecto.Migration.repo/0` — same reason `Probe.orphan_count/6` takes it
  # explicitly. `repo/0`, `execute/1` and `flush/0` all require a live
  # `Ecto.Migration.Runner`, which does not exist outside an actual migrator
  # invocation (V164Test's and V174Test's identical constraint); every DDL
  # statement here runs through plain `repo.query!/2` instead, so this
  # function works identically called from `up/1` (passing `repo()`, still
  # inside the runner there) and called directly from a test (passing
  # `PhoenixKit.Test.Repo`).

  @doc false
  def validate_one(repo, table, uuid_fk, ref_table, ref_col, prefix, escaped_prefix) do
    table_str = Atom.to_string(table)

    if table_exists?(repo, table_str, escaped_prefix) and
         column_exists?(repo, table_str, uuid_fk, escaped_prefix) and
         table_exists?(repo, ref_table, escaped_prefix) and
         column_exists?(repo, ref_table, ref_col, escaped_prefix) do
      case fk_shape_present(repo, table_str, uuid_fk, ref_table, ref_col, escaped_prefix) do
        {:present, conname, false} ->
          attempt_validate(
            repo,
            table_str,
            uuid_fk,
            ref_table,
            ref_col,
            conname,
            prefix,
            escaped_prefix
          )

        # Already validated, or no FK of this shape exists at all (nothing
        # for V176 to do — the latter is V164's job, not this one's).
        _ ->
          nil
      end
    end
  end

  # Exposed (not `defp`) and `@doc false` so the test suite can call this
  # directly with a `conname` that does not match the real constraint —
  # `Probe.orphan_count/6` still reads 0 (real state, unaffected), so this
  # proceeds to VALIDATE a name that does not exist, which Postgres refuses
  # (undefined_object, 42704) inside the EXCEPTION handler below. That is
  # the exact "VALIDATE fails for a reason other than orphans" case
  # `validate_one/7` cannot reach through its normal path (it always looks
  # up the real name), and the one this function must not silently report
  # as success on.
  @doc false
  def attempt_validate(
        repo,
        table_str,
        uuid_fk,
        ref_table,
        ref_col,
        conname,
        prefix,
        escaped_prefix
      ) do
    table_name = prefix_table_name(table_str, prefix)

    case Probe.orphan_count(repo, prefix, table_str, uuid_fk, ref_table, ref_col) do
      0 ->
        # PL/pgSQL EXCEPTION handler, not an Elixir rescue — a failing
        # immediate VALIDATE would otherwise abort the surrounding
        # transaction (25P02), same reasoning as V164's `validate_fk/7`. The
        # zero-orphan check above means this is only reached when VALIDATE
        # is EXPECTED to succeed; a failure here is something else entirely
        # (lock contention, a permission error, a row written between the
        # count above and this VALIDATE) — the EXCEPTION handler routes the
        # SQLSTATE to the Postgres log, not to Elixir, so "the query didn't
        # raise" is not proof the constraint validated. Re-read
        # `convalidated` below rather than trust that.
        repo.query!("""
        DO $$
        BEGIN
          ALTER TABLE #{table_name} VALIDATE CONSTRAINT #{conname};
        EXCEPTION
          WHEN OTHERS THEN
            RAISE WARNING 'PhoenixKit V176: VALIDATE CONSTRAINT #{conname} failed: % (SQLSTATE %)',
              SQLERRM, SQLSTATE;
        END $$;
        """)

        # Matched by name (`^conname`), not just shape: `fk_shape_present/6`
        # matches by shape on purpose (a twin V164 itself adopted under a
        # different name must still be found by IT), but that means a
        # differently-named twin of the same shape that is ALREADY valid
        # would otherwise read as "this VALIDATE succeeded" even when the
        # actual target (`conname`) never did.
        case fk_shape_present(repo, table_str, uuid_fk, ref_table, ref_col, escaped_prefix) do
          {:present, ^conname, true} ->
            nil

          _still_not_valid_or_gone ->
            "#{conname} on #{table_str}.#{uuid_fk} could not be validated — 0 orphaned row(s) " <>
              "at count time, but VALIDATE still failed (see the RAISE WARNING above in the " <>
              "Postgres log for the SQLSTATE). Left NOT VALID."
        end

      count ->
        "#{conname} on #{table_str}.#{uuid_fk} (#{orphan_message(count)} — VALIDATE would fail, " <>
          "left NOT VALID)"
    end
  end

  defp orphan_message(:unknown), do: "an unknown number of orphaned row(s)"
  defp orphan_message(count), do: "#{count} orphaned row(s)"

  defp report_still_not_valid([]), do: :ok

  defp report_still_not_valid(labels) do
    IO.warn(
      "PhoenixKit V176 SUMMARY: #{length(labels)} constraint(s) are NOT VALID and could NOT be " <>
        "validated this run — orphaned rows are blocking VALIDATE. Nothing was deleted or " <>
        "nulled out to force it through (new writes are already checked; existing rows are " <>
        "not — same as before this version ran). Investigate and clean up the orphaned rows, " <>
        "then re-run this migration (the orphan count is read fresh every time) or run " <>
        "VALIDATE CONSTRAINT by hand: " <> Enum.join(labels, "; ")
    )
  end

  # Shape-anchored, not name-anchored — the exact idiom V164's
  # `fk_shape_present/5` uses, and the exact reason: a constraint V164
  # itself adopted under a pre-existing but differently-named twin (see its
  # moduledoc) must still be found here by what it enforces, not by the name
  # `fk_constraint_name/2` would have chosen. Kept local rather than shared
  # with V164 — same rule V164 states for its own local `table_exists?` /
  # `column_exists?`: a future refactor of a shared helper must not change
  # what an already-shipped version does.
  defp fk_shape_present(repo, table_str, uuid_fk, ref_table, ref_col, escaped_prefix) do
    query = """
    SELECT c.conname, c.convalidated
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    JOIN pg_class ft ON ft.oid = c.confrelid
    JOIN pg_namespace fn ON fn.oid = ft.relnamespace
    WHERE c.contype = 'f'
      AND n.nspname = '#{escaped_prefix}'
      AND t.relname = '#{table_str}'
      AND ft.relname = '#{ref_table}'
      AND fn.nspname = '#{escaped_prefix}'
      AND array_length(c.conkey, 1) = 1
      AND array_length(c.confkey, 1) = 1
      AND (SELECT a.attname FROM pg_attribute a
           WHERE a.attrelid = c.conrelid AND a.attnum = c.conkey[1]) = '#{uuid_fk}'
      AND (SELECT a.attname FROM pg_attribute a
           WHERE a.attrelid = c.confrelid AND a.attnum = c.confkey[1]) = '#{ref_col}'
    ORDER BY (c.conname = '#{UUIDFKColumns.fk_constraint_name(table_str, uuid_fk)}') DESC
    LIMIT 1
    """

    case repo.query(query, [], log: false) do
      {:ok, %{rows: [[name, validated]]}} -> {:present, name, validated}
      {:ok, %{rows: []}} -> :absent
      # Never guess on a failed probe — a false ":absent" here would read as
      # "nothing to validate" and silently skip a constraint that is really
      # there.
      other -> raise "PhoenixKit V176: could not probe FKs on #{table_str}: #{inspect(other)}"
    end
  end

  # ── Existence checks (same pattern as every other version file) ──────

  defp table_exists?(repo, table, escaped_prefix) do
    query = """
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_name = '#{table}'
      AND table_schema = '#{escaped_prefix}'
    )
    """

    case repo.query(query, [], log: false) do
      {:ok, %{rows: [[true]]}} -> true
      _ -> false
    end
  end

  defp column_exists?(repo, table, column, escaped_prefix) do
    query = """
    SELECT EXISTS (
      SELECT FROM information_schema.columns
      WHERE table_name = '#{table}'
      AND column_name = '#{column}'
      AND table_schema = '#{escaped_prefix}'
    )
    """

    case repo.query(query, [], log: false) do
      {:ok, %{rows: [[true]]}} -> true
      _ -> false
    end
  end

  defp prefix_table_name(table_name, nil), do: table_name
  defp prefix_table_name(table_name, "public"), do: "public.#{table_name}"
  defp prefix_table_name(table_name, prefix), do: "#{prefix}.#{table_name}"
end
