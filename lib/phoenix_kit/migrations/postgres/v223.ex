defmodule PhoenixKit.Migrations.Postgres.V223 do
  @moduledoc """
  V223: an AI request's cost in dollars, and the AI tables' leftovers cleared.

  ## The cost

  `phoenix_kit_ai_requests.cost_cents` never held cents: `phoenix_kit_ai` stored a
  provider's reported cost as `round(dollars * 1_000_000)`, millionths of a dollar, so a
  cheap call (a short embedding costs about $0.0000001) was stored as `0`, and every
  reader had to divide.

  The column becomes **`cost`**, a **`numeric(28,18)`** amount of US dollars, like every
  other amount of money in the kit (`price`, `total`, `amount`): `0.00003` is three
  thousandths of a cent. Eighteen decimal places (an attodollar) keep the cheapest
  single tokens with room to spare: a cached input token at $0.0014 per million
  (OpenRouter's cheapest in 2026) is `0.0000000014`, and a small embedding model run
  locally, priced at its electricity, is about `0.0000000001` a token — prices keep
  falling, and a scale is costly to change once released. Postgres stores a numeric's
  significant digits, not its declared scale, so the places cost nothing. The stored
  costs are converted in the same rewrite (`cost_cents / 1_000_000`). The rename is
  deliberate: a `phoenix_kit_ai` that still writes millionths fails on the missing column
  instead of storing costs a million times too large. A database that ran an unreleased
  V223 holding `cost_nanodollars` (billionths, `bigint`) is converted the same way
  (`/ 1_000_000_000`). The AI settings (spend caps, task limits, prices) are converted by
  `phoenix_kit_ai`'s own migration chain, not here.

  ## The leftovers

    * **`phoenix_kit_ai_requests.model`** is widened to `varchar(150)`, the width of
      `phoenix_kit_ai_endpoints.model`: a longer model id failed the usage row's insert,
      so its spend went uncounted.
    * **`phoenix_kit_ai_accounts`** (the provider accounts from before V34's endpoints —
      name, provider, a plaintext API key) and **`phoenix_kit_ai_requests.account_uuid`**
      are dropped. Nothing has read either since V34, which kept the table "for
      historical request references" and never copied it into the endpoints. The number
      of rows dropped is raised as a NOTICE.
    * **Unique indexes on `uuid` beside a primary key** on the endpoints, prompts and
      requests tables (`phoenix_kit_ai_endpoints_uuid_idx`, `phoenix_kit_ai_prompts_uuid_idx`
      — `<prefix>_…` outside `public` — `phoenix_kit_ai_prompts_uuid_index`,
      `phoenix_kit_ai_requests_uuid_idx`) are dropped. They are found by shape (unique,
      btree, on `uuid` alone, no predicate, not a constraint's own), not by name. A foreign
      key bound to one of them (Postgres binds a key to the first matching unique index,
      and these predate the primary keys) blocks its drop, so every such key — this
      module's or another's — is dropped first and added again after, with the same name
      and definition, now bound to the primary key.

  Everything structural is one `DO` block, so it is atomic even though the wrappers this
  chain runs under have no enclosing transaction, and a re-run finds nothing left to do
  (a key is added back only when it is missing). `search_path` is emptied inside it so
  the re-added keys' definitions name their schemas. Cost beside a legacy cost column,
  or both legacy columns, stops the migration instead.

  Needs the `phoenix_kit_ai` release that writes `cost` and no longer reads `account_uuid`.

  ## Locks

  `ALTER COLUMN … TYPE` rewrites the requests table and its indexes once, under an
  `ACCESS EXCLUSIVE` lock held until the block ends: AI calls wait to write their usage
  rows, and spend checks wait to read them. Re-adding the foreign keys checks every row
  of the referencing tables again — the requests table twice (endpoint, prompt) — inside
  the same lock. The accounts table, the guard events and the task settings are small.

  ## Down

  Back to the V222 shape: the costs in integer millionths (`cost_cents`; finer precision
  is lost, a row above $2,147.48 stops the rollback), `model` narrowed to `varchar(100)`
  (a longer model stops the rollback), the four duplicate indexes recreated (the foreign
  keys stay on the primary keys), and an EMPTY `phoenix_kit_ai_accounts` with its
  indexes and an empty `account_uuid` — the rows and keys dropped do not come back.
  """

  use Ecto.Migration

  alias PhoenixKit.Migrations.Postgres.V203

  @doc false
  def up(opts) do
    opts |> Map.get(:prefix, "public") |> up_statements() |> Enum.each(&execute/1)
  end

  @doc "Rolls V223 back to the V222 shape (see the moduledoc's Down)."
  def down(opts) do
    opts |> Map.get(:prefix, "public") |> down_statements() |> Enum.each(&execute/1)
  end

  @doc false
  def up_statements(prefix) do
    p = V203.prefix_str(prefix)
    t = "#{p}phoenix_kit_ai_requests"

    [
      """
      DO $$
      DECLARE
        fk record;
        idx record;
        dropped bigint;
        fk_tables text[] := '{}';
        fk_names text[] := '{}';
        fk_defs text[] := '{}';
        caller_path text := current_setting('search_path');
      BEGIN
        -- Nothing on the path: every name below is written out, and
        -- pg_get_constraintdef/regclass render theirs schema-qualified. Put
        -- back at the end: inside a caller's transaction a local setting would
        -- outlive this block.
        PERFORM set_config('search_path', '', true);

        IF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost")}
          AND (#{column_exists(prefix, "phoenix_kit_ai_requests", "cost_cents")}
               OR #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_nanodollars")}) THEN
          RAISE EXCEPTION 'V223: #{t} has cost and a legacy cost column (cost_cents or cost_nanodollars); move the costs into cost (dollars: cost_cents / 1000000, cost_nanodollars / 1000000000) and drop the legacy column, then migrate again';
        ELSIF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_cents")}
          AND #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_nanodollars")} THEN
          RAISE EXCEPTION 'V223: #{t} has both cost_cents and cost_nanodollars; keep one of them, then migrate again';
        END IF;

        -- 1. The pre-endpoints accounts: never read, never copied into the
        --    endpoints (V34 kept them "for historical request references").
        IF #{column_exists(prefix, "phoenix_kit_ai_requests", "account_uuid")} THEN
          ALTER TABLE #{t} DROP COLUMN account_uuid;
        END IF;

        IF #{table_exists(prefix, "phoenix_kit_ai_accounts")} THEN
          EXECUTE 'SELECT count(*) FROM #{p}phoenix_kit_ai_accounts' INTO dropped;
          RAISE NOTICE 'V223: dropping #{p}phoenix_kit_ai_accounts (% rows, unused since V34)', dropped;
          DROP TABLE #{p}phoenix_kit_ai_accounts;
        END IF;

        -- 2. Unique indexes on uuid beside the primary key, found by shape (a
        --    prefixed install names two of them "<prefix>_..."). A foreign key
        --    bound to one blocks its drop, so every such key is dropped first and
        --    added again after, when the primary key is the one left to bind to.
        FOR idx IN
          SELECT i.indexrelid AS oid, format('%I.%I', n.nspname, ic.relname) AS name
          FROM pg_index i
          JOIN pg_class ic ON ic.oid = i.indexrelid
          JOIN pg_class tc ON tc.oid = i.indrelid
          JOIN pg_namespace n ON n.oid = tc.relnamespace
          JOIN pg_am am ON am.oid = ic.relam
          WHERE n.nspname = '#{prefix}'
            AND tc.relname IN ('phoenix_kit_ai_endpoints', 'phoenix_kit_ai_prompts',
                               'phoenix_kit_ai_requests')
            AND i.indisunique AND NOT i.indisprimary AND NOT i.indisreplident
            AND i.indnatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL
            AND am.amname = 'btree'
            AND (SELECT a.attname FROM pg_attribute a
                 WHERE a.attrelid = tc.oid AND a.attnum = i.indkey[0]) = 'uuid'
            AND NOT EXISTS (SELECT 1 FROM pg_constraint c
                            WHERE c.conindid = i.indexrelid AND c.contype IN ('p', 'u', 'x'))
        LOOP
          FOR fk IN
            SELECT c.conname, c.conrelid::regclass::text AS tbl, pg_get_constraintdef(c.oid) AS def
            FROM pg_constraint c
            WHERE c.contype = 'f' AND c.conindid = idx.oid
          LOOP
            fk_tables := fk_tables || fk.tbl;
            fk_names := fk_names || fk.conname::text;
            fk_defs := fk_defs || fk.def;
            EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', fk.tbl, fk.conname);
          END LOOP;

          EXECUTE 'DROP INDEX ' || idx.name;
        END LOOP;

        -- 3. The cost in dollars (after the drops, so the rewrite rebuilds
        --    fewer indexes).
        IF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_cents")} THEN
          ALTER TABLE #{t} ALTER COLUMN cost_cents TYPE numeric(28,18)
            USING cost_cents::numeric / 1000000;
          ALTER TABLE #{t} RENAME COLUMN cost_cents TO cost;
        ELSIF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_nanodollars")} THEN
          ALTER TABLE #{t} ALTER COLUMN cost_nanodollars TYPE numeric(28,18)
            USING cost_nanodollars::numeric / 1000000000;
          ALTER TABLE #{t} RENAME COLUMN cost_nanodollars TO cost;
        ELSIF EXISTS (SELECT 1 FROM information_schema.columns
                      WHERE table_schema = '#{prefix}' AND table_name = 'phoenix_kit_ai_requests'
                        AND column_name = 'cost' AND data_type = 'numeric'
                        AND (numeric_scale < 18 OR numeric_precision < 28)) THEN
          -- a dev database on an earlier unreleased V223 (numeric(20,10)): widen, lossless
          ALTER TABLE #{t} ALTER COLUMN cost TYPE numeric(28,18);
        END IF;

        -- 4. The foreign keys back, by name, now bound to the primary keys.
        FOR i IN 1 .. coalesce(array_length(fk_names, 1), 0) LOOP
          IF NOT EXISTS (SELECT 1 FROM pg_constraint
                         WHERE conname = fk_names[i] AND conrelid = fk_tables[i]::regclass) THEN
            EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s', fk_tables[i], fk_names[i], fk_defs[i]);
          END IF;
        END LOOP;

        -- 5. A usage row's model as long as an endpoint's.
        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = '#{prefix}' AND table_name = 'phoenix_kit_ai_requests'
                     AND column_name = 'model' AND data_type = 'character varying'
                     AND character_maximum_length < 150) THEN
          ALTER TABLE #{t} ALTER COLUMN model TYPE character varying(150);
        END IF;

        PERFORM set_config('search_path', caller_path, true);
      END
      $$
      """,
      "COMMENT ON TABLE #{p}phoenix_kit IS '223'"
    ]
  end

  @doc false
  def down_statements(prefix) do
    p = V203.prefix_str(prefix)
    t = "#{p}phoenix_kit_ai_requests"
    # V135 named these two "<prefix>_..." outside public
    pn = if prefix == "public", do: "", else: "#{prefix}_"

    [
      """
      DO $$
      DECLARE
        caller_path text := current_setting('search_path');
      BEGIN
        PERFORM set_config('search_path', '', true);

        IF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost")}
          AND #{column_exists(prefix, "phoenix_kit_ai_requests", "cost_cents")} THEN
          RAISE EXCEPTION 'V223 down: #{t} has both cost and cost_cents; keep one of them, then roll back again';
        END IF;

        IF EXISTS (SELECT 1 FROM #{t} WHERE length(model) > 100) THEN
          RAISE EXCEPTION 'V223 down: #{t} has a model longer than 100 characters, which V222 cannot hold; shorten or remove those rows, then roll back again';
        END IF;

        IF EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_schema = '#{prefix}' AND table_name = 'phoenix_kit_ai_requests'
                     AND column_name = 'model' AND character_maximum_length > 100) THEN
          ALTER TABLE #{t} ALTER COLUMN model TYPE character varying(100);
        END IF;

        IF #{column_exists(prefix, "phoenix_kit_ai_requests", "cost")} THEN
          ALTER TABLE #{t} ALTER COLUMN cost TYPE integer
            USING round(cost * 1000000)::integer;
          ALTER TABLE #{t} RENAME COLUMN cost TO cost_cents;
        END IF;

        CREATE UNIQUE INDEX IF NOT EXISTS #{pn}phoenix_kit_ai_endpoints_uuid_idx ON #{p}phoenix_kit_ai_endpoints USING btree (uuid);
        CREATE UNIQUE INDEX IF NOT EXISTS #{pn}phoenix_kit_ai_prompts_uuid_idx ON #{p}phoenix_kit_ai_prompts USING btree (uuid);
        CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_ai_prompts_uuid_index ON #{p}phoenix_kit_ai_prompts USING btree (uuid);
        CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_ai_requests_uuid_idx ON #{t} USING btree (uuid);

        -- the accounts come back empty: their rows cannot
        CREATE TABLE IF NOT EXISTS #{p}phoenix_kit_ai_accounts (
          "name" character varying(100) NOT NULL,
          "provider" character varying(50) DEFAULT 'openrouter'::character varying NOT NULL,
          "api_key" text NOT NULL,
          "base_url" character varying(255),
          "settings" jsonb DEFAULT '{}'::jsonb,
          "enabled" boolean DEFAULT true NOT NULL,
          "last_validated_at" timestamp with time zone,
          "inserted_at" timestamp with time zone NOT NULL,
          "updated_at" timestamp with time zone NOT NULL,
          "uuid" uuid DEFAULT #{p}uuid_generate_v7() NOT NULL
        );

        IF NOT EXISTS (
          SELECT 1 FROM pg_constraint c
          JOIN pg_class tc ON tc.oid = c.conrelid
          JOIN pg_namespace n ON n.oid = tc.relnamespace
          WHERE c.conname = 'phoenix_kit_ai_accounts_pkey'
            AND tc.relname = 'phoenix_kit_ai_accounts' AND n.nspname = '#{prefix}'
        ) THEN
          ALTER TABLE #{p}phoenix_kit_ai_accounts ADD CONSTRAINT phoenix_kit_ai_accounts_pkey PRIMARY KEY (uuid);
        END IF;

        CREATE INDEX IF NOT EXISTS phoenix_kit_ai_accounts_enabled_idx ON #{p}phoenix_kit_ai_accounts USING btree (enabled);
        CREATE INDEX IF NOT EXISTS phoenix_kit_ai_accounts_provider_idx ON #{p}phoenix_kit_ai_accounts USING btree (provider);
        CREATE UNIQUE INDEX IF NOT EXISTS phoenix_kit_ai_accounts_uuid_idx ON #{p}phoenix_kit_ai_accounts USING btree (uuid);

        ALTER TABLE #{t} ADD COLUMN IF NOT EXISTS account_uuid uuid;
        CREATE INDEX IF NOT EXISTS phoenix_kit_ai_requests_account_uuid_idx ON #{t} USING btree (account_uuid);

        PERFORM set_config('search_path', caller_path, true);
      END
      $$
      """,
      "COMMENT ON TABLE #{p}phoenix_kit IS '222'"
    ]
  end

  defp column_exists(prefix, table, column) do
    """
    EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = '#{prefix}'
            AND table_name = '#{table}'
            AND column_name = '#{column}'
        )\
    """
  end

  defp table_exists(prefix, table) do
    """
    EXISTS (
          SELECT 1
          FROM information_schema.tables
          WHERE table_schema = '#{prefix}'
            AND table_name = '#{table}'
        )\
    """
  end
end
