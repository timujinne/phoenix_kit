defmodule PhoenixKit.Migrations.Postgres.V223Test do
  @moduledoc """
  V223's AI costs in dollars, run as the real SQL: `cost_cents` (integer, millionths)
  becomes `cost` (numeric(28,18), dollars) with every cost converted, an unreleased
  `cost_nanodollars` (billionths) likewise, the settings untouched, the spend indexes
  follow the rename, a re-run converts nothing twice, a rollback turns the costs back into
  millionths, and the same statements work in a named schema.
  """
  use PhoenixKit.DataCase, async: false

  alias PhoenixKit.Migrations.Postgres.V223
  alias PhoenixKit.Test.Repo

  @scratch "pk_v223_scratch"

  defp run(statements), do: Enum.each(statements, &Repo.query!/1)
  defp query(sql, params \\ []), do: Repo.query!(sql, params).rows

  defp marker(schema \\ "public") do
    [[marker]] = query("SELECT obj_description('#{schema}.phoenix_kit'::regclass)")
    marker
  end

  # [[column, type]] of the cost column, whichever name it has
  defp cost_column(schema \\ "public") do
    query(
      """
      SELECT column_name, format_type(atttypid, atttypmod)
      FROM information_schema.columns c
      JOIN pg_attribute a ON a.attname = c.column_name
        AND a.attrelid = (quote_ident(c.table_schema) || '.' || quote_ident(c.table_name))::regclass
      WHERE c.table_schema = $1 AND c.table_name = 'phoenix_kit_ai_requests'
        AND c.column_name IN ('cost', 'cost_cents', 'cost_nanodollars')
      """,
      [schema]
    )
  end

  defp spend_index_definitions(schema \\ "public") do
    query(
      """
      SELECT indexdef FROM pg_indexes
      WHERE schemaname = $1 AND indexname LIKE 'phoenix_kit_ai_requests_%_spend_idx'
      ORDER BY indexname
      """,
      [schema]
    )
    |> List.flatten()
  end

  defp insert_request(model, cost, column, schema \\ "public") do
    query(
      "INSERT INTO #{schema}.phoenix_kit_ai_requests (model, #{column}, inserted_at, updated_at) " <>
        "VALUES ($1, $2, now(), now())",
      [model, if(is_binary(cost), do: Decimal.new(cost), else: cost)]
    )
  end

  defp costs(column, schema \\ "public") do
    query("SELECT model, #{column} FROM #{schema}.phoenix_kit_ai_requests")
    |> Map.new(fn [model, cost] -> {model, cost} end)
  end

  defp put_setting(key, value, schema \\ "public") do
    query(
      "INSERT INTO #{schema}.phoenix_kit_settings (key, value, module) VALUES ($1, $2, 'ai') " <>
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
      [key, value]
    )
  end

  defp setting(key, schema \\ "public") do
    [[value]] = query("SELECT value FROM #{schema}.phoenix_kit_settings WHERE key = $1", [key])
    value
  end

  defp seed_caps(schema \\ "public") do
    put_setting("ai_daily_budget", "5000000", schema)
    put_setting("ai_daily_budget_per_endpoint", " 250000 ", schema)
    put_setting("ai_daily_budget_per_user", "0", schema)
    put_setting("ai_daily_calls_per_user", "200", schema)
  end

  defp dollars(map), do: Map.new(map, fn {k, v} -> {k, v && Decimal.new(v)} end)

  defp assert_costs(column, expected, schema \\ "public") do
    actual = costs(column, schema)
    assert Map.keys(actual) == Map.keys(expected)

    for {model, want} <- dollars(expected) do
      got = actual[model]

      assert (is_nil(want) and is_nil(got)) or Decimal.equal?(got, want),
             "#{model}: expected #{inspect(want)}, got #{inspect(got)}"
    end
  end

  defp to_nanodollars do
    run([
      "ALTER TABLE public.phoenix_kit_ai_requests ALTER COLUMN cost TYPE bigint " <>
        "USING round(cost * 1000000000)::bigint",
      "ALTER TABLE public.phoenix_kit_ai_requests RENAME COLUMN cost TO cost_nanodollars"
    ])
  end

  test "the chain is at 223 or later, with a numeric(28,18) cost in both spend indexes" do
    assert String.to_integer(marker()) >= 223
    assert [["cost", "numeric(28,18)"]] = cost_column()

    assert [endpoint_idx, user_idx] = spend_index_definitions()
    assert endpoint_idx =~ "(endpoint_uuid, inserted_at) INCLUDE (cost)"
    assert user_idx =~ "(user_uuid, inserted_at) INCLUDE (cost)"
  end

  test "millionths become dollars; the settings are left as they are" do
    run(V223.down_statements("public"))
    assert [["cost_cents", "integer"]] = cost_column()

    insert_request("embedding", 20, "cost_cents")
    insert_request("free", 0, "cost_cents")
    insert_request("unpriced", nil, "cost_cents")
    insert_request("expensive", 2_000_000_000, "cost_cents")
    seed_caps()

    run(V223.up_statements("public"))

    assert [["cost", "numeric(28,18)"]] = cost_column()
    assert marker() == "223"

    assert_costs("cost", %{
      "embedding" => "0.00002",
      "free" => "0",
      "unpriced" => nil,
      "expensive" => "2000"
    })

    assert setting("ai_daily_budget") == "5000000"
    assert setting("ai_daily_budget_per_endpoint") == " 250000 "
    assert setting("ai_daily_budget_per_user") == "0"
    assert setting("ai_daily_calls_per_user") == "200"
  end

  test "a database on the unreleased nanodollar V223 is converted too" do
    insert_request("embedding", "0.00000004", "cost")
    insert_request("chat", "1.5", "cost")
    to_nanodollars()
    assert [["cost_nanodollars", "bigint"]] = cost_column()
    assert costs("cost_nanodollars") == %{"embedding" => 40, "chat" => 1_500_000_000}

    run(V223.up_statements("public"))

    assert [["cost", "numeric(28,18)"]] = cost_column()
    assert_costs("cost", %{"embedding" => "0.00000004", "chat" => "1.5"})
    assert [endpoint_idx, _] = spend_index_definitions()
    assert endpoint_idx =~ "INCLUDE (cost)"
  end

  test "a cost from an earlier unreleased V223 (numeric(20,10)) is widened, nothing lost" do
    insert_request("chat", "1.2345678901", "cost")
    run(["ALTER TABLE public.phoenix_kit_ai_requests ALTER COLUMN cost TYPE numeric(20,10)"])
    assert [["cost", "numeric(20,10)"]] = cost_column()

    run(V223.up_statements("public"))

    assert [["cost", "numeric(28,18)"]] = cost_column()
    assert_costs("cost", %{"chat" => "1.2345678901"})

    # an attodollar fits now
    insert_request("token", "0.000000000000000001", "cost")
    assert_costs("cost", %{"chat" => "1.2345678901", "token" => "0.000000000000000001"})
  end

  test "a table with cost and a legacy column stops the migration, up and down" do
    run(["ALTER TABLE public.phoenix_kit_ai_requests ADD COLUMN cost_cents integer"])

    assert_raise Postgrex.Error, ~r/has cost and a legacy cost column/, fn ->
      Repo.transaction(fn -> run(V223.up_statements("public")) end)
    end

    assert_raise Postgrex.Error, ~r/has both cost and cost_cents/, fn ->
      Repo.transaction(fn -> run(V223.down_statements("public")) end)
    end
  end

  test "a table with both legacy columns stops the migration" do
    run(V223.down_statements("public"))
    run(["ALTER TABLE public.phoenix_kit_ai_requests ADD COLUMN cost_nanodollars bigint"])

    assert_raise Postgrex.Error, ~r/has both cost_cents and cost_nanodollars/, fn ->
      Repo.transaction(fn -> run(V223.up_statements("public")) end)
    end
  end

  test "running it again converts nothing twice" do
    insert_request("embedding", "0.00002", "cost")

    run(V223.up_statements("public"))
    run(V223.up_statements("public"))

    assert_costs("cost", %{"embedding" => "0.00002"})
  end

  # Both blocks empty search_path to make the re-added keys' definitions
  # schema-qualified; inside a caller's transaction (this test's sandbox) that
  # local setting would otherwise outlive the block.
  test "leaves the caller's search_path as it found it, up and down" do
    query("SET LOCAL search_path TO pg_catalog, public")
    [[before]] = query("SELECT current_setting('search_path')")

    run(V223.down_statements("public"))
    assert [[^before]] = query("SELECT current_setting('search_path')")

    run(V223.up_statements("public"))
    assert [[^before]] = query("SELECT current_setting('search_path')")
  end

  test "rolls back to integer cost_cents in millionths, and forward again" do
    insert_request("embedding", "0.0000204", "cost")
    insert_request("tiny", "0.00000016", "cost")
    put_setting("ai_daily_budget", "5000000")

    run(V223.down_statements("public"))

    assert [["cost_cents", "integer"]] = cost_column()
    assert marker() == "222"
    assert costs("cost_cents") == %{"embedding" => 20, "tiny" => 0}
    assert setting("ai_daily_budget") == "5000000"
    assert [endpoint_idx, _] = spend_index_definitions()
    assert endpoint_idx =~ "INCLUDE (cost_cents)"

    run(V223.down_statements("public"))
    assert costs("cost_cents") == %{"embedding" => 20, "tiny" => 0}

    run(V223.up_statements("public"))
    assert [["cost", "numeric(28,18)"]] = cost_column()
    assert_costs("cost", %{"embedding" => "0.00002", "tiny" => "0"})
  end

  test "a cost an integer of millionths cannot hold stops the rollback" do
    insert_request("huge", "2147.484", "cost")

    assert_raise Postgrex.Error, ~r/integer out of range/, fn ->
      Repo.transaction(fn -> run(V223.down_statements("public")) end)
    end
  end

  test "works in a named schema and leaves public alone" do
    run(V223.down_statements("public"))
    insert_request("public_row", 20, "cost_cents")
    put_setting("ai_daily_budget", "5000000")

    run([
      "CREATE SCHEMA #{@scratch}",
      "CREATE TABLE #{@scratch}.phoenix_kit (id integer)",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_requests " <>
        "(LIKE public.phoenix_kit_ai_requests INCLUDING DEFAULTS INCLUDING INDEXES)",
      "CREATE TABLE #{@scratch}.phoenix_kit_settings " <>
        "(LIKE public.phoenix_kit_settings INCLUDING DEFAULTS INCLUDING INDEXES)",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_endpoints " <>
        "(LIKE public.phoenix_kit_ai_endpoints INCLUDING DEFAULTS INCLUDING INDEXES)",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_prompts " <>
        "(LIKE public.phoenix_kit_ai_prompts INCLUDING DEFAULTS INCLUDING INDEXES)",
      # a named-schema install has its own uuid_generate_v7 (the accounts' default)
      "CREATE FUNCTION #{@scratch}.uuid_generate_v7() RETURNS uuid " <>
        "LANGUAGE sql AS 'SELECT public.uuid_generate_v7()'"
    ])

    insert_request("scratch_row", 7, "cost_cents", @scratch)
    seed_caps(@scratch)

    run(V223.up_statements(@scratch))

    assert [["cost", "numeric(28,18)"]] = cost_column(@scratch)
    assert_costs("cost", %{"scratch_row" => "0.000007"}, @scratch)
    assert setting("ai_daily_budget", @scratch) == "5000000"
    assert marker(@scratch) == "223"

    assert [["cost_cents", "integer"]] = cost_column()
    assert costs("cost_cents") == %{"public_row" => 20}

    run(V223.down_statements(@scratch))
    assert [["cost_cents", "integer"]] = cost_column(@scratch)
    assert costs("cost_cents", @scratch) == %{"scratch_row" => 7}
    assert marker(@scratch) == "222"
  end

  # ---- the leftovers: model width, accounts, duplicate uuid indexes ----

  defp column_type(table, column, schema \\ "public") do
    query(
      """
      SELECT format_type(atttypid, atttypmod) FROM pg_attribute
      WHERE attrelid = to_regclass($1) AND attname = $2 AND NOT attisdropped
      """,
      ["#{schema}.#{table}", column]
    )
  end

  defp table?(table, schema \\ "public"),
    do: query("SELECT to_regclass($1) IS NOT NULL", ["#{schema}.#{table}"]) == [[true]]

  # names of the unique, non-primary indexes on `uuid` of a table
  defp uuid_duplicates(table, schema \\ "public") do
    query(
      """
      SELECT ic.relname FROM pg_index i
      JOIN pg_class ic ON ic.oid = i.indexrelid
      JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0]
      WHERE i.indrelid = to_regclass($1) AND i.indisunique AND NOT i.indisprimary
        AND i.indnatts = 1 AND a.attname = 'uuid'
      ORDER BY 1
      """,
      ["#{schema}.#{table}"]
    )
    |> List.flatten()
  end

  # the index a foreign key is bound to
  defp fk_index(table, name, schema \\ "public") do
    [[index]] =
      query(
        "SELECT conindid::regclass::text FROM pg_constraint WHERE conrelid = to_regclass($1) AND conname = $2",
        ["#{schema}.#{table}", name]
      )

    index
  end

  test "the chain head has no accounts, no account_uuid, no duplicate uuid indexes, a wide model" do
    refute table?("phoenix_kit_ai_accounts")
    assert column_type("phoenix_kit_ai_requests", "account_uuid") == []
    assert column_type("phoenix_kit_ai_requests", "model") == [["character varying(150)"]]

    for table <- ~w(phoenix_kit_ai_endpoints phoenix_kit_ai_prompts phoenix_kit_ai_requests) do
      assert uuid_duplicates(table) == [], table
    end

    assert fk_index("phoenix_kit_ai_requests", "fk_ai_requests_endpoint_uuid") =~
             "phoenix_kit_ai_endpoints_pkey"
  end

  test "down restores the V222 shape; up drops it again and re-binds the keys to the pkeys" do
    run(V223.down_statements("public"))

    assert table?("phoenix_kit_ai_accounts")
    assert column_type("phoenix_kit_ai_requests", "account_uuid") == [["uuid"]]
    assert column_type("phoenix_kit_ai_requests", "model") == [["character varying(100)"]]

    assert uuid_duplicates("phoenix_kit_ai_prompts") ==
             ["phoenix_kit_ai_prompts_uuid_idx", "phoenix_kit_ai_prompts_uuid_index"]

    # A key bound to a duplicate, as the old chain left them (re-created while the
    # duplicate is the only unique index on endpoints.uuid).
    run([
      "ALTER TABLE public.phoenix_kit_ai_requests DROP CONSTRAINT fk_ai_requests_endpoint_uuid",
      "ALTER TABLE public.phoenix_kit_ai_requests DROP CONSTRAINT IF EXISTS phoenix_kit_ai_requests_endpoint_uuid_fkey",
      "ALTER TABLE public.phoenix_kit_ai_endpoints DROP CONSTRAINT phoenix_kit_ai_endpoints_pkey CASCADE",
      "ALTER TABLE public.phoenix_kit_ai_requests ADD CONSTRAINT fk_ai_requests_endpoint_uuid " <>
        "FOREIGN KEY (endpoint_uuid) REFERENCES public.phoenix_kit_ai_endpoints(uuid) ON DELETE SET NULL",
      "ALTER TABLE public.phoenix_kit_ai_endpoints ADD CONSTRAINT phoenix_kit_ai_endpoints_pkey PRIMARY KEY (uuid)"
    ])

    assert fk_index("phoenix_kit_ai_requests", "fk_ai_requests_endpoint_uuid") ==
             "phoenix_kit_ai_endpoints_uuid_idx"

    query(
      "INSERT INTO public.phoenix_kit_ai_accounts (name, api_key, inserted_at, updated_at) " <>
        "VALUES ('old', 'sk-old-plaintext', now(), now())"
    )

    run(V223.up_statements("public"))

    refute table?("phoenix_kit_ai_accounts")
    assert column_type("phoenix_kit_ai_requests", "account_uuid") == []
    assert column_type("phoenix_kit_ai_requests", "model") == [["character varying(150)"]]

    for table <- ~w(phoenix_kit_ai_endpoints phoenix_kit_ai_prompts phoenix_kit_ai_requests) do
      assert uuid_duplicates(table) == [], table
    end

    # the key is back under its own name and definition, bound to the pkey
    assert fk_index("phoenix_kit_ai_requests", "fk_ai_requests_endpoint_uuid") ==
             "phoenix_kit_ai_endpoints_pkey"

    assert [[def]] =
             query(
               "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'fk_ai_requests_endpoint_uuid'"
             )

    assert def =~ "REFERENCES phoenix_kit_ai_endpoints(uuid) ON DELETE SET NULL"

    # and still enforced
    assert_raise Postgrex.Error, ~r/foreign key/, fn ->
      Repo.transaction(fn ->
        query(
          "INSERT INTO public.phoenix_kit_ai_requests (model, endpoint_uuid, inserted_at, updated_at) " <>
            "VALUES ('m', $1, now(), now())",
          [Ecto.UUID.bingenerate()]
        )
      end)
    end

    # a re-run has nothing left to do
    run(V223.up_statements("public"))

    assert fk_index("phoenix_kit_ai_requests", "fk_ai_requests_endpoint_uuid") ==
             "phoenix_kit_ai_endpoints_pkey"
  end

  test "a model longer than V222's 100 characters stops the rollback" do
    query(
      "INSERT INTO public.phoenix_kit_ai_requests (model, inserted_at, updated_at) VALUES ($1, now(), now())",
      [String.duplicate("m", 120)]
    )

    assert_raise Postgrex.Error, ~r/model longer than 100 characters/, fn ->
      Repo.transaction(fn -> run(V223.down_statements("public")) end)
    end
  end

  test "in a named schema the <prefix>_ duplicate indexes are found and dropped" do
    run([
      "CREATE SCHEMA #{@scratch}",
      "CREATE TABLE #{@scratch}.phoenix_kit (id integer)",
      "CREATE FUNCTION #{@scratch}.uuid_generate_v7() RETURNS uuid " <>
        "LANGUAGE sql AS 'SELECT public.uuid_generate_v7()'",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_endpoints (uuid uuid PRIMARY KEY)",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_prompts (uuid uuid PRIMARY KEY)",
      "CREATE TABLE #{@scratch}.phoenix_kit_ai_requests " <>
        "(uuid uuid PRIMARY KEY, model varchar(100), cost numeric(28,18), endpoint_uuid uuid)",
      # V135's names outside public
      "CREATE UNIQUE INDEX #{@scratch}_phoenix_kit_ai_endpoints_uuid_idx " <>
        "ON #{@scratch}.phoenix_kit_ai_endpoints (uuid)",
      "CREATE UNIQUE INDEX #{@scratch}_phoenix_kit_ai_prompts_uuid_idx " <>
        "ON #{@scratch}.phoenix_kit_ai_prompts (uuid)"
    ])

    run(V223.up_statements(@scratch))

    assert uuid_duplicates("phoenix_kit_ai_endpoints", @scratch) == []
    assert uuid_duplicates("phoenix_kit_ai_prompts", @scratch) == []

    assert column_type("phoenix_kit_ai_requests", "model", @scratch) ==
             [["character varying(150)"]]

    # public is untouched by a named-schema run
    assert uuid_duplicates("phoenix_kit_ai_endpoints") == []

    run(V223.down_statements(@scratch))

    assert uuid_duplicates("phoenix_kit_ai_endpoints", @scratch) ==
             ["#{@scratch}_phoenix_kit_ai_endpoints_uuid_idx"]

    assert table?("phoenix_kit_ai_accounts", @scratch)
  end
end
