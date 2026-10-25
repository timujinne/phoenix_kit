# adoption_ddl.exs — prints the adoption DDL for tables core's chain creates.
#
# For a module adopting tables core creates for it (the extraction guide's
# Phase 0; dev_docs/plans/2026-10-25-module-table-ownership.md, steps 3–5):
# builds a FRESH core install into a scratch schema and prints, for the given
# tables, the `CREATE TABLE IF NOT EXISTS` statements (columns in order, types,
# defaults, NOT NULL), every constraint as a `guarded_constraint/4` call
# (primary keys and unique first, then foreign keys, then CHECKs), every index
# not backing a constraint as `CREATE INDEX IF NOT EXISTS`, with `#{p}` where
# the schema goes, plus any triggers and seed rows to handle by hand. The
# output is a starting point for a module's `up_statements/2` in the shape of
# `phoenix_kit_locations`' and `phoenix_kit_comments`' chains;
# `PhoenixKit.TestSupport.ModuleChainCheck` then proves the result.
#
#   MIX_ENV=test mix run --no-start dev_docs/squash/adoption_ddl.exs OUT.ex table1 table2 ...
#
# Uses the suite's database (PGDATABASE etc. as for `mix test`); the scratch
# schema is dropped afterwards.
[out | tables] = System.argv()
{:ok, _} = Application.ensure_all_started(:ecto_sql)
{:ok, _} = PhoenixKit.Test.Repo.start_link(pool_size: 2, log: false)
alias PhoenixKit.Test.Repo
s = "pk_adopt_gen"
q = fn sql, params -> Repo.query!(sql, params, log: false).rows end
Repo.query!("DROP SCHEMA IF EXISTS #{s} CASCADE"); Repo.query!("CREATE SCHEMA #{s}")
{:ok, dev} = StringIO.open(""); gl = Process.group_leader(); Process.group_leader(self(), dev)
:ok = PhoenixKit.Migration.ensure_current(Repo, prefix: s, log: false)
Process.group_leader(self(), gl)
# A schema-qualified reference becomes `#{p}`. Core's V56 convention also puts
# the schema name in front of a few index names on a named-schema install (none
# on `public`): such a name becomes `#{np}`, which the chain sets to "" for
# `public` and "<prefix>_" otherwise.
un = fn text ->
  text
  |> String.replace(~s("#{s}".), "\#{p}")
  |> String.replace("#{s}.", "\#{p}")
  |> String.replace("#{s}_", "\#{np}")
end
ind = fn text, n -> text |> String.split("\n") |> Enum.map_join("\n", &(String.duplicate(" ", n) <> &1)) end
missing = tables -- (q.("SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND relkind='r'", [s]) |> List.flatten())
missing == [] || raise "not on a fresh core build: #{inspect(missing)}"

create = for t <- tables do
  cols = q.("""
    SELECT a.attname, format_type(a.atttypid, a.atttypmod), pg_get_expr(d.adbin, d.adrelid), a.attnotnull
    FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
    LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
    WHERE n.nspname=$1 AND c.relname=$2 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum
  """, [s, t])
  body = Enum.map_join(cols, ",\n", fn [name, type, default, nn] ->
    ~s(  "#{name}" #{type}) <> if(default, do: " DEFAULT #{un.(default)}", else: "") <> if(nn, do: " NOT NULL", else: "")
  end)
  "\"\"\"\nCREATE TABLE IF NOT EXISTS \#{p}#{t} (\n#{body}\n)\n\"\"\""
end

cons = q.("""
  SELECT c.relname, con.conname, con.contype, pg_get_constraintdef(con.oid)
  FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname=$1 AND c.relname = ANY($2) AND con.contype IN ('p','u','f','c','x')
  ORDER BY array_position(ARRAY['p','u','x','f','c']::"char"[], con.contype), array_position($2::text[], c.relname::text), con.conname
""", [s, tables])
guards = for [t, name, _type, def] <- cons do
  "guarded_constraint(\n  prefix,\n  \"#{t}\",\n  \"#{name}\",\n  \"ALTER TABLE \#{p}#{t} ADD CONSTRAINT #{name} #{un.(def) |> String.replace("\"", "\\\"")}\"\n)"
end

idx = q.("""
  SELECT i.relname, pg_get_indexdef(i.oid)
  FROM pg_index x JOIN pg_class i ON i.oid=x.indexrelid JOIN pg_class c ON c.oid=x.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname=$1 AND c.relname = ANY($2)
    AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = i.oid AND k.contype IN ('p','u','x'))
  ORDER BY array_position($2::text[], c.relname::text), i.relname
""", [s, tables])
indexes = for [_name, def] <- idx do
  def = def |> String.replace(~r/^CREATE (UNIQUE )?INDEX /, "CREATE \\1INDEX IF NOT EXISTS ") |> un.()
  ~s("#{String.replace(def, "\"", "\\\"")}")
end

trg = q.("SELECT c.relname, t.tgname, pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname = ANY($2) AND NOT t.tgisinternal", [s, tables])
seeds = for t <- tables, [[n]] = q.("SELECT count(*) FROM #{s}.#{t}", []), n > 0, do: "#{t}: #{n} rows"

File.write!(out, """
# ---- tables(p) ----
[
#{Enum.map_join(create, ",\n", &ind.(&1, 2))}
]
# ---- constraints (PK, UNIQUE, EXCLUDE, then FK, then CHECK) ----
[
#{Enum.map_join(guards, ",\n", &ind.(&1, 2))}
]
# ---- indexes (constraint-backed ones excluded) ----
[
#{Enum.map_join(indexes, ",\n", &ind.(&1, 2))}
]
# ---- names using `\#{np}` (core's V56 schema-name convention): #{if String.contains?(Enum.join(indexes ++ guards), "\#{np}"), do: "yes — define np = if prefix == \"public\", do: \"\", else: \"\#{prefix}_\"", else: "none"}
# ---- triggers: #{inspect(trg)}
# ---- seed rows on a fresh build: #{inspect(seeds)}
""")
Repo.query!("DROP SCHEMA #{s} CASCADE")
IO.puts("wrote #{out}: #{length(create)} tables, #{length(guards)} constraints, #{length(indexes)} indexes, #{length(trg)} triggers, seeds=#{inspect(seeds)}")
