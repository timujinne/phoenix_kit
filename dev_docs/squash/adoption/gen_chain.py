#!/usr/bin/env python3
"""Write a module adoption chain (V1) and its two tests from a JSON config and adoption_ddl.exs output.

Usage (from core's dev_docs/squash/adoption/): python3 gen_chain.py CONFIG.json
See README.md here; example_sync.json is the config sync's chain was made from."""
import json, re, sys, os
cfg = json.load(open(sys.argv[1]))
ddl = open(cfg["ddl"]).read()
parts = re.split(r'^# ---- .*$', ddl, flags=re.M)
def body(x):
    x = x.strip(); assert x.startswith('[') and x.endswith(']'); return x[1:-1].strip('\n')
def indent(block, n):
    return "\n".join((" " * n + l) if l.strip() else l for l in block.split("\n"))
tables_src, cons_src, idx_src = (indent(body(parts[i]), 4) for i in (1, 2, 3))
tables = re.findall(r'CREATE TABLE IF NOT EXISTS #\{p\}(\w+) \(', ddl)
cons = re.findall(r'ADD CONSTRAINT (\w+) ', ddl)
fks = re.findall(r'ADD CONSTRAINT (\w+) FOREIGN KEY .*? ON DELETE (CASCADE|SET NULL|RESTRICT|NO ACTION|SET DEFAULT)', ddl)
fks_noaction = [n for n in re.findall(r'ADD CONSTRAINT (\w+) FOREIGN KEY', ddl) if n not in dict(fks)]
idxs = re.findall(r'INDEX IF NOT EXISTS (?:#\{np\})?(\w+) ON', ddl)
M, app, marker, vt = cfg["module"], cfg["app_module"], cfg["marker"], cfg["version_table"]
n_pk = sum(1 for c in re.findall(r'ADD CONSTRAINT \w+ (PRIMARY KEY|UNIQUE|FOREIGN KEY|CHECK|EXCLUDE)', ddl) if c == "PRIMARY KEY")
kinds = re.findall(r'ADD CONSTRAINT \w+ (PRIMARY KEY|UNIQUE|FOREIGN KEY|CHECK|EXCLUDE)', ddl)
from collections import Counter
kc = Counter(kinds)
cons_summary = ", ".join(f"{v} {k.lower()}{'s' if v != 1 else ''}".replace("primary keys","primary keys").replace("foreign keys","foreign keys") for k, v in [("PRIMARY KEY", kc["PRIMARY KEY"]), ("UNIQUE", kc["UNIQUE"]), ("FOREIGN KEY", kc["FOREIGN KEY"]), ("CHECK", kc["CHECK"])] if v)
table_list = ", ".join(f"`{t}`" for t in tables[:-1]) + (" and " if len(tables) > 1 else "") + f"`{tables[-1]}`"
coord = open(os.path.join(os.path.dirname(sys.argv[0]), "template_coord.ex")).read()
repl = {
 "@@MODULE@@": M, "@@PKG@@": cfg["package"], "@@N_TABLES@@": cfg["n_words"], "@@TABLE_LIST@@": table_list,
 "@@HISTORY@@": cfg["history"], "@@MARKER@@": marker, "@@VERSION_TABLE@@": vt, "@@ROWS@@": cfg["rows"],
 "@@TABLES_COMMENT@@": cfg["tables_comment"], "@@CONS_COMMENT@@": cfg["constraints_comment"],
 "@@TABLES@@": tables_src, "@@CONSTRAINTS@@": cons_src, "@@INDEXES@@": idx_src, "@@ORDER@@": cfg["order_doc"], "@@TESTPATH@@": cfg["test_path"], "@@ALONEPATH@@": cfg["alone_path"],
}
for k, v in repl.items(): coord = coord.replace(k, v)
assert "@@" not in coord, re.findall(r'@@\w+@@', coord)
assert "#{np}" not in cons_src, "constraint names with the schema-name convention: handle by hand"
if "#{np}" in idx_src:
    coord = coord.replace("[tables(p), constraints(prefix, p), indexes(p)]", "[tables(p), constraints(prefix, p), indexes(prefix, p)]")
    coord = coord.replace("""  defp indexes(p) do
    [""", """  defp indexes(prefix, p) do
    np = name_prefix(prefix)

    [""")
    coord = coord.replace("""  defp marker_query do""", """  # Core's V56 convention puts the schema name in front of a few index names
  # on a named-schema install, and none on `public`; the chain names them the
  # same way, so it adopts core's index instead of building a second one.
  defp name_prefix("public"), do: ""
  defp name_prefix(prefix), do: "#{prefix}_"

  defp marker_query do""")
    assert "indexes(prefix, p)" in coord and "np = name_prefix(prefix)" in coord
open(cfg["out_coord"], "w").write(coord)
tst = open(os.path.join(os.path.dirname(sys.argv[0]), "template_test.exs")).read()
w = lambda xs, n: "\n".join(" " * n + x for x in xs)
repl2 = {
 "@@MODULE@@": M, "@@APP_MODULE@@": app, "@@MARKER@@": marker, "@@VERSION_TABLE@@": vt,
 "@@TABLES@@": w(tables, 4), "@@INDEXES@@": w(idxs, 4), "@@CONSTRAINTS@@": w(cons, 4),
 "@@CONS_SUMMARY@@": cons_summary, "@@FK_PAIRS@@": ",\n".join(f'          {{"{n}", "{a}"}}' for n, a in fks),
 "@@FK_TARGETS@@": "\n".join(f'    assert joined =~ "REFERENCES tenant_a.{t}(uuid)"' for t in sorted(set(re.findall(r'REFERENCES #\{p\}(\w+)\(', ddl)))),
 "@@TABLE_NOUN@@": cfg["table_noun"],
}
for k, v in repl2.items(): tst = tst.replace(k, v)
np_names = re.findall(r'INDEX IF NOT EXISTS #\{np\}(\w+) ON #\{p\}(\w+)', ddl)
if np_names:
    lines = "\n".join(
        f'    assert Enum.any?(Migrations.up_statements("public"), &(&1 =~ "INDEX IF NOT EXISTS {n} ON public.{t} "))\n'
        f'    assert Enum.any?(Migrations.up_statements("tenant_a"), &(&1 =~ "INDEX IF NOT EXISTS tenant_a_{n} ON tenant_a.{t} "))'
        for n, t in np_names)
    block = ('  # Core\'s V56 convention: on a named-schema install a few index names start\n'
             '  # with the schema name (none on `public`). The chain must name them alike,\n'
             '  # or it builds a second index beside core\'s instead of adopting it.\n'
             '  test "index names follow core\'s schema-name convention" do\n' + lines + '\n  end\n\n')
    anchor = '  test "down only rewrites the marker" do'
    assert tst.count(anchor) == 1
    tst = tst.replace(anchor, block + anchor)
assert "@@" not in tst, re.findall(r'@@\w+@@', tst)
open(cfg["out_test"], "w").write(tst)
alone = open(os.path.join(os.path.dirname(sys.argv[0]), "template_alone.exs")).read()
for k, v in {"@@APP_MODULE@@": app, "@@MODULE@@": M, "@@REPO@@": cfg["repo"], "@@N_TABLES@@": cfg["n_words"], "@@TABLE_NOUN@@": cfg["table_noun"]}.items():
    alone = alone.replace(k, v)
open(cfg["out_alone"], "w").write(alone)
print(f"{M}: {len(tables)} tables, {len(cons)} constraints ({cons_summary}), {len(idxs)} indexes, fks without ON DELETE: {fks_noaction}")
