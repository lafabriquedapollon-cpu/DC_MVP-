"""Static inventory of candidate runtime deletion and raw SQL surfaces (not an exhaustive call graph)."""
import ast
from pathlib import Path
import json

def main():
    records=set()
    files=sorted(Path("backend").rglob("*.py"))
    for p in files:
        if any(x in {"tests","__pycache__"} for x in p.parts):
            continue
        tree=ast.parse(p.read_text(encoding="utf-8-sig"),filename=str(p))
        for n in ast.walk(tree):
            kind=None
            if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute):
                attr=n.func.attr
                if attr in {"delete","unlink","rmtree","raw_connection","set_authorizer","exec_driver_sql","driver_connection"}:
                    kind=attr
                elif attr=="connect" and isinstance(n.func.value,ast.Name) and n.func.value.id in {"sqlite3","sqlcipher","driver","pysqlcipher"}:
                    kind="direct_dbapi_connect"
            elif isinstance(n,ast.Attribute) and n.attr in {"driver_connection","dbapi_connection"}:
                kind=n.attr
            elif isinstance(n,ast.Constant) and isinstance(n.value,str):
                v=n.value.lower()
                if "pragma" in v and ("foreign_keys" in v or "defer_foreign_keys" in v):
                    kind="fk_pragma_literal"
                elif "delete from " in v:
                    kind="sql_delete_literal"
            if kind: records.add((str(p),n.lineno,kind))
    for path,line,kind in sorted(records):
        print("F04_INVENTORY "+json.dumps({"path":path,"line":line,"kind":kind},sort_keys=True))
    print(f"F04_INVENTORY_PASS files_scanned={len(files)} sites={len(records)}")

if __name__=="__main__":
    main()
