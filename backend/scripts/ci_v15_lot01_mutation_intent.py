"""Offline contract checks; no authority or runtime claim."""
import importlib.util
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
assert os.environ.get("GITHUB_ACTIONS") == "true"
source=Path(__file__).resolve().parents[1]/"services"/"platform_mutation_intent.py"
spec=importlib.util.spec_from_file_location("dc_intent",source)
mod=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=mod
spec.loader.exec_module(mod)
intent=mod.PlatformMutationIntent("trial-code.revoke",1,2,3,"00000000-0000-4000-8000-000000000001","a"*64,"b"*32,"c"*64,"d"*64)
digest=intent.digest()
rows=[]
def check(label,fn):
    try:
        assert fn()
        rows.append({"label":label,"pass":True})
    except Exception as e:
        rows.append({"label":label,"pass":False,"error":type(e).__name__})
    print(json.dumps(rows[-1]),flush=True)
def refused(**kwargs):
    try: replace(intent,**kwargs).digest()
    except ValueError: return True
    return False
check("deterministic domain-bound 32-byte digest",lambda:len(digest)==32 and intent.digest()==digest)
for field,value in [("target_id",2),("actor_id",3),("tenant_id",4),("device_id","00000000-0000-4000-8000-000000000002"),("credential_binding","e"*64),("approval_jti","e"*32),("uv_jti","f"*64),("nonce","e"*64)]:
    check("digest changes with "+field,lambda f=field,v=value:replace(intent,**{f:v}).digest()!=digest)
for field,value in [("action","license.grant"),("action","trial-code.create"),("action",""),("target_id",0),("target_id",True),("actor_id",-1),("tenant_id",2**63),("device_id","wrong"),("credential_binding","a"*63),("approval_jti","B"*32),("uv_jti","bad"),("nonce","d"*63)]:
    check("reject malformed "+field,lambda f=field,v=value:refused(**{f:v}))
Path(os.environ["DC_EVIDENCE"],"intent.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==21 and all(row["pass"] for row in rows)
