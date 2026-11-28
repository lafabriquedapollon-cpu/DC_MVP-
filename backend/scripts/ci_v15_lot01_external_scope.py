import importlib.util, sys, os, json
from dataclasses import replace
from pathlib import Path
assert os.environ.get("GITHUB_ACTIONS")=="true"
spec=importlib.util.spec_from_file_location("external_scope",Path(__file__).resolve().parents[1]/"services"/"pocket_external_scope.py")
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
lab=m.ExternalScope("laboratory","lab-person-a","org-a")
tech=m.ExternalScope("technical","tech-person-a","org-t")
a=m.ResourceAssignment("laboratory","lab-person-a","org-a",1,10,True)
t=m.ResourceAssignment("technical","tech-person-a","org-t",1,20,True)
rows=[]
def case(label, scope, grant, action, cab, res, expected):
    got=m.matches_read_scope(scope,grant,action=action,cabinet_id=cab,resource_id=res)
    rows.append(dict(label=label,passed=got is expected))
    print(json.dumps(rows[-1]),flush=True)
case("lab exact order scope",lab,a,"assigned-order.read",1,10,True)
case("tech exact diagnostic scope",tech,t,"diagnostic.read",1,20,True)
for name,grant in [("revoked",replace(a,active=False)),("other principal",replace(a,principal_id="other")),("other organization",replace(a,organization_id="other")),("other cabinet",replace(a,cabinet_id=2)),("other order",replace(a,resource_id=11)),("wrong kind",replace(a,kind="technical")),("missing organization",replace(a,organization_id="")),("nonboolean active",replace(a,active=1))]:
    case(name,lab,grant,"assigned-order.read",1,10,False)
for action in ["cabinet.patients.read","cabinet.clinical.read","cabinet.finance.read","assigned-order.write","global-orders.read","diagnostic.read",""]:
    case("lab denies "+action,lab,a,action,1,10,False)
for action in ["cabinet.patients.read","cabinet.clinical.read","cabinet.finance.read","diagnostic.write","assigned-order.read"]:
    case("tech denies "+action,tech,t,action,1,20,False)
case("staff cannot impersonate lab",replace(lab,kind="staff"),a,"assigned-order.read",1,10,False)
case("patient cannot impersonate lab",replace(lab,kind="patient"),a,"assigned-order.read",1,10,False)
case("missing principal",None,a,"assigned-order.read",1,10,False)
case("missing assignment",lab,None,"assigned-order.read",1,10,False)
case("boolean resource",lab,a,"assigned-order.read",1,True,False)
Path(os.environ["DC_EVIDENCE"],"external-scope.json").write_text(json.dumps(rows,indent=2))
assert len(rows)==27 and all(r["passed"] for r in rows)
