"""End-to-end isolated HTTPS LAB with real Desktop login and two browser engines.
No production routes, credentials or patient records. Evidence is booleans only.
"""
import os,json,ssl,urllib.request,urllib.error
from pathlib import Path
from datetime import timedelta
from playwright.sync_api import sync_playwright
from backend import database,models
from backend.routers.external_lab_rehearsal import assert_lab,ORIGIN,PREFIX
from backend.services.pocket_external_device_candidate import now_utc
assert_lab()
rows=[]
def check(label,result):
    row={"label":label,"pass":bool(result)};rows.append(row);print(json.dumps(row),flush=True);assert row["pass"],label
ctx=ssl.create_default_context(cafile=os.environ["DC_LAB_ROOT"]+"/lab-cert.pem")
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
password=os.environ["DC_SYNTH_PASSWORD"]
def http(path,body=None,headers=None,form=False):
    from urllib.parse import urlencode
    h={"Origin":ORIGIN,**(headers or {})}
    data=None
    if body is not None:
        data=(urlencode(body) if form else json.dumps(body)).encode()
        h["Content-Type"]="application/x-www-form-urlencoded" if form else "application/json"
    req=urllib.request.Request(ORIGIN+path,data=data,headers=h)
    try:
        with opener.open(req,timeout=15) as response:
            return response.status,json.loads(response.read()),response.headers
    except urllib.error.HTTPError as exc:
        return exc.code,None,exc.headers
def login(email):
    code,body,_=http("/api/auth/login",{"username":email,"password":password},form=True)
    assert code==200 and body["access_token"]
    h={"Authorization":"Bearer "+body["access_token"]}
    code,_,headers=http("/api/workstation/state",headers=h)
    assert code==200
    cookie=next(c.split(";")[0] for c in headers.get_all("Set-Cookie",[]) if c.startswith("dc_workstation="))
    return {**h,"Cookie":cookie}
def prepare_payload(lab,pub,fp):
    return dict(lab_id=lab,public_key_hex=pub,verified_fingerprint=fp,password=password,confirm=True)
def intent(msg):return json.loads(bytes.fromhex(msg["message_hex"]))
def expect(page,path,data):
    return page.evaluate("""async ({path,data})=>{const r=await fetch(path,{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});return {status:r.status,body:r.ok?await r.json():null,cache:r.headers.get('cache-control')};}""",dict(path=PREFIX+path,data=data))
def signed(page,key_id,pub,msg,expected):
    return page.evaluate("""async x=>{const k=await import('/api/external-lab-rehearsal/client.mjs');return await k.signBoundDeviceProof(x.id,x.hex,x.pub,x.expected);}""",dict(id=key_id,hex=msg["message_hex"],pub=pub,expected=expected))
def refused_sign(page,key_id,pub,msg,expected):
    return page.evaluate("""async x=>{try{const k=await import('/api/external-lab-rehearsal/client.mjs');await k.signBoundDeviceProof(x.id,x.hex,x.pub,x.expected);return false;}catch{return true;}}""",dict(id=key_id,hex=msg["message_hex"],pub=pub,expected=expected))
try:
    check("verified TLS certificate and real health",http("/health")[0]==200)
    owner=login("ci-owner@example.com")
    with database.SessionLocal() as db:
        with db.begin():
            u=db.query(models.User).filter_by(email="ci-owner@example.com").one()
            ca=u.id
            other=db.query(models.User).filter_by(email="ci-other@example.com").one().id
            fixtures={}
            for name in ("chromium","webkit"):
                p=models.Patient(nom="SYNTH_RUNTIME_"+name,prenom="SYNTH",date_naissance=now_utc(),sexe="M",employer_id=ca)
                db.add(p);db.flush()
                act=models.Acte(patient_id=p.id,praticien_id=ca,type_acte=models.ActeType.PROTHESE,libelle="SYNTH_RUNTIME",montant=999)
                db.add(act);db.flush()
                lab=models.Lab(employer_id=ca,name="SYNTH_RUNTIME_"+name);db.add(lab);db.flush()
                job=models.LabJob(patient_id=p.id,act_id=act.id,lab_id=lab.id,material="SYNTH",type="SYNTH",notes="SYNTH_PRIVATE",deadline=now_utc()+timedelta(days=1),status=models.LabJobStatus.SENT)
                db.add(job);db.flush();fixtures[name]=(lab.id,job.id)
    check("owner route refuses anonymous",http(PREFIX+"/owner/prepare",{})[0]==401)
    check("external route refuses foreign origin",http(PREFIX+"/session/challenge",{"device_id":"missing","cabinet_id":ca},{"Origin":"https://foreign.invalid"})[0]==403)
    with sync_playwright() as pw:
        for name in ("chromium","webkit"):
            browser=getattr(pw,name).launch(headless=True)
            try:
                # Ephemeral self-signed LAB certificate already verified above with Python TLS.
                # Browser flag is scoped to this disposable test context, not product.
                context=browser.new_context(ignore_https_errors=True)
                page=context.new_page()
                response=page.goto(ORIGIN+PREFIX+"/shell")
                check(name+" CSP delivered",response.status==200 and "script-src 'self'" in response.headers["content-security-policy"])
                check(name+" inline script blocked",page.evaluate("""async()=>{const s=document.createElement('script');s.textContent='window.labInjection=true';document.body.append(s);await new Promise(r=>setTimeout(r,50));return window.labInjection!==true;}"""))
                key_id="deviceA"
                pub=page.evaluate("""async()=>{const k=await import('/api/external-lab-rehearsal/client.mjs');return await k.createDeviceKey('deviceA');}""")
                import hashlib
                fp=hashlib.sha256(bytes.fromhex(pub)).hexdigest()
                lab,order=fixtures[name]
                code,row,_=http(PREFIX+"/owner/prepare",prepare_payload(lab,pub,fp),owner)
                check(name+" Desktop owner prepares exact binding",code==200)
                i=intent(row)
                expected=["dc/external-lab-enrollment/v1",row["nonce"],ca,lab,pub,row["principal_id"],row["organization_id"],row["device_id"],i[-1]]
                bad=expected.copy();bad[2]=other
                check(name+" altered approved cabinet refused before signature",refused_sign(page,key_id,pub,row,bad))
                sig=signed(page,key_id,pub,row,expected)
                proof={"nonce":row["nonce"],"signature_hex":sig}
                r=expect(page,"/enrollment/complete",proof)
                check(name+" browser signature accepted by actual server",r["status"]==200 and r["body"]["device_id"]==row["device_id"])
                check(name+" enrollment replay refused",expect(page,"/enrollment/complete",proof)["status"]==403)
                sc={"device_id":row["device_id"],"cabinet_id":ca}
                r=expect(page,"/session/challenge",sc);assert r["status"]==200
                m=r["body"];i=intent(m)
                exp=["dc/external-lab-session/v1",m["nonce"],row["device_id"],row["principal_id"],ca,lab,i[-1]]
                sig=signed(page,key_id,pub,m,exp)
                r=expect(page,"/session/issue",{"nonce":m["nonce"],"signature_hex":sig})
                check(name+" real session minted no-store",r["status"]==200 and r["cache"]=="no-store")
                raw=r["body"]["token"]
                rd={"raw_token":raw,"device_id":row["device_id"],"cabinet_id":ca,"resource_id":order}
                check(name+" read denied before explicit grant",expect(page,"/read/challenge",rd)["status"]==403)
                check(name+" owner grant",http(PREFIX+"/owner/grant",{"principal_id":row["principal_id"],"order_id":order,"password":password,"confirm":True},owner)[0]==200)
                r=expect(page,"/read/challenge",rd);assert r["status"]==200
                m=r["body"];digest=hashlib.sha256(("dc/external-session/v1:"+raw).encode()).hexdigest()
                exp=["dc/external-device-read/v1",digest,row["device_id"],"assigned-order.read",ca,order,m["nonce"]]
                sig=signed(page,key_id,pub,m,exp)
                read={**rd,"nonce":m["nonce"],"signature_hex":sig}
                r=expect(page,"/read/complete",read)
                check(name+" minimized actual order projection",r["status"]==200 and set(r["body"])=={"order_id","status","deadline"} and r["body"]["order_id"]==order)
                check(name+" signed read replay refused",expect(page,"/read/complete",read)["status"]==403)
                check(name+" cross cabinet session denied",expect(page,"/session/challenge",{**sc,"cabinet_id":other})["status"]==403)
                page.reload()
                check(name+" key survives page reload",page.evaluate("""async()=>{const k=await import('/api/external-lab-rehearsal/client.mjs');return await k.getDevicePublicKey('deviceA');}""")==pub)
                r=expect(page,"/session/challenge",sc);assert r["status"]==200
                m=r["body"];i=intent(m)
                exp=["dc/external-lab-session/v1",m["nonce"],row["device_id"],row["principal_id"],ca,lab,i[-1]]
                page.evaluate("""async()=>{const k=await import('/api/external-lab-rehearsal/client.mjs');await k.deleteDeviceKey('deviceA');}""")
                check(name+" lost key fails closed",refused_sign(page,key_id,pub,m,exp))
                check(name+" Desktop revocation commits",http(PREFIX+"/owner/revoke",{"lab_id":lab,"password":password,"confirm":True},owner)[0]==200)
                check(name+" revoked token cannot challenge",expect(page,"/read/challenge",rd)["status"]==403)
                check(name+" revoked device cannot issue session",expect(page,"/session/challenge",sc)["status"]==403)
                context.close()
            finally:browser.close()
    # 2 prior owner prepare successes, use wrong keys to exhaust the same fixed budget.
    for _ in range(3):
        code,_,_=http(PREFIX+"/owner/prepare",prepare_payload(fixtures["chromium"][0],"0"*64,"0"*64),owner)
        assert code==403
    code,_,headers=http(PREFIX+"/owner/prepare",prepare_payload(fixtures["chromium"][0],"0"*64,"0"*64),owner)
    check("owner prepare sixth request rate limited",code==429 and int(headers["Retry-After"])>0)
    assert len(rows)==34
finally:
    Path(os.environ["DC_EVIDENCE"],"external-lab-runtime.json").write_text(json.dumps(rows,indent=2))
