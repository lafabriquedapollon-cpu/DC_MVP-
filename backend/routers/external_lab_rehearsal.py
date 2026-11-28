"""Synthetic CI runtime only. Never imported or mounted by production main.

Mount via explicit isolated launcher, on HTTPS loopback. No clinical records
or generic user privileges returned. No new production migration.
"""
import os
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, Response
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy import select
from backend import database, models
from backend.config import settings
from backend.core.runtime_safety import assert_runtime_startup_allowed, REHEARSAL_MIGRATION_ONLY
from backend.routers.auth import get_current_user
from backend.routers.workstation_mode import _find_workstation
from backend.utils.rate_limit import check_rate_limit
from backend.services.pocket_external_lab_authority_candidate import stage_grant, stage_revoke, AuthorityRefused
from backend.services.pocket_external_lab_enrollment_candidate import stage_prepare, stage_complete, stage_revoke_enrollment
from backend.services.pocket_external_lab_session_candidate import stage_session_challenge, stage_issue_session, SessionRefused
from backend.services.pocket_external_lab_projection_candidate import stage_lab_projection, ProjectionRefused
from backend.services.pocket_external_device_candidate import stage_challenge, message
from backend.services.pocket_external_store_candidate import metadata, digest_token

ORIGIN="https://127.0.0.1:8443"
PREFIX="/api/external-lab-rehearsal"
CSP="default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'"
def assert_lab():
    root=Path(os.environ["DC_LAB_ROOT"]).resolve(strict=True)
    target=root/"fresh-rehearsal.db"
    if (os.environ.get("GITHUB_ACTIONS")!="true" or settings.ENVIRONMENT!="e2e_install_rehearsal"
        or root.parent!=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        or settings.DATABASE_URL!=f"sqlite:///{target}" or not target.is_file() or target.is_symlink()
        or database.engine.dialect.driver!="pysqlcipher"
        or assert_runtime_startup_allowed(settings)!=REHEARSAL_MIGRATION_ONLY):
        raise RuntimeError("isolated LAB required")

def create_router():
    assert_lab()
    router=APIRouter()
    def transport(request,*,post=True):
        if request.url.scheme!="https" or request.headers.get("host")!="127.0.0.1:8443" or request.client is None or request.client.host!="127.0.0.1":
            raise HTTPException(403,"LAB transport refused")
        if post and request.headers.get("origin")!=ORIGIN:
            raise HTTPException(403,"origin refused")
    def output(data,status=200):
        return JSONResponse(data,status_code=status,headers={"Cache-Control":"no-store","Content-Security-Policy":CSP,"Referrer-Policy":"no-referrer"})
    async def body(request,fields):
        transport(request)
        if request.headers.get("content-type","").split(";")[0]!="application/json":
            raise HTTPException(415,"JSON required")
        raw=bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw)>4096:raise HTTPException(413,"request too large")
        import json
        try:
            data=json.loads(raw)
        except (ValueError,UnicodeError):
            raise HTTPException(400,"invalid request")
        if type(data) is not dict or set(data)!=set(fields):
            raise HTTPException(400,"invalid request")
        if any(type(data[k]) is not t for k,t in fields.items()):
            raise HTTPException(400,"invalid request")
        return data
    def invoke(db,fn,**args):
        try:
            value=fn(db,**args)
            db.commit()
            return value
        except (AuthorityRefused,SessionRefused,ProjectionRefused,ValueError):
            db.rollback()
            raise HTTPException(403,"operation refused")
        except (IntegrityError,OperationalError):
            db.rollback()
            raise HTTPException(409,"transaction refused")
    def owner(request,db,user):
        transport(request)
        if user.employer_id is not None or user.role not in (models.UserRole.ADMIN,models.UserRole.DENTISTE):
            raise HTTPException(403,"owner required")
        if _find_workstation(request,db,user.id) is None:
            raise HTTPException(423,"workstation required")
        return dict(actor_id=user.id,cabinet_id=user.id)
    def challenge_payload(row):
        return {"nonce":row["nonce"],"message_hex":row["message"].hex()}
    @router.post("/owner/prepare")
    async def prepare(request:Request,db=Depends(database.get_db),user=Depends(get_current_user)):
        ctx=owner(request,db,user)
        check_rate_limit(request,"external-lab-owner-prepare",max_attempts=5)
        args=await body(request,{"lab_id":int,"public_key_hex":str,"verified_fingerprint":str,"password":str,"confirm":bool})
        row=invoke(db,stage_prepare,**ctx,**args)
        return output({**challenge_payload(row),"device_id":row["device_id"],"principal_id":row["principal_id"],"organization_id":row["organization_id"]})
    @router.post("/owner/grant")
    async def grant(request:Request,db=Depends(database.get_db),user=Depends(get_current_user)):
        ctx=owner(request,db,user)
        check_rate_limit(request,"external-lab-owner-grant",max_attempts=5)
        args=await body(request,{"principal_id":str,"order_id":int,"password":str,"confirm":bool})
        invoke(db,stage_grant,**ctx,**args)
        return output({"ok":True})
    @router.post("/owner/revoke")
    async def revoke(request:Request,db=Depends(database.get_db),user=Depends(get_current_user)):
        ctx=owner(request,db,user)
        check_rate_limit(request,"external-lab-owner-revoke",max_attempts=5)
        args=await body(request,{"lab_id":int,"password":str,"confirm":bool})
        invoke(db,stage_revoke_enrollment,**ctx,**args)
        return output({"ok":True})
    @router.post("/enrollment/complete")
    async def complete(request:Request,db=Depends(database.get_db)):
        transport(request);check_rate_limit(request,"external-lab-complete",max_attempts=20)
        args=await body(request,{"nonce":str,"signature_hex":str})
        return output(invoke(db,stage_complete,**args))
    @router.post("/session/challenge")
    async def session_challenge(request:Request,db=Depends(database.get_db)):
        transport(request);check_rate_limit(request,"external-lab-session-challenge",max_attempts=30)
        args=await body(request,{"device_id":str,"cabinet_id":int})
        return output(challenge_payload(invoke(db,stage_session_challenge,**args)))
    @router.post("/session/issue")
    async def session_issue(request:Request,db=Depends(database.get_db)):
        transport(request);check_rate_limit(request,"external-lab-session-issue",max_attempts=30)
        args=await body(request,{"nonce":str,"signature_hex":str})
        return output(invoke(db,stage_issue_session,**args))
    @router.post("/read/challenge")
    async def read_challenge(request:Request,db=Depends(database.get_db)):
        transport(request);check_rate_limit(request,"external-lab-read-challenge",max_attempts=30)
        args=await body(request,{"raw_token":str,"device_id":str,"cabinet_id":int,"resource_id":int})
        nonce=invoke(db,stage_challenge,action="assigned-order.read",**args)
        if nonce is None:raise HTTPException(403,"operation refused")
        msg=message(session_digest=digest_token(args["raw_token"]),device_id=args["device_id"],action="assigned-order.read",cabinet_id=args["cabinet_id"],resource_id=args["resource_id"],nonce=nonce)
        return output({"nonce":nonce,"message_hex":msg.hex()})
    @router.post("/read/complete")
    async def read_complete(request:Request,db=Depends(database.get_db)):
        transport(request);check_rate_limit(request,"external-lab-read-complete",max_attempts=30)
        args=await body(request,{"raw_token":str,"device_id":str,"cabinet_id":int,"resource_id":int,"nonce":str,"signature_hex":str})
        return output(invoke(db,stage_lab_projection,**args))
    @router.get("/shell")
    async def shell(request:Request):
        transport(request,post=False)
        return HTMLResponse("<!doctype html><html lang='en'><meta charset='utf-8'><title>Synthetic Pocket LAB</title><body><h1>External laboratory LAB</h1><script type='module' src='/api/external-lab-rehearsal/client.mjs'></script></body></html>",
            headers={"Content-Security-Policy":CSP,"Cache-Control":"no-store","Referrer-Policy":"no-referrer"})
    @router.get("/client.mjs")
    async def client(request:Request):
        transport(request,post=False)
        path=Path(__file__).resolve().parents[2]/"frontend/src/features/mobile/security/externalLabDeviceKeyCandidate.mjs"
        return Response(path.read_text(),media_type="text/javascript",headers={"Cache-Control":"no-store","Content-Security-Policy":CSP})
    return router
