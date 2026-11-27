"""Disposable Windows hosted runner. Native SCM, service SID and distinct user tokens."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import win32api
import win32con
import win32file
import win32net
import win32netcon
import win32pipe
import win32security
import win32service
import pywintypes
from scripts.j5_owner_store import Store
from scripts.ci_j5_02c_recovery_lab import fixture,registration,assertion,decode
from scripts.j5_owner_broker import NAME,MAX,DATA_RIGHTS,SQOS,encode,sid_text,sid,user_sid,require
SC=Path(os.environ["SystemRoot"])/"System32"/"sc.exe"
def sc(*args):
    r=subprocess.run([str(SC),*args],capture_output=True,timeout=30)
    require(r.returncode==0,"SC_"+args[0].upper()+"_FAILED")
def acl(path,entries):
    d=win32security.ACL()
    for principal,mask in entries:
        d.AddAccessAllowedAceEx(win32security.ACL_REVISION,3,mask,sid(principal))
    win32security.SetNamedSecurityInfo(str(path),win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION|win32security.PROTECTED_DACL_SECURITY_INFORMATION,None,None,d,None)
def account(name):
    password="Aa9!"+secrets.token_hex(20)
    win32net.NetUserAdd(None,1,{"name":name,"password":password,"priv":win32netcon.USER_PRIV_USER,
        "flags":win32netcon.UF_SCRIPT|win32netcon.UF_DONT_EXPIRE_PASSWD})
    try:return win32security.LogonUser(name,".",password,win32con.LOGON32_LOGON_INTERACTIVE,win32con.LOGON32_PROVIDER_DEFAULT)
    except BaseException:win32net.NetUserDel(None,name);raise
def request(token,pipe,op,payload,*,denied=False):
    request_id=secrets.token_hex(16)
    deadline=time.monotonic()+10
    while True:
        win32security.ImpersonateLoggedOnUser(token)
        try:
            try:h=win32file.CreateFile(pipe,DATA_RIGHTS,0,None,win32con.OPEN_EXISTING,SQOS,None)
            except pywintypes.error as e:
                if denied and e.winerror==5:return None
                if e.winerror not in (2,231) or time.monotonic()>deadline:raise
                h=None
        finally:win32security.RevertToSelf()
        if h is not None:break
        time.sleep(.1)
    with_handle=h
    try:
        require(not denied,"UNAUTHORIZED_PIPE_OPEN")
        # The data-only client does not acquire FILE_WRITE_ATTRIBUTES or GENERIC_WRITE.
        win32file.WriteFile(h,encode({"operation":op,"request_id":request_id,"payload":payload}))
        end=time.monotonic()+8
        while time.monotonic()<end:
            try:
                _,available,_=win32pipe.PeekNamedPipe(h,0)
                if available:
                    require(available<=MAX,"RESPONSE_SIZE")
                    rc,raw=win32file.ReadFile(h,available)
                    if rc==0 and raw:break
            except pywintypes.error as e:
                if e.winerror not in (232,233):raise
            time.sleep(.025)
        else:raise RuntimeError("RESPONSE_TIMEOUT")
        result=json.loads(raw);require(result["request_id"]==request_id,"RESPONSE_BINDING")
        win32file.WriteFile(h,b"ACK")
        return result
    finally:h.Close()
def main():
    require(os.name=="nt" and os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("RUNNER_ENVIRONMENT")=="github-hosted","HOSTED_WINDOWS_ONLY")
    bundle=Path(sys.argv[1]).resolve(strict=True)
    runner=Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    exercise(bundle,runner)

def exercise(bundle,runner):
    require(bundle.is_relative_to(runner) and (bundle/"dc-owner-commissioning.exe").is_file(),"BUNDLE_PATH")
    # Never claim, stop, reconfigure or delete a pre-existing service.
    manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
    try:
        try:existing=win32service.OpenService(manager,NAME,win32service.SERVICE_QUERY_STATUS)
        except pywintypes.error as exc:require(exc.winerror==1060,"SERVICE_PREFLIGHT_FAILED")
        else:
            win32service.CloseServiceHandle(existing)
            raise RuntimeError("SERVICE_ALREADY_EXISTS")
    finally:win32service.CloseServiceHandle(manager)
    token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
    try:admin=user_sid(token)
    finally:token.Close()
    names=["dcj5a"+secrets.token_hex(4),"dcj5b"+secrets.token_hex(4)];tokens=[];created=False
    with tempfile.TemporaryDirectory(prefix="dc-owner-ci-",dir=runner) as tmp:
        root=Path(tmp);state=root/"state";state.mkdir();exe=bundle/"dc-owner-commissioning.exe"
        try:
            for name in names:tokens.append(account(name))
            client,other=map(user_sid,tokens)
            require(client!=other and client!=admin,"USER_DISTINCT")
            command='"'+str(exe)+'" --service "'+str(root/"config.json")+'"'
            sc("create",NAME,"binPath=",command,"start=","demand","obj=","NT AUTHORITY\\LocalService");created=True
            sc("sidtype",NAME,"unrestricted")
            service=sid_text(win32security.LookupAccountName(None,"NT SERVICE\\"+NAME)[0])
            full=0x1f01ff;rx=0x1200a9
            # Admin/controller owns config and executable; only service can mutate state.
            acl(root,[(admin,full),("S-1-5-18",full),(service,rx)])
            acl(state,[(admin,full),("S-1-5-18",full),(service,full)])
            acl(bundle,[(admin,full),("S-1-5-18",full),(service,rx)])
            Store.provision(state/"owner.sqlite")
            pipe=r"\\.\pipe\dc-owner-lab-"+secrets.token_hex(16)
            (root/"config.json").write_text(json.dumps({"mode":"COMMISSIONING_ONLY","client_sid":client,"service_sid":service,"pipe":pipe}),encoding="utf-8")
            sc("start",NAME)
            def call(op,**kw):
                r=request(tokens[0],pipe,op,kw);require(r["ok"],"OP_FAILED_"+op);return r["result"]
            def reject(op,**kw):require(request(tokens[0],pipe,op,kw)["ok"] is False,"UNEXPECTED_ACCEPT_"+op)
            require(call("status")=={"mode":"COMMISSIONING_ONLY","phase":"pending","release_enabled":False},"INITIAL_STATE")
            request(tokens[1],pipe,"status",{},denied=True)
            win32security.ImpersonateLoggedOnUser(tokens[0])
            try:
                try:h=win32file.CreateFile(str(state/"owner.sqlite"),win32con.GENERIC_WRITE,0,None,win32con.OPEN_EXISTING,0,None)
                except pywintypes.error as e:require(e.winerror==5,"WRONG_DENIAL")
                else:h.Close();raise RuntimeError("DIRECT_WRITER_ACCEPTED")
            finally:win32security.RevertToSelf()
            print("J5_04C_NATIVE_SCM_DISTINCT_CLIENT_DIRECT_WRITER_DENIED_PASS",flush=True)
            reject("approve_release");reject("bootstrap");reject("status",peer_sid=client)
            primary,backup,replacement=fixture(),fixture(),fixture()
            def enroll(role,f,flags):
                q=call("register_begin",role=role)
                if role=="backup":reject("register_finish",nonce=q["nonce"],credential=registration(f,decode(q["challenge"])))
                r=registration(f,decode(q["challenge"]),flags=flags|0x40)
                require(call("register_finish",nonce=q["nonce"],credential=r)["cid"]==f[0],"REGISTER")
                reject("register_finish",nonce=q["nonce"],credential=r)
                p=call("prove_begin",cid=f[0])
                proof=assertion(f,decode(p["challenge"]),flags=flags)
                reject("prove_finish",nonce=p["nonce"],proof=assertion(f,decode(p["challenge"]),origin="https://wrong.invalid",flags=flags))
                call("prove_finish",nonce=p["nonce"],proof=proof)
                reject("prove_finish",nonce=p["nonce"],proof=proof)
            enroll("primary",primary,29);enroll("backup",backup,5)
            require(call("status")["phase"]=="enrolled_lab","ENROLLMENT")
            reject("register_begin",role="primary")
            print("J5_04C_SERVER_CHALLENGE_ENROLLMENT_REPLAY_PASS",flush=True)
            sc("stop",NAME);wait_stopped();sc("start",NAME)
            require(call("status")["phase"]=="enrolled_lab","RESTART_PERSISTENCE")
            enroll("replacement",replacement,29)
            q=call("recover_begin",cid=replacement[0])
            reject("recover_finish",nonce=q["nonce"],proof=assertion(primary,decode(q["challenge"])))
            proof=assertion(backup,decode(q["challenge"]),flags=5)
            call("recover_finish",nonce=q["nonce"],proof=proof);reject("recover_finish",nonce=q["nonce"],proof=proof)
            require(call("status")["release_enabled"] is False,"RELEASE_GATE")
            print("J5_04C_RECOVERY_RESTART_NO_RELEASE_PASS",flush=True)
        finally:
            trace=state/"broker-status.log"
            if trace.is_file():
                for line in trace.read_text(encoding="ascii").splitlines()[-50:]:
                    if len(line)<100 and all(c.isalnum() or c in "_ - " for c in line):
                        print("J5_04C_SERVICE_TRACE "+line,flush=True)
            if created:
                subprocess.run([str(SC),"stop",NAME],capture_output=True,timeout=30)
                wait_stopped();sc("delete",NAME)
            for token,name in zip(tokens,names):token.Close();win32net.NetUserDel(None,name)
    print("J5_04C_NATIVE_CLEANUP_PASS",flush=True)
def wait_stopped():
    manager=win32service.OpenSCManager(None,None,win32service.SC_MANAGER_CONNECT)
    try:
        service=win32service.OpenService(manager,NAME,win32service.SERVICE_QUERY_STATUS)
        try:
            for _ in range(100):
                if win32service.QueryServiceStatus(service)[1]==win32service.SERVICE_STOPPED:return
                time.sleep(.2)
            raise RuntimeError("SERVICE_STOP_TIMEOUT")
        finally:win32service.CloseServiceHandle(service)
    finally:win32service.CloseServiceHandle(manager)
if __name__=="__main__":main()
