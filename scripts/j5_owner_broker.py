"""Dedicated SCM service, native local named pipe, commissioning only."""
import json
import os
from pathlib import Path
import re
import sys
import time
import win32api
import win32con
import win32file
import win32pipe
import win32security
import win32service
import win32serviceutil
import servicemanager
import pywintypes
from scripts.j5_owner_store import Store,require,unique

NAME="DigitalCrownOwnerCommissioning"
MAX=32768
# Native CreateFile requires FILE_READ_ATTRIBUTES in the DACL.
# No FILE_CREATE_PIPE_INSTANCE, GENERIC_WRITE or WRITE_DAC.
DATA_RIGHTS=0x00100083
FULL=0x1f01ff
FIRST=0x00080000
REJECT_REMOTE=8
SQOS=0x00120000
def sid_text(s):return win32security.ConvertSidToStringSid(s)
def sid(s):return win32security.ConvertStringSidToSid(s)
def user_sid(token):return sid_text(win32security.GetTokenInformation(token,win32security.TokenUser)[0])
def encode(value):
    data=json.dumps(value,separators=(",",":"),ensure_ascii=True).encode("ascii")
    require(len(data)<=MAX,"MESSAGE_SIZE");return data
def read(handle,stop,seconds=5):
    deadline=time.monotonic()+seconds
    while not stop() and time.monotonic()<deadline:
        try:
            rc,data=win32file.ReadFile(handle,MAX)
            if rc==0 and data:return data
            if rc not in (0,232):raise ValueError("READ_STATUS")
        except pywintypes.error as exc:
            if exc.winerror not in (232,233,536):raise
        time.sleep(.025)
    raise TimeoutError("READ_TIMEOUT")
def write(handle,value):
    rc,n=win32file.WriteFile(handle,value)
    require(rc==0 and n==len(value),"WRITE_FAILED")
def pipe_acl(client,service):
    acl=win32security.ACL()
    for s,mask in (("S-1-5-18",FULL),(service,FULL),(client,DATA_RIGHTS)):
        acl.AddAccessAllowedAce(win32security.ACL_REVISION,mask,sid(s))
    sd=win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1,acl,0)
    sa=pywintypes.SECURITY_ATTRIBUTES();sa.SECURITY_DESCRIPTOR=sd
    return sa
def config(path):
    p=Path(path)
    require(p.is_absolute() and p.is_file() and not p.is_symlink(),"CONFIG_PATH")
    c=json.loads(p.read_text(encoding="utf-8"),object_pairs_hook=unique)
    require(set(c)=={"mode","client_sid","service_sid","pipe"} and c["mode"]=="COMMISSIONING_ONLY","CONFIG_SCHEMA")
    require(re.fullmatch(r"\\\\\.\\pipe\\dc-owner-lab-[a-f0-9]{32}",c["pipe"]),"PIPE_NAME")
    require(sid_text(sid(c["client_sid"]))==c["client_sid"] and sid_text(sid(c["service_sid"]))==c["service_sid"],"SID")
    require(c["client_sid"]!=c["service_sid"],"DISTINCT_PRINCIPAL")
    return c,p.parent/"state"/"owner.sqlite"
class Service(win32serviceutil.ServiceFramework):
    _svc_name_=NAME
    _svc_display_name_="Digital Crown OWNER commissioning (NOT CLINICAL)"
    def __init__(self,args):
        super().__init__(args);self.stopping=False
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING);self.stopping=True
    def SvcDoRun(self):
        c,path=config(sys.argv[2])
        token=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
        try:
            require(user_sid(token)=="S-1-5-19","LOCAL_SERVICE_REQUIRED")
            groups={sid_text(s):flags for s,flags in win32security.GetTokenInformation(token,win32security.TokenGroups)}
            require(groups.get(c["service_sid"],0)&4,"SERVICE_SID_REQUIRED")
        finally:token.Close()
        store=Store(path)
        h=win32pipe.CreateNamedPipe(c["pipe"],win32pipe.PIPE_ACCESS_DUPLEX|FIRST,
            win32pipe.PIPE_TYPE_MESSAGE|win32pipe.PIPE_READMODE_MESSAGE|win32pipe.PIPE_NOWAIT|REJECT_REMOTE,
            1,MAX,MAX,0,pipe_acl(c["client_sid"],c["service_sid"]))
        try:
            while not self.stopping:
                # Poll a listening instance without disconnecting it between polls.
                try:
                    rc=win32pipe.ConnectNamedPipe(h,None)
                    if rc in (231,536):time.sleep(.025);continue
                except pywintypes.error as exc:
                    if exc.winerror in (231,536):time.sleep(.025);continue
                    if exc.winerror!=535:raise
                try:
                    raw=read(h,lambda:self.stopping)
                    win32pipe.ImpersonateNamedPipeClient(h)
                    try:
                        peer=win32security.OpenThreadToken(win32api.GetCurrentThread(),win32con.TOKEN_QUERY,True)
                        try:actual=user_sid(peer)
                        finally:peer.Close()
                    finally:win32security.RevertToSelf()
                    require(actual==c["client_sid"],"PEER_DENIED")
                    req=json.loads(raw,object_pairs_hook=unique)
                    require(type(req)is dict and set(req)=={"operation","request_id","payload"} and
                            isinstance(req["request_id"],str) and re.fullmatch("[a-f0-9]{32}",req["request_id"]),"REQUEST_SCHEMA")
                    try:result={"ok":True,"request_id":req["request_id"],"result":store.dispatch(req["operation"],req["payload"])}
                    except Exception:result={"ok":False,"request_id":req["request_id"],"error":"DENIED"}
                    write(h,encode(result))
                    # A bounded ack avoids losing the response on disconnect.
                    require(read(h,lambda:self.stopping)==b"ACK","ACK")
                except Exception:pass
                finally:
                    try:win32pipe.DisconnectNamedPipe(h)
                    except pywintypes.error:pass
        finally:h.Close()
def main():
    if len(sys.argv)!=3 or sys.argv[1]!="--service" or not getattr(sys,"frozen",False):
        raise SystemExit("COMMISSIONING_SERVICE_ONLY")
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(Service)
    servicemanager.StartServiceCtrlDispatcher()
if __name__=="__main__":main()
