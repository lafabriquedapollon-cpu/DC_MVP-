"""Native diagnostic, no broker rebuild, no clinical state."""
import os,secrets
import win32api,win32con,win32file,win32pipe,win32security,win32net,pywintypes
from scripts.ci_j5_04c_native_broker import account
from scripts.j5_owner_broker import pipe_acl,user_sid,DATA_RIGHTS,SQOS
import pywintypes
def main():
    assert os.environ.get("GITHUB_ACTIONS")=="true" and os.name=="nt"
    name="dcdiag"+secrets.token_hex(4)
    token=account(name)
    h=None
    try:
        client=user_sid(token)
        own=win32security.OpenProcessToken(win32api.GetCurrentProcess(),win32con.TOKEN_QUERY)
        try:server=user_sid(own)
        finally:own.Close()
        pipe=r"\\.\pipe\dc-owner-diag-"+secrets.token_hex(16)
        h=win32pipe.CreateNamedPipe(pipe,3|0x80000,4|2|1|8,1,32768,32768,0,pipe_acl(client,server))
        sd=win32security.GetSecurityInfo(h,win32security.SE_KERNEL_OBJECT,win32security.DACL_SECURITY_INFORMATION)
        acl=sd.GetSecurityDescriptorDacl()
        print("DIAG_CLIENT_ACE",[(a[1]) for a in (acl.GetAce(i) for i in range(acl.GetAceCount())) if win32security.ConvertSidToStringSid(a[2])==client])
        try:win32pipe.ConnectNamedPipe(h,None)
        except pywintypes.error as e:print("DIAG_LISTEN",e.winerror)
        # Compare explicit rights with the additional read-attributes right
        # potentially requested internally by CreateFileW.
        # No append/create-instance or generic write permission is granted.
        for grant in (DATA_RIGHTS, DATA_RIGHTS|0x80, DATA_RIGHTS|0x80|0x20000|8):
            if h:h.Close()
            sa=pipe_acl(client,server)
            d=sa.SECURITY_DESCRIPTOR.GetSecurityDescriptorDacl()
            d.DeleteAce(2)
            d.AddAccessAllowedAce(win32security.ACL_REVISION,grant,win32security.ConvertStringSidToSid(client))
            sa.SECURITY_DESCRIPTOR.SetSecurityDescriptorDacl(1,d,0)
            h=win32pipe.CreateNamedPipe(pipe,3|0x80000,4|2|1|8,1,32768,32768,0,sa)
            try:win32pipe.ConnectNamedPipe(h,None)
            except pywintypes.error as e:
                if e.winerror!=536:raise
            win32security.ImpersonateLoggedOnUser(token)
            try:
                thread=win32security.OpenThreadToken(win32api.GetCurrentThread(),win32con.TOKEN_QUERY,True)
                try:assert user_sid(thread)==client
                finally:thread.Close()
                try:
                    c=win32file.CreateFile(pipe,DATA_RIGHTS,0,None,3,SQOS,None)
                    c.Close()
                    print("DIAG_GRANT",hex(grant),"PASS",flush=True)
                except pywintypes.error as e:print("DIAG_GRANT",hex(grant),e.winerror,flush=True)
            finally:win32security.RevertToSelf()
        for mask in (1,2,3,DATA_RIGHTS):
            win32security.ImpersonateLoggedOnUser(token)
            try:
                try:
                    c=win32file.CreateFile(pipe,mask,0,None,3,SQOS,None)
                    c.Close()
                    print("DIAG_OPEN",hex(mask),"PASS",flush=True)
                except pywintypes.error as e:print("DIAG_OPEN",hex(mask),e.winerror,flush=True)
            finally:win32security.RevertToSelf()
            try:win32pipe.DisconnectNamedPipe(h)
            except pywintypes.error:pass
            try:win32pipe.ConnectNamedPipe(h,None)
            except pywintypes.error:pass
    finally:
        if h:h.Close()
        token.Close();win32net.NetUserDel(None,name)
if __name__=="__main__":main()
