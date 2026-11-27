"""J5-02C.6: Windows admission contract, NOT a broker implementation.
No TPM command submission, service installation, physical device or OWNER activation.
Native Windows AccessCheck and read-only TBS device-info discovery only.
All budget/clock/authorization inputs in this laboratory are synthetic.
"""
import csv
import ctypes
import os
import subprocess
import unittest
from ctypes import wintypes
from dataclasses import dataclass

class Denied(ValueError): pass

OPS = frozenset(("register","prove","approve","redeem","rotate","recover","replace_backup","revoke_backup"))
SOFTWARE_GATES = ("exact_head","prior_regressions","broker_contract","acl_contract","budget_contract","clock_contract","recovery_contract")
HARDWARE_GATES = ("real_service_token","direct_tbs_denial","tpm_identity","nv_policy","nv_endurance","trusted_clock","independent_backup","recovery_drill","non_destructive_decommission")

def authorize_fixture(*, operation, peer_sid, expected_sid, remote, peer_verified, request_fields):
    if operation not in OPS or remote is not False or peer_verified is not True:
        raise Denied("peer or operation")
    if not isinstance(expected_sid,str) or not expected_sid or peer_sid!=expected_sid:
        raise Denied("peer")
    if type(request_fields) is not set or request_fields!={"operation","request_id","payload"}:
        raise Denied("request schema")
    return "LAB_DISPATCH_ONLY"

def admission(software,hardware):
    if set(software)!=set(SOFTWARE_GATES) or set(hardware)!=set(HARDWARE_GATES):
        raise Denied("gate schema")
    if any(v is not True for v in software.values()): return "SOFTWARE_BLOCKED"
    # This module cannot validate hardware evidence or authorize a release.
    if any(v is not True for v in hardware.values()): return "LOT10_REQUIRED"
    return "EXTERNAL_HUMAN_GATE_REQUIRED"

@dataclass
class Budget:
    """Fixture allowance, not NV lifetime measurement or durable ledger."""
    capacity: int
    reserve: int
    attempted: int = 0
    def charge(self, *, recovery=False, count=1):
        if any(type(v) is not int for v in (self.capacity,self.reserve,self.attempted,count)) or not (0<self.reserve<self.capacity) or not (0<=self.attempted<=self.capacity) or count<=0 or type(recovery) is not bool:
            raise Denied("unqualified budget")
        cap=self.capacity if recovery else self.capacity-self.reserve
        if self.attempted+count>cap: raise Denied("budget exhausted")
        # Never refund an attempt with an unknown outcome.
        self.attempted+=count

def clock_gate(*,high_water,observed,independent,uncertainty,max_uncertainty):
    if independent is not True or any(type(x) is not int for x in (high_water,observed,uncertainty,max_uncertainty)):
        raise Denied("untrusted clock")
    if min(high_water,observed,uncertainty,max_uncertainty)<0 or uncertainty>max_uncertainty or observed-uncertainty<high_water:
        raise Denied("clock rollback or uncertainty")
    return observed-uncertainty

class ContractTests(unittest.TestCase):
    def test_01_allow_list(self):
        for op in OPS:
            self.assertEqual(authorize_fixture(operation=op,peer_sid="fixture",expected_sid="fixture",remote=False,peer_verified=True,request_fields={"operation","request_id","payload"}),"LAB_DISPATCH_ONLY")
    def check(self,**kw):
        args=dict(operation="approve",peer_sid="fixture",expected_sid="fixture",remote=False,peer_verified=True,request_fields={"operation","request_id","payload"})
        args.update(kw);return authorize_fixture(**args)
    def test_02_raw_command_denied(self):
        for op in ("submit_raw","clear","undefine","define","unseal","set_clock","reset","shell","approve_release"):
            with self.subTest(op=op),self.assertRaises(Denied): self.check(operation=op)
    def test_03_remote_denied(self):
        with self.assertRaises(Denied): self.check(remote=True)
    def test_04_sid_denied(self):
        with self.assertRaises(Denied): self.check(peer_sid="other")
    def test_05_unverified_peer_denied(self):
        with self.assertRaises(Denied): self.check(peer_verified=False)
    def test_06_extra_field_denied(self):
        with self.assertRaises(Denied): self.check(request_fields={"operation","request_id","payload","raw_tpm"})
    def test_07_missing_hardware(self):
        s=dict.fromkeys(SOFTWARE_GATES,True);h=dict.fromkeys(HARDWARE_GATES,False)
        self.assertEqual(admission(s,h),"LOT10_REQUIRED")
    def test_08_each_hardware_gate(self):
        s=dict.fromkeys(SOFTWARE_GATES,True)
        for gate in HARDWARE_GATES:
            h=dict.fromkeys(HARDWARE_GATES,True);h[gate]=False
            self.assertEqual(admission(s,h),"LOT10_REQUIRED")
    def test_09_all_fixtures_no_activation(self):
        self.assertEqual(admission(dict.fromkeys(SOFTWARE_GATES,True),dict.fromkeys(HARDWARE_GATES,True)),"EXTERNAL_HUMAN_GATE_REQUIRED")
    def test_10_software_block(self):
        s=dict.fromkeys(SOFTWARE_GATES,True);s["prior_regressions"]=False
        self.assertEqual(admission(s,dict.fromkeys(HARDWARE_GATES,True)),"SOFTWARE_BLOCKED")
    def test_11_schema_fail_closed(self):
        with self.assertRaises(Denied): admission({}, {})
    def test_12_budget_reserve(self):
        b=Budget(10,2);b.charge(count=8)
        with self.assertRaises(Denied): b.charge()
        b.charge(recovery=True,count=2)
        with self.assertRaises(Denied): b.charge(recovery=True)
    def test_13_unknown_write_charged(self):
        b=Budget(10,2);b.charge()
        # Simulated timeout: do not restore the allowance.
        self.assertEqual(b.attempted,1)
        with self.assertRaises(Denied): b.charge(count=8)
    def test_14_unknown_capacity(self):
        for b in (Budget(0,0),Budget(10,0),Budget(10,10),Budget(True,1),Budget(10,2,-1)):
            with self.assertRaises(Denied): b.charge()
    def test_15_clock_positive(self):
        self.assertEqual(clock_gate(high_water=1000,observed=1010,independent=True,uncertainty=2,max_uncertainty=3),1008)
    def test_16_clock_untrusted(self):
        with self.assertRaises(Denied): clock_gate(high_water=1000,observed=1010,independent=False,uncertainty=0,max_uncertainty=3)
    def test_17_clock_rollback(self):
        with self.assertRaises(Denied): clock_gate(high_water=1000,observed=1001,independent=True,uncertainty=2,max_uncertainty=3)
    def test_18_clock_uncertainty(self):
        with self.assertRaises(Denied): clock_gate(high_water=1000,observed=1010,independent=True,uncertainty=4,max_uncertainty=3)

@unittest.skipUnless(os.name=="nt","native Windows only")
class NativeWindowsTests(unittest.TestCase):
    def setUp(self):
        self.a=ctypes.WinDLL("advapi32",use_last_error=True)
        self.k=ctypes.WinDLL("kernel32",use_last_error=True)
        self.k.GetCurrentProcess.restype=wintypes.HANDLE
        self.k.CloseHandle.argtypes=[wintypes.HANDLE]
        self.k.LocalFree.argtypes=[ctypes.c_void_p]
        self.a.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
        self.a.DuplicateToken.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.POINTER(wintypes.HANDLE)]
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[wintypes.LPCWSTR,wintypes.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.ULONG)]
        self.a.AccessCheck.argtypes=[ctypes.c_void_p,wintypes.HANDLE,wintypes.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.BOOL)]
        self.token=wintypes.HANDLE()
        self.assertTrue(self.a.OpenProcessToken(self.k.GetCurrentProcess(),0x000a,ctypes.byref(self.token)))
        self.addCleanup(self.k.CloseHandle,self.token)
        self.imp=wintypes.HANDLE()
        self.assertTrue(self.a.DuplicateToken(self.token,2,ctypes.byref(self.imp)))
        self.addCleanup(self.k.CloseHandle,self.imp)
        # Local identity used only in memory, never printed or persisted.
        row=next(csv.reader(subprocess.check_output(["whoami","/user","/fo","csv","/nh"],text=True).splitlines()))
        self.sid=row[-1].strip()
        self.assertTrue(self.sid.startswith("S-1-"))
    def allowed(self,sid,rights):
        sd=ctypes.c_void_p()
        sddl="O:SYG:SYD:P(A;;0x00100003;;;"+sid+")"
        self.assertTrue(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(sd),None))
        try:
            mapping=(wintypes.DWORD*4)(0x00120089,0x00120116,0x001200a0,0x001f01ff)
            privilege=ctypes.create_string_buffer(1024)
            length=wintypes.DWORD(len(privilege));granted=wintypes.DWORD();status=wintypes.BOOL()
            self.assertTrue(self.a.AccessCheck(sd,self.imp,rights,ctypes.byref(mapping),privilege,ctypes.byref(length),ctypes.byref(granted),ctypes.byref(status)),ctypes.get_last_error())
            return bool(status.value)
        finally: self.k.LocalFree(sd)
    def test_19_kernel_acl_client_data(self):
        self.assertTrue(self.allowed(self.sid,0x00100003))
    def test_20_kernel_acl_no_create_pipe_instance(self):
        self.assertFalse(self.allowed(self.sid,0x00000004))
    def test_21_kernel_acl_unlisted_principal(self):
        self.assertFalse(self.allowed("S-1-5-21-111-222-333-444",0x00000003))
    def test_22_native_tbs_discovery_only(self):
        class Info(ctypes.Structure):
            _fields_=[("structVersion",wintypes.UINT),("tpmVersion",wintypes.UINT),("tpmInterfaceType",wintypes.UINT),("tpmImpRevision",wintypes.UINT)]
        tbs=ctypes.WinDLL("tbs.dll")
        fn=tbs.Tbsi_GetDeviceInfo
        fn.argtypes=[wintypes.UINT,ctypes.c_void_p];fn.restype=wintypes.UINT
        info=Info()
        rc=fn(ctypes.sizeof(info),ctypes.byref(info))
        print("TBS_DISCOVERY_ONLY result=0x%08x version=%d; PHYSICAL_ADMISSION_NOT_RUN"%(rc,info.tpmVersion),flush=True)
        if rc==0: self.assertIn(info.tpmVersion,(1,2))
        # Any discovery failure is explicitly not hardware admission.

if __name__=="__main__":
    unittest.main(verbosity=2)
