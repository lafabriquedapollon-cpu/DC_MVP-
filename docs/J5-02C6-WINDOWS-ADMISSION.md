# J5-02C.6 — Windows admission contract (NOT A RELEASE)

## Exit scope
Software admission dossier only. No actual broker installation, raw TPM submission on Windows, physical TPM tests, OWNER enrollment, production or changes to launcher. Real hardware admission remains LOT10 and a separate human authorization. J5-03 may proceed in a synthetic, fail-closed packaging lab without activation.

## Trust boundary
Desktop client is untrusted; dedicated least-privilege Windows service identity owns the writer capability. Local IPC must use a service-controlled named pipe, explicit DACL with the authorized logon SID and exact read/write data rights (not generic write, which grants FILE_CREATE_PIPE_INSTANCE), remote rejection, first-instance protection, bounded messages, kernel peer-token verification and server-side operation validation. No client-supplied SID, command bytes, TPM index, clock, hierarchy auth, or paths may be accepted. Client requests are semantic actions; each mutation revalidates WebAuthn and current anchor inside a serialized transaction. No generic signing or raw TBS relay. Service binary, service configuration, credential material and DB paths must be protected against ordinary users. A separate principal must not be able to submit authorized NV writes directly via TBS; ACL on IPC alone does not establish that. Admin/kernel/firmware compromise is outside the ordinary-user guarantee and must never be claimed protected.

## Hardware gate and lifecycle
Use TBS device discovery read-only; successful discovery is not authorization. Windows can block TPM commands; no disabling command blocking, no registry/Group Policy edits, no TPM clear/reset, no changes to existing TPM/BitLocker/Windows Hello keys. Before hardware provisioning, demonstrate compatible hardware/firmware, exact NV policy and identity, exclusive writer authorization, readback, reboot persistence, rollback refusal, independent backup credential, recoverability and a non-destructive replacement/decommission procedure. The emulator's intentionally non-deletable policy is not a physical provisioning recipe. If platform authorization or safe decommission cannot be proven, reject this TPM design and select an independent anchor by explicit decision. No automatic re-provision after missing state, mismatch, timeout, reset or device replacement. Never lower an anchor. Preserve old valid authority until a separately authorized replacement ceremony succeeds; otherwise fail closed.

## Time and endurance
Require independent authenticated time evidence, bounded uncertainty and persisted high-water. Windows wall time alone is insufficient; no caller-provided time, no backwards adjustment, no fallback acceptance when time unavailable. Persist the high-water before accepting a later operation; account for failed/uncertain attempts conservatively. NV budget must be based on the exact TPM vendor/model endurance and measured workload with safety margin, recovery reserve and rate limiting. No universal numeric endurance assumed. Exhaustion/unknown capacity or lost state blocks new approval; reserved recovery writes only under authenticated recovery policy. Avoid writes on unauthenticated traffic; throttle before challenge issuance, no unbounded background high-water updates. Fixture budget model is not an implementation of a persistent quota or trusted clock. Power interruption between TPM and DB commits must block without automatic repair.

## Acceptance evidence required on LOT10 (not performed)
- Actual Windows service SID, effective rights and peer-token tests under distinct user/service tokens; unauthorized direct TBS writer rejected, no policy relaxation.
- TPM identity and NV policy attested/bound to external enrollment, protected against rollback and replacement within threat model.
- Real reboot/restore/rotation/revocation and interruption tests; old approval denied, hardware identity change denied.
- Device-bound backup independent of primary synchronization/account; human custody and actual recovery drill. BE=0 alone insufficient.
- Independent clock and endurance/availability measured; recovery and decommission do not alter existing TPM keys or disable BitLocker.
- Separate OWNER approval and verified release provenance/packaging; no production activation from this lab.

## Evidence scope
Native Windows AccessCheck against the current runner token and constructed DACL demonstrates only access-mask semantics, not a service ACL or different Windows principal. Read-only Tbsi_GetDeviceInfo logs a result code, not hardware admission. Contract unit tests use synthetic inputs; all-green cannot enable OWNER. Previous 77 tests run on Linux swtpm. No physical operations.

## References
- https://learn.microsoft.com/en-us/windows/win32/tbs/command-blocking
- https://learn.microsoft.com/en-us/windows/win32/tbs/using-tbs
- https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_getdeviceinfo
- https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
- https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
