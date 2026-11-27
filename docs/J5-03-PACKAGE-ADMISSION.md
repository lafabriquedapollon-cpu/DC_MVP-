# J5-03 — Zero-manual-dependency package: admission record
Goal: one Windows setup EXE, installed application in onedir layout (PyInstaller + Inno Setup), no manual Python, Node, pip, DLL or model downloads. First-run user authentication/licence and secure local provisioning remain mandatory, not installation of dependencies. CPU baseline; no mandatory GPU or external LLM. Patient DB/media generated locally, never shipped.

## Existing evidence
- Run 45915837801 at 5703d44ea3dd66be5d67ed589f016263b0e61c1e: real frozen backend, frontend, native DLL relocation, SQLCipher persistence, loopback, installed restart and clean uninstall; ephemeral synthetic PE only, no distributable artifact.
- Reuse the exact existing Windows build lock, CPU wheels, guarded frontend and native sidecar. Do not silently substitute dependencies. A version pin alone is not a wheel hash lock.
- Current run.py and DigitalCrown.spec deliberately refuse positive activation. Legacy certification identity differs from proposed recovery authority; do not change trust root or claim installability.

## Input admission
- Source and built frontend, Python/CPU ONNX/PyTorch runtimes, native libraries, SQLCipher, PDF/font resources, application icons, other approved assets: exact inventory, versions, licences, sizes and SHA256; exclude private keys, credentials, .env and real clinical databases/media.
- Scientific registry absent at current HEAD. Historical record identifies SRPose38 267484931 bytes SHA256 a5ecd466d6d2c4ef02e145a143076a05720c0be56a260224812c23e2ecf42ddb, bytes not verified/recovered. Legacy CephLD-CCA and panoramic model not pinned. Registry and actual weights must be restored privately, validate rights, hash and scientific gate separately. No invented weights, no placeholder passed as model, no private model upload to public GitHub or public CI artifacts. Do not assume all historical models are required.
- Reconcile code, release identity, asset certificate, provenance and provisioning/restore only after owner gates. An unapproved feature must remain disabled; cannot call an incomplete package a complete certified release.
- Validate final immutable package manifest (all executable/resource files), dependency closure and no downloads at startup on clean Windows, actual installed executable, init/restart, local encrypted data, synthetic model inference where authorized, failure on missing/tampered asset, upgrade/restore/uninstall. Verify package hash and provenance before delivery. No physical tests before LOT10; final reception separately authorized.
- No certificate or installer issued by this read-only audit. Positive authority, secure provisioning and runtime assets are blockers, not reasons to weaken gates.
