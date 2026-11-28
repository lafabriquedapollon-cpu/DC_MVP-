"""R5-B building block: bind a proposed platform mutation to an exact intent.

This module does not authenticate, issue credentials, authorize mutations,
consume nonces, perform database writes or expose an API. Callers must
authenticate and revalidate authority, then atomically consume the intent,
apply the mutation and persist the audit in one transaction.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import re
import uuid

_ALLOWED_ACTIONS = frozenset({"trial-code.revoke"})

def _positive_int(value: int) -> int:
    if type(value) is not int or not 0 < value <= 2**63 - 1:
        raise ValueError("invalid identifier")
    return value

def _hex(value: str, size: int) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{" + str(size) + r"}", value):
        raise ValueError("invalid binding")
    return value

def _device(value: str) -> str:
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid device")
    return value

@dataclass(frozen=True)
class PlatformMutationIntent:
    action: str
    target_id: int
    actor_id: int
    tenant_id: int
    device_id: str
    credential_binding: str
    approval_jti: str
    uv_jti: str
    nonce: str

    def digest(self) -> bytes:
        if not isinstance(self.action, str) or self.action not in _ALLOWED_ACTIONS:
            raise ValueError("action not admitted")
        fields = [
            "digital-crown/platform-mutation-intent/v1",
            self.action,
            _positive_int(self.target_id),
            _positive_int(self.actor_id),
            _positive_int(self.tenant_id),
            _device(self.device_id),
            _hex(self.credential_binding, 64),
            _hex(self.approval_jti, 32),
            _hex(self.uv_jti, 32),
            _hex(self.nonce, 64),
        ]
        return hashlib.sha256(json.dumps(fields, separators=(",", ":"), ensure_ascii=True).encode("ascii")).digest()
