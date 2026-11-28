"""External Pocket scope contract, not an authentication provider.

Only server-resolved assignments may populate these types. No staff UserRole
conversion, JWT issuance, database registration, route or capability grant
is performed here. Future adapters must verify assignment and revocation
against their authoritative stores on every request.
"""
from dataclasses import dataclass
from typing import Literal

@dataclass(frozen=True)
class ExternalScope:
    kind: Literal["technical", "laboratory"]
    principal_id: str
    organization_id: str

@dataclass(frozen=True)
class ResourceAssignment:
    kind: Literal["technical", "laboratory"]
    principal_id: str
    organization_id: str
    cabinet_id: int
    resource_id: int
    active: bool

def matches_read_scope(scope: ExternalScope, assignment: ResourceAssignment,
                       *, action: str, cabinet_id: int, resource_id: int) -> bool:
    if not isinstance(scope, ExternalScope) or not isinstance(assignment, ResourceAssignment):
        return False
    if scope.kind not in ("technical", "laboratory") or scope.kind != assignment.kind:
        return False
    if any(type(v) is not str or not v.strip() for v in
           (scope.principal_id, scope.organization_id, assignment.principal_id, assignment.organization_id)):
        return False
    if assignment.active is not True or scope.principal_id != assignment.principal_id or scope.organization_id != assignment.organization_id:
        return False
    if any(type(v) is not int or v <= 0 for v in
           (cabinet_id, resource_id, assignment.cabinet_id, assignment.resource_id)):
        return False
    if cabinet_id != assignment.cabinet_id or resource_id != assignment.resource_id:
        return False
    # No global lab inbox, clinical records, financial records or mutation.
    # Technical scope is limited to a specifically assigned nonclinical diagnostic projection.
    return action == {"technical": "diagnostic.read", "laboratory": "assigned-order.read"}[scope.kind]
