"""Proposed recovery authority contract; NOT an active release trust root.

The existing production verifier and signing identity remain unchanged.
A branch name, an arbitrary JSON evidence file, or successful CI alone cannot
authorize a clinical release. This module only constructs a verification plan.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

REPOSITORY = "lafabriquedapollon-cpu/DC_MVP-"
REPOSITORY_ID = 1468617084
OWNER_ID = 262976758
SOURCE_REF = "refs/heads/main"
SIGNER_WORKFLOW = REPOSITORY + "/.github/workflows/cabinet-release-certification.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE = "https://slsa.dev/provenance/v1"
_SHA = re.compile(r"[0-9a-f]{40}")


class AuthorityDenied(RuntimeError):
    pass


def exact_sha(value: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AuthorityDenied("EXACT_LOWERCASE_SHA_REQUIRED")
    return value


def check_repository_identity(repository: Mapping) -> None:
    owner = repository.get("owner")
    if (
        repository.get("full_name") != REPOSITORY
        or type(repository.get("id")) is not int
        or repository.get("id") != REPOSITORY_ID
        or not isinstance(owner, Mapping)
        or type(owner.get("id")) is not int
        or owner.get("id") != OWNER_ID
        or repository.get("default_branch") != "main"
    ):
        raise AuthorityDenied("REPOSITORY_IDENTITY_MISMATCH")


def check_candidate_ref(branch: Mapping, *, approved_sha: str) -> None:
    """Check necessary conditions only; this is NOT a full ruleset audit."""
    exact_sha(approved_sha)
    if branch.get("name") != "main" or branch.get("protected") is not True:
        raise AuthorityDenied("PROTECTED_MAIN_REQUIRED")
    commit = branch.get("commit")
    if not isinstance(commit, Mapping) or commit.get("sha") != approved_sha:
        raise AuthorityDenied("APPROVED_SOURCE_SHA_MISMATCH")


def verification_plan(subject: Path, *, approved_sha: str) -> tuple[str, ...]:
    """Construct fixed online GitHub CLI arguments; never executes or issues.

    The approved SHA must eventually come from a separately authenticated owner
    approval record. A caller-supplied SHA is NOT itself that approval.
    Same-repository, non-reusable signer workflow at the exact approved commit.
    No custom root, offline bundle, owner-only scope or self-hosted runner.
    """
    sha = exact_sha(approved_sha)
    if not subject.is_absolute() or subject.is_symlink() or not subject.is_file():
        raise AuthorityDenied("REGULAR_ABSOLUTE_SUBJECT_REQUIRED")
    return (
        "attestation", "verify", str(subject),
        "--hostname", "github.com",
        "--repo", REPOSITORY,
        "--signer-workflow", SIGNER_WORKFLOW,
        "--signer-digest", sha,
        "--source-digest", sha,
        "--source-ref", SOURCE_REF,
        "--cert-oidc-issuer", OIDC_ISSUER,
        "--predicate-type", PREDICATE,
        "--deny-self-hosted-runners",
        "--format", "json",
    )
