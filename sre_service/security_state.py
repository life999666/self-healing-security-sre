"""State model for security incidents handed off by Sentinel."""
from __future__ import annotations

from typing import Any, TypedDict


class SecurityRemediationState(TypedDict, total=False):
    incident: dict[str, Any]
    target_file: str
    repo_file_path: str
    original_code: str
    vulnerability_confirmed: bool
    vulnerability_type: str
    root_cause_analysis: str
    unsafe_findings: list[str]
    fix_code: str
    fix_validated: bool
    validation_errors: list[str]
    iteration_count: int
    pr_status: str
    pr_url: str
    status: str


def create_security_state(incident: dict[str, Any], target_file: str, repo_file_path: str) -> SecurityRemediationState:
    return {
        "incident": incident,
        "target_file": target_file,
        "repo_file_path": repo_file_path,
        "original_code": "",
        "vulnerability_confirmed": False,
        "vulnerability_type": incident.get("label", "unknown"),
        "root_cause_analysis": "",
        "unsafe_findings": [],
        "fix_code": "",
        "fix_validated": False,
        "validation_errors": [],
        "iteration_count": 0,
        "pr_status": "pending",
        "pr_url": "",
        "status": "received",
    }
