"""HTTP bridge service that lets Sentinel request defensive source remediation."""
from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from config import settings
from security_graph import security_graph
from security_state import create_security_state

ROOT = Path(__file__).resolve().parent


class SentinelIncident(BaseModel):
    incident_id: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=80)
    source_ip: str = Field(min_length=1, max_length=80)
    path: str = Field(min_length=1, max_length=2048)
    evidence: dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(default="", max_length=5000)
    sentinel_status: str = Field(default="unknown", max_length=80)
    origin: str = Field(default="gateway", max_length=80)
    created: float | None = None
    completed: float | None = None
    sentinel_duration_ms: float | None = None


app = FastAPI(title="Self-Healing Security SRE Remediation API", docs_url=None, redoc_url=None)


def bridge_token() -> str:
    return os.getenv("BRIDGE_TOKEN", "")


def require_bridge_token(x_bridge_token: str = Header(default="")) -> None:
    expected = bridge_token()
    if len(expected) < 32:
        raise HTTPException(503, "BRIDGE_TOKEN is not securely configured")
    if not secrets.compare_digest(x_bridge_token, expected):
        raise HTTPException(401, "Invalid bridge token")


@app.get("/health")
def health():
    return {
        "service": "sre-remediation",
        "status": "running",
        "llm_provider": settings.llm_provider,
    }


@app.post("/remediate", dependencies=[Depends(require_bridge_token)])
def remediate(incident: SentinelIncident):
    started = time.time()

    # In v1 only SQL incidents enter source-code remediation. Brute force and
    # flood incidents remain Sentinel gateway mitigations unless separate source
    # evidence is added later.
    if incident.label != "sql_injection":
        return {
            "incident_id": incident.incident_id,
            "status": "no_code_change_required",
            "reason": "This incident type is handled by Sentinel containment/monitoring in v1.",
            "duration_ms": round((time.time() - started) * 1000, 1),
        }

    configured_target = os.getenv(
        "SECURITY_TARGET_FILE",
        str((ROOT.parent / "sentinel_service" / "kali_lab" / "unsafe_demo.py").resolve()),
    )
    target_path = Path(configured_target)
    if not target_path.is_absolute():
        target_path = (ROOT / target_path).resolve()
    target_file = str(target_path)
    repo_file_path = os.getenv(
        "SECURITY_TARGET_REPO_PATH",
        "sentinel_service/kali_lab/unsafe_demo.py",
    )

    payload = incident.model_dump()
    initial = create_security_state(payload, target_file, repo_file_path)
    final = security_graph.invoke(initial)

    return {
        "incident_id": incident.incident_id,
        "status": final.get("status", "completed"),
        "vulnerability_confirmed": final.get("vulnerability_confirmed", False),
        "root_cause_analysis": final.get("root_cause_analysis", ""),
        "unsafe_findings": final.get("unsafe_findings", []),
        "target_file": repo_file_path,
        "fix_validated": final.get("fix_validated", False),
        "validation_errors": final.get("validation_errors", []),
        "pr_status": final.get("pr_status", "not_created"),
        "pr_url": final.get("pr_url", ""),
        "duration_ms": round((time.time() - started) * 1000, 1),
    }


if __name__ == "__main__":
    port = int(os.getenv("SECURITY_API_PORT", "8101"))
    uvicorn.run("security_service:app", host="127.0.0.1", port=port, reload=False, log_level="info")
