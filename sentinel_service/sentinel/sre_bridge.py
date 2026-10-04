"""Bounded HTTP handoff from Sentinel to the SRE remediation service."""
from __future__ import annotations

import httpx


class SREBridge:
    def __init__(self, url: str, token: str, timeout_seconds: float = 180.0):
        self.url = url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds
        if not self.url.startswith(("http://127.0.0.1:", "http://localhost:")):
            raise ValueError("SRE bridge v1 must use a local loopback HTTP address")
        if len(self.token) < 32:
            raise ValueError("SRE_BRIDGE_TOKEN must be at least 32 characters")

    async def __call__(self, incident: dict) -> dict:
        payload = {
            "incident_id": incident["id"],
            "label": incident["label"],
            "source_ip": incident["source_ip"],
            "path": incident["path"],
            "evidence": incident.get("evidence", {}),
            "explanation": incident.get("explanation", ""),
            "sentinel_status": incident.get("status", "unknown"),
            "origin": incident.get("origin", "gateway"),
            "created": incident.get("created"),
            "completed": incident.get("sentinel_completed"),
            "sentinel_duration_ms": incident.get("sentinel_duration_ms"),
        }
        async with httpx.AsyncClient(trust_env=False, timeout=self.timeout_seconds) as client:
            response = await client.post(
                self.url + "/remediate",
                json=payload,
                headers={"X-Bridge-Token": self.token},
            )
            response.raise_for_status()
            return response.json()
