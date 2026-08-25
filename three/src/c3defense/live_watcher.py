from __future__ import annotations
from dataclasses import dataclass
from typing import Any

ALLOWED_LIVE_SYSTEM_STATES={"NORMAL","ACTIVE","RUNNING","SECURE_ACTIVE","SECURE_TELEMETRY_ACTIVE"}

@dataclass(frozen=True)
class PacketIdentity:
    session_id:str
    sequence:str
    timestamp:str
    @property
    def key(self)->str:
        return f"{self.session_id}|{self.sequence}|{self.timestamp}"

def packet_identity(current:dict[str,Any])->PacketIdentity:
    return PacketIdentity(str(current.get("sessionId","NOSESSION")),str(current.get("sequence","NOSEQ")),str(current.get("timestamp","NOTIMESTAMP")))

def is_new_packet(current:dict[str,Any],seen_keys:set[str])->bool:
    return packet_identity(current).key not in seen_keys

def is_live_operational_state(system_state:Any)->bool:
    value=str(system_state or "").strip().upper()
    if not value or any(word in value for word in ("LOCKDOWN","REVOKED","BLOCKED")):
        return False
    return value in ALLOWED_LIVE_SYSTEM_STATES

def live_packet_passed(result:dict[str,Any])->tuple[bool,list[str]]:
    failures=[]
    source=result.get("source",{})
    mapping=result.get("mapping",{})
    integration=result.get("integration",{})
    if source.get("freshness")!="FRESH": failures.append("SOURCE_NOT_FRESH")
    if not source.get("sampleValid"): failures.append("SAMPLE_NOT_VALID")
    if not source.get("securityValid"): failures.append("COMPONENT2_SECURITY_NOT_VALID")
    if mapping.get("status")!="PASSED": failures.append("MAPPING_NOT_PASSED")
    if result.get("runtimeGuard") is None: failures.append("RUNTIME_GUARD_NOT_EXECUTED")
    if integration.get("actuatorCommandSent") is not False: failures.append("ACTUATOR_BOUNDARY_FAILED")
    if integration.get("decision") not in {"ALLOW_SANITIZED_AI_ANALYSIS_ONLY","QUARANTINE_REAL_TELEMETRY_AND_FALLBACK"}:
        failures.append("INVALID_LIVE_INTEGRATION_DECISION")
    return not failures,failures
