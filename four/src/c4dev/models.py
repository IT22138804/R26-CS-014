from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class Decision:
    allowed: bool
    decision: str
    reason: str
    sanitized_state: str | None
    safety_override: bool
    bola_attempt: bool
    role_violation: bool
    replay_detected: bool = False
    actuator_command_sent: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
