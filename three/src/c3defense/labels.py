from __future__ import annotations


def expected_control_label(temperature_c: float, soil_pct: float) -> str:
    fan_on = temperature_c >= 31.0
    pump_on = soil_pct <= 25.0
    if fan_on and pump_on:
        return "FAN_AND_PUMP_ON"
    if fan_on:
        return "FAN_ON"
    if pump_on:
        return "PUMP_ON"
    return "NORMAL"
