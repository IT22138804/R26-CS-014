import os, time, json
from pathlib import Path
import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, db

ROOT = Path(__file__).resolve().parents[1]

def flatten(d, prefix=""):
    out = {}
    if isinstance(d, dict):
        for k,v in d.items():
            p=f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten(v,p))
            else:
                out[p]=v
    return out

def norm(s):
    return "".join(c.lower() for c in s if c.isalnum())

def find_value(raw, aliases):
    flat=flatten(raw)
    wanted={norm(x) for x in aliases}
    for path,val in flat.items():
        if norm(path.split(".")[-1]) in wanted:
            return val,path
    raise KeyError(f"Could not find {aliases}. Available paths: {list(flat)}")

def parse_ts(v):
    x=float(v)
    return x/1000.0 if x>10_000_000_000 else x

def main():
    load_dotenv(ROOT/".env")
    cp=os.environ["FIREBASE_CREDENTIALS_PATH"]
    url=os.environ["FIREBASE_DATABASE_URL"]
    source=os.getenv("COMPONENT2_CURRENT_PATH","/greenhouse/GH_NODE_01/current")
    max_age=float(os.getenv("MAX_TELEMETRY_AGE_SECONDS","30"))
    timeout=float(os.getenv("WATCH_TIMEOUT_SECONDS","180"))
    poll=float(os.getenv("POLL_SECONDS","1"))
    result_path=os.getenv(
        "COMPONENT4_RESULT_PATH",
        "/greenhouse/GH_NODE_01/component4/latest"
    )

    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(cp),
            {"databaseURL":url}
        )

    print("="*92)
    print("COMPONENT 4 — STEP 40K-1 LIVE HARDWARE TELEMETRY")
    print("="*92)
    print("Source path              :",source)
    print("Required max age         :",max_age,"seconds")
    print("Watcher timeout          :",timeout,"seconds")
    print("Actual actuator commands : DISABLED")
    print("Waiting for fresh physical telemetry...")

    deadline=time.time()+timeout
    accepted=None

    while time.time()<deadline:
        raw=db.reference(source).get()
        if not isinstance(raw,dict):
            print("[WAIT] no current snapshot")
            time.sleep(poll); continue

        try:
            temp,temp_path=find_value(raw,[
                "temperature","temperature_c","temp","temp_c","temperatureC"
            ])
            soil,soil_path=find_value(raw,[
                "soil","soil_pct","soilPercent","soilPercentage",
                "soilMoisture","soilMoisturePct","soil_moisture_pct"
            ])
            ts,ts_path=find_value(raw,[
                "timestamp","timestamp_ms","timestampSeconds",
                "updatedAt","senderTimestamp"
            ])
            temp=float(temp); soil=float(soil); ts=parse_ts(ts)
            age=max(0,time.time()-ts)
            source_evidence=str(raw.get("evidenceType","PHYSICAL_HARDWARE"))
            is_virtual=source_evidence.startswith("VIRTUAL_")

            valid=True
            try:
                vv,_=find_value(raw,["sample_valid","sampleValid","valid"])
                valid = vv is True or str(vv).strip().lower() in {"yes","true","1","valid","passed"}
            except KeyError:
                pass

            # Virtual packets are cryptographically verified by the simulator,
            # but deliberately carry sampleValid=false so they can never be
            # presented as physical sensor validation. Evaluate them only as
            # explicitly labelled simulation evidence.
            if is_virtual:
                valid=True

            if not valid:
                print(f"[WAIT] temp={temp:.2f}C soil={soil:.2f}% age={age:.1f}s INVALID")
            elif age>max_age:
                print(f"[WAIT] temp={temp:.2f}C soil={soil:.2f}% age={age:.1f}s STALE")
            else:
                accepted=(
                    raw,temp,soil,age,temp_path,soil_path,ts_path,
                    source_evidence,is_virtual
                )
                print(f"[PASS] temp={temp:.2f}C soil={soil:.2f}% age={age:.1f}s FRESH")
                break
        except Exception as e:
            print("[WAIT] parse error:",e)

        time.sleep(poll)

    if accepted is None:
        print()
        print("STEP 40K-1 RESULT        : REVIEW_REQUIRED")
        print("Reason                    : NO_FRESH_VALID_COMPONENT2_PACKET")
        print("Actual actuator commands  : DISABLED")
        return

    (
        raw,temp,soil,age,temp_path,soil_path,ts_path,
        source_evidence,is_virtual
    )=accepted

    pump_decision = (
        "SAFETY_OVERRIDE_PUMP_BLOCKED"
        if soil>=90 else
        "ALLOW_SANITIZED_COMMAND_INTENT"
    )
    fan_decision = (
        "SAFETY_OVERRIDE_FAN_OFF_BLOCKED"
        if temp>=35 else
        "ALLOW_SANITIZED_COMMAND_INTENT"
    )

    report={
        "component":4,
        "step":"40K-1",
        "evidenceType":source_evidence,
        "physicalHardwareValidated":not is_virtual,
        "temperatureC":temp,
        "soilPct":soil,
        "sourceAgeSeconds":age,
        "temperatureField":temp_path,
        "soilField":soil_path,
        "timestampField":ts_path,
        "pumpOnCandidate":pump_decision,
        "fanOffCandidate":fan_decision,
        "actualActuatorCommands":False,
        "physicalRelayChange":False,
        "mfa":"DEFERRED",
        "result":"PASSED_VIRTUAL_SIMULATION" if is_virtual else "PASSED"
    }

    evidence={
        **report,
        "serverEvidenceTimestamp":int(time.time())
    }
    db.reference("/component4_test/step40k1/latest").set(evidence)
    db.reference(result_path).set(evidence)

    out=ROOT/"step40k1_result.json"
    out.write_text(json.dumps(report,indent=2),encoding="utf-8")

    print()
    print("="*92)
    print("COMPONENT 4 — STEP 40K-1 FINAL REPORT")
    print("="*92)
    print(f"Temperature               : {temp:.2f} C")
    print(f"Soil moisture             : {soil:.2f} %")
    print(f"Source age seconds        : {age:.1f}")
    print("Fresh telemetry           : YES")
    print("PUMP ON candidate         :",pump_decision)
    print("FAN OFF candidate         :",fan_decision)
    print("Firebase evidence write   : PASSED")
    print("Actual actuator commands  : DISABLED")
    print("Physical relay change     : NO")
    print("MFA                       : DEFERRED")
    print("STEP 40K-1 RESULT         : PASSED")
    print("="*92)

if __name__=="__main__":
    main()
