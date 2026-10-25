"""Reproducible controlled contract validation; never physical evidence."""
from __future__ import annotations
import hashlib
import math
import random
import time


def run_validation(guard, root, request_id):
    rng = random.Random(3911)
    cases = []
    def add(name, kind, temperature=26., humidity=62., light=18000., soil=54., **changes):
        record = dict(temperature_c=temperature, humidity_pct=humidity, light_lux=light,
                      soil_raw=2486., soil_pct=soil, packet_interval_ms=8000.)
        record.update(changes)
        cases.append((name, kind, record))
    for i in range(15):
        add(f"exact_{i}", "attack", rng.uniform(31.46,31.54), light=rng.uniform(.01,.19))
        add(f"jitter_{i}", "attack", rng.uniform(31.57,31.74), light=rng.uniform(.3,3.4))
        add(f"correlation_{i}", "attack", rng.uniform(30.9,32.3), rng.uniform(54,64), rng.uniform(3.6,8.4), rng.uniform(46,54))
        add(f"clean_day_{i}", "clean", rng.uniform(20,30), light=rng.uniform(10000,40000))
        add(f"clean_dark_{i}", "clean", rng.uniform(18,27), rng.uniform(70,90), rng.uniform(0,.2))
        add(f"clean_hot_{i}", "clean", rng.uniform(32,38), light=rng.uniform(18000,40000))
    for temperature, light in [(31.45,.2),(31.55,.2),(31.25,3.5),(31.75,3.5)]:
        add(f"boundary_{temperature}_{light}", "attack", temperature, light=light)
    for field, value in [("humidity_pct",101), ("light_lux",-1), ("soil_pct",101),
                         ("packet_interval_ms",0), ("temperature_c",float("nan")),
                         ("temperature_c","bad-number"), ("temperature_c",None)]:
        add(f"invalid_{field}_{str(value)}", "invalid", **{field:value})
    add("missing_temperature", "invalid")
    cases[-1][2].pop("temperature_c")
    rows = {}; tp=tn=fp=fn=errors=0
    times=[]
    for index, (name, kind, record) in enumerate(cases):
        record["record_id"] = f"VALIDATION-{request_id}-{index}"
        started=time.perf_counter()
        try:
            actual=guard.inspect(record).to_dict()
            duration=(time.perf_counter()-started)*1000
            times.append(duration)
            # Separate policy oracle: do not call the production label function.
            if kind == "invalid":
                checks={"failClosed": actual["quarantine"] is True and actual["final_action"] == "SAFE_FAIL_CLOSED",
                        "modelSkipped": actual["model_prediction"] == "NOT_EXECUTED"}
            else:
                fan=record["temperature_c"]>=31; pump=record["soil_pct"]<=25
                expected="FAN_AND_PUMP_ON" if fan and pump else "FAN_ON" if fan else "PUMP_ON" if pump else "NORMAL"
                predicted=bool(actual["quarantine"])
                if kind=="attack": tp+=int(predicted); fn+=int(not predicted)
                else: fp+=int(predicted); tn+=int(not predicted)
                checks={"expectedContainment": predicted == (kind=="attack"),
                        "safeActionMatchesPolicy": actual["final_action"] == expected,
                        "forwardingMatchesDecision": actual["forwarding"] == ("QUARANTINE_ONLY" if predicted else "ALLOWED"),
                        "fallbackUsedWhenQuarantined": not predicted or actual["final_action"] == actual["deterministic_fallback"]}
            row={"name":name,"kind":kind,"input":record,"observed":actual,"checks":checks,
                 "passed":all(checks.values()),"runtimeMs":duration}
        except Exception as error:
            errors+=1
            row={"name":name,"kind":kind,"input":record,"passed":False,
                 "error":type(error).__name__,"checks":{"returnedFailClosedDecision":False}}
        # Firebase JSON must not contain NaN/Infinity.
        row["input"]={k: "NON_FINITE_TEST_VALUE" if isinstance(v,float) and not math.isfinite(v) else v for k,v in record.items()}
        rows[f"case_{index:03d}"]=row
    artifact_hashes={}
    for relative in ["outputs/step39d/sanitized_control_model.joblib","outputs/step39c/activation_cluster_model.joblib"]:
        artifact_hashes[relative.replace('/','_').replace('.','_')]=hashlib.sha256((root/relative).read_bytes()).hexdigest()
    passed=sum(row["passed"] for row in rows.values())
    summary={"requestId":request_id,"casesExecuted":len(rows),"passed":passed,"failed":len(rows)-passed,
             "result":"PASSED_CONTROLLED_CONTRACT" if passed==len(rows) else "REVIEW_REQUIRED",
             "truePositive":tp,"trueNegative":tn,"falsePositive":fp,"falseNegative":fn,"exceptions":errors,
             "attackDetectionRate":tp/(tp+fn) if tp+fn else None,
             "cleanFalsePositiveRate":fp/(fp+tn) if fp+tn else None,
             "meanRuntimeMs":sum(times)/len(times) if times else None,
             "maxRuntimeMs":max(times) if times else None,"seed":3911,"artifactHashes":artifact_hashes,
             "timestamp":int(time.time()),"evidenceType":"CONTROLLED_REAL_COMPONENT3_RUNTIME",
             "physicalMeasurementClaim":False,"independentDatasetClaim":False,"actuatorCommandSent":False,
             "limitations":"Synthetic configured-pattern contract tests; not unseen-attack accuracy, training-poisoning resistance or end-to-end actuator enforcement."}
    return {"summary":summary,"cases":rows}
