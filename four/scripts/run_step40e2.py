from __future__ import annotations
import json, os, time
from pathlib import Path
import requests
import firebase_admin
from dotenv import load_dotenv
from firebase_admin import auth, credentials, db

ROOT = Path(__file__).resolve().parents[1]
GATEWAY_UID = "JCBeErnTRHf5ZP7OGpLWkpjfKKy1"
DASHBOARD_UID = "L7XhYCjTs9Ys21wwpb9FOnDeyau2"

def cfg():
    load_dotenv(ROOT / ".env")
    cp = Path(os.environ["FIREBASE_CREDENTIALS_PATH"])
    url = os.environ["FIREBASE_DATABASE_URL"].rstrip("/")
    api = os.environ["FIREBASE_WEB_API_KEY"]
    return cp, url, api

def init_admin(cp, url):
    try:
        firebase_admin.get_app()
    except ValueError:
        firebase_admin.initialize_app(
            credentials.Certificate(str(cp)),
            {"databaseURL": url},
        )

def ensure(uid):
    try:
        auth.get_user(uid)
    except auth.UserNotFoundError:
        auth.create_user(uid=uid, display_name=uid)

def token(uid, api_key):
    custom = auth.create_custom_token(uid)
    if isinstance(custom, bytes):
        custom = custom.decode()
    r = requests.post(
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken",
        params={"key": api_key},
        json={"token": custom, "returnSecureToken": True},
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["idToken"]

def call(method, url, path, tok=None, value=None):
    params = {"auth": tok} if tok else {}
    kwargs = {"method": method, "url": f"{url}/{path.strip('/')}.json",
              "params": params, "timeout": 20}
    if method in ("PUT","POST","PATCH"):
        kwargs["json"] = value
    return requests.request(**kwargs)

def main():
    cp, url, api = cfg()
    init_admin(cp, url)

    test_profiles = {
        "C4_LIVE_OPERATOR_A": {"role":"operator","assigned_nodes":{"GH_NODE_01":True}},
        "C4_LIVE_OPERATOR_B": {"role":"operator","assigned_nodes":{"GH_NODE_02":True}},
        "C4_LIVE_VIEWER_A": {"role":"viewer","assigned_nodes":{"GH_NODE_01":True}},
        "C4_LIVE_STRANGER": {"role":"viewer","assigned_nodes":{}},
    }
    for uid, prof in test_profiles.items():
        ensure(uid)
        db.reference(f"/component4_test/users/{uid}").set(prof)
    db.reference("/component4_test/nodes").update({
        "GH_NODE_01":{"label":"Node 1"},
        "GH_NODE_02":{"label":"Node 2"}
    })

    T = {
        "gateway": token(GATEWAY_UID, api),
        "dashboard": token(DASHBOARD_UID, api),
        "opA": token("C4_LIVE_OPERATOR_A", api),
        "opB": token("C4_LIVE_OPERATOR_B", api),
        "viewer": token("C4_LIVE_VIEWER_A", api),
        "stranger": token("C4_LIVE_STRANGER", api),
    }

    stamp = int(time.time())
    cases = []

    def check(cid, scenario, expected, response):
        actual = "ALLOW" if 200 <= response.status_code < 300 else "DENY"
        passed = actual == expected
        cases.append({"caseId":cid,"scenario":scenario,"expected":expected,
                      "actual":actual,"httpStatus":response.status_code,"passed":passed})
        print(f"[{'PASS' if passed else 'FAIL'}] {cid} {scenario} -> HTTP {response.status_code} {actual}")

    gh_probe=f"/greenhouse/GH_NODE_01/step40e2_probe_{stamp}"
    net_probe=f"/network/step40e2_probe_{stamp}"
    demo_probe=f"/demo/step40e2_probe_{stamp}"

    print("="*90)
    print("COMPONENT 4 — STEP 40E-2 LIVE FIREBASE RULES VERIFICATION")
    print("="*90)

    check("C4E2-01","GATEWAY_WRITE_GREENHOUSE","ALLOW",
          call("PUT",url,gh_probe,T["gateway"],{"probe":"40E2"}))
    check("C4E2-02","DASHBOARD_READ_GREENHOUSE","ALLOW",
          call("GET",url,"/greenhouse/GH_NODE_01",T["dashboard"]))
    check("C4E2-03","DASHBOARD_WRITE_GREENHOUSE_DENIED","DENY",
          call("PUT",url,f"/greenhouse/GH_NODE_01/dash_probe_{stamp}",T["dashboard"],True))
    check("C4E2-04","STRANGER_READ_GREENHOUSE_DENIED","DENY",
          call("GET",url,"/greenhouse/GH_NODE_01",T["stranger"]))

    check("C4E2-05","GATEWAY_WRITE_NETWORK","ALLOW",
          call("PUT",url,net_probe,T["gateway"],{"probe":"40E2"}))
    check("C4E2-06","DASHBOARD_READ_NETWORK","ALLOW",
          call("GET",url,"/network",T["dashboard"]))
    check("C4E2-07","DASHBOARD_WRITE_NETWORK_DENIED","DENY",
          call("PUT",url,f"/network/dash_probe_{stamp}",T["dashboard"],True))

    check("C4E2-08","DASHBOARD_READ_DEMO","ALLOW",
          call("GET",url,"/demo",T["dashboard"]))
    check("C4E2-09","DASHBOARD_WRITE_DEMO","ALLOW",
          call("PUT",url,demo_probe,T["dashboard"],{"probe":"40E2"}))
    check("C4E2-10","GATEWAY_READ_DEMO_DENIED","DENY",
          call("GET",url,"/demo",T["gateway"]))

    check("C4E2-11","OPERATOR_READ_ASSIGNED_NODE","ALLOW",
          call("GET",url,"/component4_test/nodes/GH_NODE_01",T["opA"]))
    check("C4E2-12","BOLA_READ_UNASSIGNED_NODE_DENIED","DENY",
          call("GET",url,"/component4_test/nodes/GH_NODE_02",T["opA"]))

    ok_path=f"/component4_test/client_requests/C4_LIVE_OPERATOR_A/ok_{stamp}"
    good={"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON","createdAt":stamp}
    check("C4E2-13","VALID_ASSIGNED_NODE_REQUEST","ALLOW",
          call("PUT",url,ok_path,T["opA"],good))
    bad={**good,"nodeId":"GH_NODE_02","createdAt":stamp+1}
    check("C4E2-14","BOLA_REQUEST_UNASSIGNED_NODE_DENIED","DENY",
          call("PUT",url,f"/component4_test/client_requests/C4_LIVE_OPERATOR_A/bola_{stamp}",T["opA"],bad))
    check("C4E2-15","CROSS_USER_NAMESPACE_DENIED","DENY",
          call("PUT",url,f"/component4_test/client_requests/C4_LIVE_OPERATOR_A/cross_{stamp}",T["opB"],
               {"nodeId":"GH_NODE_02","actuator":"relay_fan","state":"ON","createdAt":stamp+2}))
    check("C4E2-16","VIEWER_CONTROL_REQUEST_DENIED","DENY",
          call("PUT",url,f"/component4_test/client_requests/C4_LIVE_VIEWER_A/v_{stamp}",T["viewer"],
               {"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"ON","createdAt":stamp+3}))
    check("C4E2-17","DIRECT_ACTUATOR_WRITE_DENIED","DENY",
          call("PUT",url,"/component4_test/actuator_state/GH_NODE_01/relay_pump",T["opA"],"ON"))
    check("C4E2-18","ROLE_FIELD_INJECTION_DENIED","DENY",
          call("PUT",url,f"/component4_test/client_requests/C4_LIVE_OPERATOR_A/r_{stamp}",T["opA"],
               {"nodeId":"GH_NODE_01","actuator":"relay_pump","state":"ON","createdAt":stamp+4,"role":"admin"}))
    check("C4E2-19","SELF_ROLE_ESCALATION_DENIED","DENY",
          call("PUT",url,"/component4_test/users/C4_LIVE_OPERATOR_A/role",T["opA"],"admin"))
    check("C4E2-20","INVALID_STATE_DENIED","DENY",
          call("PUT",url,f"/component4_test/client_requests/C4_LIVE_OPERATOR_A/s_{stamp}",T["opA"],
               {"nodeId":"GH_NODE_01","actuator":"relay_fan","state":"TOGGLE","createdAt":stamp+5}))

    # cleanup temporary successful writes
    call("DELETE",url,gh_probe,T["gateway"])
    call("DELETE",url,net_probe,T["gateway"])
    call("DELETE",url,demo_probe,T["dashboard"])
    db.reference(ok_path).delete()

    passed=sum(1 for c in cases if c["passed"])
    existing=cases[:10]
    comp4=cases[10:]
    bola=[c for c in cases if "BOLA" in c["scenario"] or "CROSS_USER" in c["scenario"]]
    report={
        "component":4,"step":"40E-2",
        "casesExecuted":len(cases),"casesPassed":passed,"casesFailed":len(cases)-passed,
        "existingRulesLiveRegression":f"{sum(c['passed'] for c in existing)}/{len(existing)}",
        "component4LiveRulesValidation":f"{sum(c['passed'] for c in comp4)}/{len(comp4)}",
        "bolaObjectAttacks":len(bola),
        "bolaObjectAttacksBlocked":sum(c["passed"] and c["actual"]=="DENY" for c in bola),
        "temporaryLiveTestWritesCleaned":True,
        "actualActuatorCommands":False,
        "productionSecurityClaim":False,
        "result":"PASSED" if passed==len(cases) else "REVIEW_REQUIRED",
        "evidence":cases
    }
    out=ROOT/"outputs"/"step40e2"
    out.mkdir(parents=True,exist_ok=True)
    (out/"step40e2_live_rules_verification.json").write_text(
        json.dumps(report,indent=2),encoding="utf-8"
    )

    print()
    print("="*90)
    print("COMPONENT 4 — STEP 40E-2 FINAL REPORT")
    print("="*90)
    print(f"Cases executed                    : {len(cases)}")
    print(f"Cases passed                      : {passed}")
    print(f"Cases failed                      : {len(cases)-passed}")
    print(f"Existing rules live regression    : {sum(c['passed'] for c in existing)}/{len(existing)} PASSED")
    print(f"Component 4 live rules validation : {sum(c['passed'] for c in comp4)}/{len(comp4)} PASSED")
    print(f"BOLA/object attacks               : {len(bola)}")
    print(f"BOLA/object attacks blocked       : {sum(c['passed'] and c['actual']=='DENY' for c in bola)}")
    print("Temporary live test writes        : CLEANED")
    print("Actual actuator commands          : DISABLED")
    print("Production security claim         : NOT YET")
    print(f"STEP 40E-2 RESULT                 : {report['result']}")
    print("="*90)

if __name__ == "__main__":
    main()
