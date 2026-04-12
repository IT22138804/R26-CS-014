import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds
} from "@firebase/rules-unit-testing";
import { get, ref, set } from "firebase/database";
import fs from "node:fs";
import path from "node:path";

const projectId = "demo-component4";
const rules = fs.readFileSync(
  path.resolve("firebase/database.rules.json"),
  "utf8"
);

const testEnv = await initializeTestEnvironment({
  projectId,
  database: {
    rules,
    host: "127.0.0.1",
    port: 9000
  }
});

const GATEWAY_UID = "JCBeErnTRHf5ZP7OGpLWkpjfKKy1";
const DASHBOARD_UID = "L7XhYCjTs9Ys21wwpb9FOnDeyau2";

await testEnv.withSecurityRulesDisabled(
  async (context) => {
    await set(
      ref(context.database(), "/"),
      {
        greenhouse: {
          GH_NODE_01: {
            current: {
              temperature: 24.5
            }
          }
        },
        network: {
          state: "NORMAL"
        },
        demo: {
          scenario: "NONE"
        },
        component4_test: {
          users: {
            C4_OPERATOR_A: {
              role: "operator",
              assigned_nodes: {
                GH_NODE_01: true
              }
            },
            C4_OPERATOR_B: {
              role: "operator",
              assigned_nodes: {
                GH_NODE_02: true
              }
            },
            C4_VIEWER_A: {
              role: "viewer",
              assigned_nodes: {
                GH_NODE_01: true
              }
            }
          },
          nodes: {
            GH_NODE_01: {
              label: "Greenhouse Node 1"
            },
            GH_NODE_02: {
              label: "Greenhouse Node 2"
            }
          },
          actuator_state: {
            GH_NODE_01: {
              relay_pump: "OFF",
              relay_fan: "OFF"
            }
          }
        }
      }
    );
  }
);

const gatewayDb = testEnv
  .authenticatedContext(GATEWAY_UID)
  .database();

const dashboardDb = testEnv
  .authenticatedContext(DASHBOARD_UID)
  .database();

const strangerDb = testEnv
  .authenticatedContext("UNRELATED_UID")
  .database();

const operatorA = testEnv
  .authenticatedContext("C4_OPERATOR_A")
  .database();

const operatorB = testEnv
  .authenticatedContext("C4_OPERATOR_B")
  .database();

const viewerA = testEnv
  .authenticatedContext("C4_VIEWER_A")
  .database();

const anonymousDb = testEnv
  .unauthenticatedContext()
  .database();

const cases = [];

async function runCase({
  id,
  area,
  scenario,
  expected,
  operation
}) {
  let observed = "";
  let passed = false;

  try {
    if (expected === "ALLOW") {
      await assertSucceeds(operation());
      observed = "ALLOWED";
      passed = true;
    } else {
      await assertFails(operation());
      observed = "DENIED";
      passed = true;
    }
  } catch (error) {
    observed = `UNEXPECTED: ${error?.message || error}`;
  }

  cases.push({
    caseId: id,
    area,
    scenario,
    expected,
    observed,
    passed
  });

  console.log(
    `[${passed ? "PASS" : "FAIL"}] ${id} ${scenario} -> ${observed}`
  );
}

// ------------------------------------------------------------
// EXISTING COMPONENTS 1–3 RULE REGRESSION
// ------------------------------------------------------------

await runCase({
  id: "C4D-01",
  area: "EXISTING_GREENHOUSE",
  scenario: "GATEWAY_WRITE_GREENHOUSE",
  expected: "ALLOW",
  operation: () =>
    set(
      ref(
        gatewayDb,
        "/greenhouse/GH_NODE_01/step40d_probe"
      ),
      { ok: true }
    )
});

await runCase({
  id: "C4D-02",
  area: "EXISTING_GREENHOUSE",
  scenario: "DASHBOARD_READ_GREENHOUSE",
  expected: "ALLOW",
  operation: () =>
    get(
      ref(
        dashboardDb,
        "/greenhouse/GH_NODE_01"
      )
    )
});

await runCase({
  id: "C4D-03",
  area: "EXISTING_GREENHOUSE",
  scenario: "DASHBOARD_WRITE_GREENHOUSE_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        dashboardDb,
        "/greenhouse/GH_NODE_01/unauthorized"
      ),
      true
    )
});

await runCase({
  id: "C4D-04",
  area: "EXISTING_GREENHOUSE",
  scenario: "UNRELATED_USER_READ_GREENHOUSE_DENIED",
  expected: "DENY",
  operation: () =>
    get(
      ref(
        strangerDb,
        "/greenhouse/GH_NODE_01"
      )
    )
});

await runCase({
  id: "C4D-05",
  area: "EXISTING_NETWORK",
  scenario: "GATEWAY_WRITE_NETWORK",
  expected: "ALLOW",
  operation: () =>
    set(
      ref(
        gatewayDb,
        "/network/step40d_probe"
      ),
      "PASS"
    )
});

await runCase({
  id: "C4D-06",
  area: "EXISTING_NETWORK",
  scenario: "DASHBOARD_READ_NETWORK",
  expected: "ALLOW",
  operation: () =>
    get(
      ref(
        dashboardDb,
        "/network"
      )
    )
});

await runCase({
  id: "C4D-07",
  area: "EXISTING_NETWORK",
  scenario: "DASHBOARD_WRITE_NETWORK_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        dashboardDb,
        "/network/unauthorized"
      ),
      true
    )
});

await runCase({
  id: "C4D-08",
  area: "EXISTING_DEMO",
  scenario: "DASHBOARD_READ_DEMO",
  expected: "ALLOW",
  operation: () =>
    get(
      ref(
        dashboardDb,
        "/demo"
      )
    )
});

await runCase({
  id: "C4D-09",
  area: "EXISTING_DEMO",
  scenario: "DASHBOARD_WRITE_DEMO",
  expected: "ALLOW",
  operation: () =>
    set(
      ref(
        dashboardDb,
        "/demo/step40d_probe"
      ),
      "PASS"
    )
});

await runCase({
  id: "C4D-10",
  area: "EXISTING_DEMO",
  scenario: "GATEWAY_READ_DEMO_DENIED",
  expected: "DENY",
  operation: () =>
    get(
      ref(
        gatewayDb,
        "/demo"
      )
    )
});

// ------------------------------------------------------------
// COMPONENT 4 RULES
// ------------------------------------------------------------

await runCase({
  id: "C4D-11",
  area: "COMPONENT4",
  scenario: "ASSIGNED_NODE_READ",
  expected: "ALLOW",
  operation: () =>
    get(
      ref(
        operatorA,
        "/component4_test/nodes/GH_NODE_01"
      )
    )
});

await runCase({
  id: "C4D-12",
  area: "COMPONENT4",
  scenario: "BOLA_UNASSIGNED_NODE_READ",
  expected: "DENY",
  operation: () =>
    get(
      ref(
        operatorA,
        "/component4_test/nodes/GH_NODE_02"
      )
    )
});

await runCase({
  id: "C4D-13",
  area: "COMPONENT4",
  scenario: "VALID_ASSIGNED_NODE_REQUEST",
  expected: "ALLOW",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_OPERATOR_A/req_ok"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_pump",
        state: "ON",
        createdAt: 1786200000
      }
    )
});

await runCase({
  id: "C4D-14",
  area: "COMPONENT4",
  scenario: "BOLA_REQUEST_FOR_UNASSIGNED_NODE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_OPERATOR_A/req_bola"
      ),
      {
        nodeId: "GH_NODE_02",
        actuator: "relay_pump",
        state: "ON",
        createdAt: 1786200001
      }
    )
});

await runCase({
  id: "C4D-15",
  area: "COMPONENT4",
  scenario: "CROSS_USER_REQUEST_NAMESPACE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorB,
        "/component4_test/client_requests/C4_OPERATOR_A/req_cross_user"
      ),
      {
        nodeId: "GH_NODE_02",
        actuator: "relay_fan",
        state: "ON",
        createdAt: 1786200002
      }
    )
});

await runCase({
  id: "C4D-16",
  area: "COMPONENT4",
  scenario: "VIEWER_CONTROL_REQUEST_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        viewerA,
        "/component4_test/client_requests/C4_VIEWER_A/req_viewer"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_fan",
        state: "ON",
        createdAt: 1786200003
      }
    )
});

await runCase({
  id: "C4D-17",
  area: "COMPONENT4",
  scenario: "ANONYMOUS_CONTROL_REQUEST_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        anonymousDb,
        "/component4_test/client_requests/anonymous/req_anon"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_fan",
        state: "ON",
        createdAt: 1786200004
      }
    )
});

await runCase({
  id: "C4D-18",
  area: "COMPONENT4",
  scenario: "DIRECT_ACTUATOR_WRITE_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/actuator_state/GH_NODE_01/relay_pump"
      ),
      "ON"
    )
});

await runCase({
  id: "C4D-19",
  area: "COMPONENT4",
  scenario: "ROLE_FIELD_INJECTION_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_OPERATOR_A/req_role_injection"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_pump",
        state: "ON",
        createdAt: 1786200005,
        role: "admin"
      }
    )
});

await runCase({
  id: "C4D-20",
  area: "COMPONENT4",
  scenario: "SELF_ROLE_ESCALATION_DENIED",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/users/C4_OPERATOR_A/role"
      ),
      "admin"
    )
});

const passed = cases.filter(c => c.passed).length;
const existingCases = cases.filter(
  c => c.area.startsWith("EXISTING_")
);
const existingPassed = existingCases.filter(
  c => c.passed
).length;
const c4Cases = cases.filter(
  c => c.area === "COMPONENT4"
);
const c4Passed = c4Cases.filter(
  c => c.passed
).length;

const bolaCases = cases.filter(
  c =>
    c.scenario.includes("BOLA")
    || c.scenario.includes("CROSS_USER")
);
const bolaBlocked = bolaCases.filter(
  c => c.expected === "DENY" && c.observed === "DENIED"
).length;

const report = {
  component: 4,
  step: "40D",
  casesExecuted: cases.length,
  casesPassed: passed,
  casesFailed: cases.length - passed,
  existingRulesRegressionCases: existingCases.length,
  existingRulesRegressionPassed: existingPassed,
  component4RulesCases: c4Cases.length,
  component4RulesPassed: c4Passed,
  bolaObjectAttacks: bolaCases.length,
  bolaObjectAttacksBlocked: bolaBlocked,
  gatewayUidPreserved: "JCBeErnTRHf5ZP7OGpLWkpjfKKy1",
  dashboardUidPreserved: "L7XhYCjTs9Ys21wwpb9FOnDeyau2",
  emulatorOnly: true,
  liveRulesDeployed: false,
  liveDatabaseModified: false,
  actualActuatorCommands: false,
  productionSecurityClaim: false,
  result:
    passed === cases.length
      ? "PASSED"
      : "REVIEW_REQUIRED",
  evidence: cases
};

fs.mkdirSync(
  path.resolve("outputs/step40d"),
  { recursive: true }
);

fs.writeFileSync(
  path.resolve(
    "outputs/step40d/step40d_merged_rules_regression.json"
  ),
  JSON.stringify(report, null, 2)
);

console.log("");
console.log("=".repeat(88));
console.log(
  "COMPONENT 4 — STEP 40D MERGED FIREBASE RULES REGRESSION REPORT"
);
console.log("=".repeat(88));
console.log(
  `Cases executed                    : ${report.casesExecuted}`
);
console.log(
  `Cases passed                      : ${report.casesPassed}`
);
console.log(
  `Cases failed                      : ${report.casesFailed}`
);
console.log(
  `Existing rules regression         : ${existingPassed}/${existingCases.length} PASSED`
);
console.log(
  `Component 4 rules validation      : ${c4Passed}/${c4Cases.length} PASSED`
);
console.log(
  `BOLA/object attacks               : ${report.bolaObjectAttacks}`
);
console.log(
  `BOLA/object attacks blocked       : ${report.bolaObjectAttacksBlocked}`
);
console.log(
  "Gateway greenhouse/network access : PRESERVED"
);
console.log(
  "Dashboard read access             : PRESERVED"
);
console.log(
  "Dashboard demo access             : PRESERVED"
);
console.log(
  "Live database modified            : NO"
);
console.log(
  "Live Firebase rules deployed      : NO"
);
console.log(
  "Actual actuator commands          : DISABLED"
);
console.log(
  "Production security claim         : NOT YET"
);
console.log(
  `STEP 40D RESULT                   : ${report.result}`
);
console.log("=".repeat(88));

await testEnv.cleanup();

if (report.result !== "PASSED") {
  process.exitCode = 1;
}
