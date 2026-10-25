import {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds
} from "@firebase/rules-unit-testing";
import {
  get,
  ref,
  set
} from "firebase/database";
import fs from "node:fs";
import path from "node:path";

const projectId = "demo-component4";
const rulesPath = path.resolve(
  "firebase/database.rules.json"
);
const rules = fs.readFileSync(
  rulesPath,
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

const seed = {
  component4_test: {
    users: {
      C4_RULES_OPERATOR_A: {
        role: "operator",
        assigned_nodes: {
          GH_NODE_01: true
        }
      },
      C4_RULES_OPERATOR_B: {
        role: "operator",
        assigned_nodes: {
          GH_NODE_02: true
        }
      },
      C4_RULES_VIEWER_A: {
        role: "viewer",
        assigned_nodes: {
          GH_NODE_01: true
        }
      }
    },
    nodes: {
      GH_NODE_01: {
        temperature_c: 27,
        soil_pct: 18
      },
      GH_NODE_02: {
        temperature_c: 28,
        soil_pct: 55
      }
    },
    actuator_state: {
      GH_NODE_01: {
        relay_pump: "OFF",
        relay_fan: "OFF"
      }
    }
  }
};

await testEnv.withSecurityRulesDisabled(
  async (context) => {
    await set(
      ref(context.database(), "/"),
      seed
    );
  }
);

function dbFor(uid, token = {}) {
  return testEnv
    .authenticatedContext(uid, token)
    .database();
}

const unauthDb = testEnv
  .unauthenticatedContext()
  .database();

const cases = [];

async function runCase({
  id,
  scenario,
  expected,
  operation
}) {
  let passed = false;
  let observed = "";

  try {
    if (expected === "ALLOW") {
      await assertSucceeds(operation());
      passed = true;
      observed = "ALLOWED";
    } else {
      await assertFails(operation());
      passed = true;
      observed = "DENIED";
    }
  } catch (error) {
    passed = false;
    observed = `UNEXPECTED: ${error?.message || error}`;
  }

  cases.push({
    caseId: id,
    scenario,
    expected,
    observed,
    passed
  });

  console.log(
    `[${passed ? "PASS" : "FAIL"}] ${id} ${scenario} -> ${observed}`
  );
}

const operatorA = dbFor(
  "C4_RULES_OPERATOR_A",
  { role: "operator" }
);
const operatorB = dbFor(
  "C4_RULES_OPERATOR_B",
  { role: "operator" }
);
const viewerA = dbFor(
  "C4_RULES_VIEWER_A",
  { role: "viewer" }
);

await runCase({
  id: "C4C-01",
  scenario: "READ_ASSIGNED_NODE",
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
  id: "C4C-02",
  scenario: "BOLA_READ_UNASSIGNED_NODE",
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
  id: "C4C-03",
  scenario: "WRITE_VALID_REQUEST_FOR_ASSIGNED_NODE",
  expected: "ALLOW",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_01"
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
  id: "C4C-04",
  scenario: "BOLA_WRITE_REQUEST_FOR_UNASSIGNED_NODE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_02"
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
  id: "C4C-05",
  scenario: "WRITE_TO_ANOTHER_USERS_REQUEST_NAMESPACE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorB,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_03"
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
  id: "C4C-06",
  scenario: "VIEWER_TRIES_CONTROL_REQUEST",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        viewerA,
        "/component4_test/client_requests/C4_RULES_VIEWER_A/req_04"
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
  id: "C4C-07",
  scenario: "UNAUTHENTICATED_REQUEST_WRITE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        unauthDb,
        "/component4_test/client_requests/anonymous/req_05"
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
  id: "C4C-08",
  scenario: "DIRECT_ACTUATOR_STATE_WRITE",
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
  id: "C4C-09",
  scenario: "ROLE_FIELD_INJECTION_IN_REQUEST",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_06"
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
  id: "C4C-10",
  scenario: "INVALID_ACTUATOR_NAME",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_07"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_heater",
        state: "ON",
        createdAt: 1786200006
      }
    )
});

await runCase({
  id: "C4C-11",
  scenario: "INVALID_COMMAND_STATE",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/client_requests/C4_RULES_OPERATOR_A/req_08"
      ),
      {
        nodeId: "GH_NODE_01",
        actuator: "relay_fan",
        state: "TOGGLE",
        createdAt: 1786200007
      }
    )
});

await runCase({
  id: "C4C-12",
  scenario: "USER_CANNOT_EDIT_SERVER_ROLE_OR_OWNERSHIP",
  expected: "DENY",
  operation: () =>
    set(
      ref(
        operatorA,
        "/component4_test/users/C4_RULES_OPERATOR_A/role"
      ),
      "admin"
    )
});

const passed = cases.filter(
  (item) => item.passed
).length;

const bolaCases = cases.filter(
  (item) =>
    item.scenario.includes("BOLA")
    || item.scenario.includes("ANOTHER_USERS")
);

const bolaBlocked = bolaCases.filter(
  (item) =>
    item.expected === "DENY"
    && item.observed === "DENIED"
).length;

const report = {
  component: 4,
  step: "40C",
  casesExecuted: cases.length,
  casesPassed: passed,
  casesFailed: cases.length - passed,
  bolaAttempts: bolaCases.length,
  bolaAttemptsBlocked: bolaBlocked,
  assignedNodeReadAllowed:
    cases.find(
      (item) =>
        item.scenario === "READ_ASSIGNED_NODE"
    )?.passed === true,
  directActuatorWriteBlocked:
    cases.find(
      (item) =>
        item.scenario === "DIRECT_ACTUATOR_STATE_WRITE"
    )?.passed === true,
  roleFieldInjectionBlocked:
    cases.find(
      (item) =>
        item.scenario === "ROLE_FIELD_INJECTION_IN_REQUEST"
    )?.passed === true,
  userProfileEscalationBlocked:
    cases.find(
      (item) =>
        item.scenario === "USER_CANNOT_EDIT_SERVER_ROLE_OR_OWNERSHIP"
    )?.passed === true,
  emulatorOnly: true,
  liveRulesDeployed: false,
  existingComponentsRulesChanged: false,
  actualActuatorCommands: false,
  productionSecurityClaim: false,
  result:
    passed === cases.length
      ? "PASSED"
      : "REVIEW_REQUIRED",
  evidence: cases
};

fs.mkdirSync(
  path.resolve("outputs/step40c"),
  { recursive: true }
);
fs.writeFileSync(
  path.resolve(
    "outputs/step40c/step40c_rules_report.json"
  ),
  JSON.stringify(report, null, 2)
);

console.log("");
console.log("=".repeat(86));
console.log(
  "COMPONENT 4 — STEP 40C FIREBASE RULES EMULATOR REPORT"
);
console.log("=".repeat(86));
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
  `BOLA/object attacks               : ${report.bolaAttempts}`
);
console.log(
  `BOLA/object attacks blocked       : ${report.bolaAttemptsBlocked}`
);
console.log(
  `Assigned-node read                : ${report.assignedNodeReadAllowed ? "ALLOWED" : "FAILED"}`
);
console.log(
  `Direct actuator write             : ${report.directActuatorWriteBlocked ? "BLOCKED" : "FAILED"}`
);
console.log(
  `Role-field injection              : ${report.roleFieldInjectionBlocked ? "BLOCKED" : "FAILED"}`
);
console.log(
  `User role/ownership self-edit     : ${report.userProfileEscalationBlocked ? "BLOCKED" : "FAILED"}`
);
console.log(
  "Firebase Rules environment        : LOCAL EMULATOR"
);
console.log(
  "Live Firebase rules deployed      : NO"
);
console.log(
  "Components 1–3 rules changed      : NO"
);
console.log(
  "Actual actuator commands          : DISABLED"
);
console.log(
  "Production security claim         : NOT YET"
);
console.log(
  `STEP 40C RESULT                   : ${report.result}`
);
console.log("=".repeat(86));

await testEnv.cleanup();

if (report.result !== "PASSED") {
  process.exitCode = 1;
}
