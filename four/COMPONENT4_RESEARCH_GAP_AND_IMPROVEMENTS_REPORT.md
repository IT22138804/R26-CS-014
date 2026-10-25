# Component 4 Research Gap and Improvements Report

## Project Title

**Secure Mobile-Based Monitoring and Safety-Aware Actuator Control for an IoT Smart Greenhouse**

## 1. Component Overview

Component 4 provides the secure user-facing and decision-support layer of the smart-greenhouse system. It combines a Flutter mobile application, Firebase Authentication, role- and node-based access control, server-side authorization, command validation, environmental safety rules, replay protection, and audit records. It receives greenhouse telemetry produced by the earlier components and prepares safe actuator command intents for the pump and fan.

The purpose of this component is not simply to add remote ON/OFF buttons. Its purpose is to ensure that a command is accepted only when the user is authenticated, has the correct role, is assigned to the requested greenhouse node, submits a permitted command, and the latest trustworthy environmental data indicate that the action is safe.

## 2. Background and Past Research Gap

Past smart-greenhouse studies have successfully demonstrated remote sensing, cloud dashboards, mobile monitoring, irrigation automation, and rule-based environmental control. For example, SAgric-IoT integrates greenhouse monitoring with web/mobile access and protects sensor communication using IEEE 802.15.4 security mechanisms. However, protecting network frames does not by itself demonstrate fine-grained authorization for each user, greenhouse node, and actuator request.

Recent reviews show that security remains a separate and insufficiently mature concern in smart agriculture. A 2025 systematic literature review analysed 58 publications and identified continuing needs involving cyberattack detection, security frameworks, case-study evaluation, and practical adoption. A review of IoT greenhouse technology similarly notes the need to monitor, control, and manage greenhouse parameters securely. These findings indicate a practical integration gap: monitoring and automation features are common, while end-to-end, application-level protection of remote actuator commands is less consistently demonstrated.

This project addresses that integration gap through a defence-in-depth command path. Authentication alone is not treated as authorization, and authorization alone is not treated as proof that a command is environmentally safe.

## 3. Direct Comparison with Previous Research

The following table compares the main focus reported by selected previous studies with the specific improvement made in this research. A limitation in this table means that the feature was not the paper's main demonstrated contribution; it does not mean that the entire earlier system was insecure.

| Previous research | Main achievement of the previous research | Gap relative to this research | Improvement in this research (Component 4) |
|---|---|---|---|
| **SAgric-IoT: An IoT-Based Platform and Deep Learning for Greenhouse Monitoring** (Zamora-Izquierdo et al., 2023) | Integrated environmental monitoring, automatic irrigation/fertilization, early disease detection using a CNN, remote web/mobile access, and communication protection for sensor nodes. | Its primary contributions are monitoring, automation, disease detection, and device-communication security. The paper does not make per-user, per-greenhouse-node authorization and replay-safe human actuator requests its central evaluated contribution. | Adds Firebase user authentication, server-side roles, `assigned_nodes` object authorization, command allowlisting, duplicate-request rejection, and structured audit decisions for mobile actuator requests. |
| **SGF-MD: Behavior Rule Specification-based Distributed Misbehavior Detection of Embedded IoT Devices in a Closed-Loop Smart Greenhouse Farming System** (2020) | Proposed lightweight, distributed detection of misbehaving embedded devices in a closed-loop greenhouse system. | Concentrates on detecting compromised or misbehaving IoT devices. It does not primarily evaluate whether an authenticated mobile user is allowed to control a particular greenhouse node or whether a repeated user command is rejected. | Extends protection to the application/user boundary through role verification, BOLA/IDOR prevention, node ownership checks, replay/idempotency protection, and user-linked audit evidence. |
| **Design and Implementation of Intelligent Monitoring System for Agricultural Environment in IoT** (2023) | Combined sensors, actuators, wireless communication, and a cloud platform to implement greenhouse monitoring and control. | Demonstrates functional integration, but functional connectivity alone does not establish least-privilege authorization or safe handling of manipulated, duplicated, or stale-data-dependent commands. | Introduces a defence-in-depth decision pipeline that rechecks identity, role, node assignment, schema, telemetry trust, and environmental safety before creating a command intent. |
| **An Open IoT-Based Framework for Feedback Control of Photosynthetic Activities** (2021) | Provided an open API/resource framework through which web and mobile clients can obtain sensor data and control environmental parameters. | Openness and API-based control improve interoperability, but also make fine-grained authorization and request validation important. Per-node BOLA testing and replay-safe actuation are not its main reported contribution. | Restricts each user to server-assigned nodes and permitted roles, allowlists commands, rejects duplicate request IDs, and separates sanitized intent from physical dispatch. |
| **Cybersecurity in Smart Agriculture: A Systematic Literature Review** (Campoverde-Molina & Luján-Mora, 2025) | Synthesized 58 studies covering threats, attacks, intrusion detection, frameworks, models, and cybersecurity case studies in smart agriculture. | Identifies a broad need for cybersecurity adoption and evaluated case studies, but a literature review does not implement an end-to-end secure greenhouse actuator workflow. | Converts broad cybersecurity recommendations into an implemented and tested mobile-to-backend policy path with authentication, authorization, environmental interlocks, replay resistance, and audit records. |
| **Technologies, Protocols, and Applications of IoT in Greenhouse Farming: A Survey of Recent Advances** (2025) | Classified greenhouse IoT architectures, protocols, cloud/fog technologies, monitoring, control, tracking, prediction, challenges, and future directions. | Shows the breadth of greenhouse technology and the need for secure management, but does not provide a project-specific enforcement mechanism for human actuator commands. | Supplies a concrete enforcement mechanism and test evidence for role/node authorization, safe command sanitization, stale-telemetry rejection, and controlled dispatch. |

### 3.1 Summary of the Research Improvement

Previous research has largely answered questions such as **how to collect greenhouse data, automate irrigation, detect disease or device anomalies, and provide remote monitoring**. This research addresses a different but complementary question:

> How can a remote user's actuator request be securely authorized, checked against trustworthy environmental data, protected from replay, and recorded before it is allowed to reach greenhouse hardware?

The main improvement is therefore an integrated **secure and safety-aware actuator authorization pipeline**, not merely another monitoring dashboard. The following features form the improvement:

- authentication of the mobile user;
- least-privilege role-based access control;
- per-node object-level authorization to prevent BOLA/IDOR attacks;
- server-side revalidation instead of trusting the mobile client;
- command and state allowlisting;
- fail-closed rejection of stale or invalid telemetry;
- environmental safety overrides for pump and fan commands;
- replay/idempotency protection using unique request identifiers;
- structured audit evidence; and
- separation of approved command intent from final physical dispatch.

### 3.2 Detailed Research-Gap and Implementation Table

| No. | Area | Limitation or gap in past research/systems | Improvement introduced in Component 4 | Implementation evidence in this project | Expected benefit | Current status |
|---:|---|---|---|---|---|---|
| 1 | User authentication | Some greenhouse prototypes emphasize sensing, connectivity, and control functions, while application-user identity protection receives less implementation detail. A login alone may also be mistaken for complete command security. | Firebase email/password authentication is used, Firebase auth state is the identity source, and refreshed ID tokens are stored using secure device storage. Passwords are not stored locally. | `lib/screens/login_screen.dart`, `lib/screens/auth_gate.dart`, and `lib/services/secure_session_store.dart` | Reduces anonymous access, insecure local credential storage, and reliance on an unverified client session. | **Software validated**; MFA is deferred. |
| 2 | Role-based control | A basic remote-control application may expose the same controls to every authenticated user. | Component 4 separates `viewer`, `operator`, `manager`, and `admin` roles. Viewers can view permitted data, whereas actuator control is restricted to authorized control roles. | `src/c4security/policy.py` and `lib/models/user_access_profile.dart` | Supports least privilege and reduces accidental or malicious control by read-only users. | **Software validated.** |
| 3 | Object-level authorization (BOLA/IDOR) | Role checks alone do not stop an authorized user from changing a device/node identifier and attempting to control another user's greenhouse node. This object-level authorization issue is frequently missed in simple IoT dashboards. | Every request is checked against the authenticated user's server-side `assigned_nodes` record. Unauthorized node access is explicitly classified as a BOLA attempt and denied. | `src/c4security/engine.py`, `src/c4security/policy.py`, Firebase rules, and Step 40B test evidence | Prevents horizontal privilege escalation between greenhouse nodes or owners. | **Validated with live Firebase rules and attack tests.** |
| 4 | Trust in client-provided data | Client-side validation can be bypassed by a modified mobile app, direct API call, or manipulated request. | Identity, role, node assignment, command schema, and safety conditions are rechecked in the backend/security layer. The client-side guard is only defence in depth. | `src/c4security/engine.py`, `src/c4dev/processor.py`, and Firebase rules | Keeps the final decision outside the untrusted mobile client and reduces request tampering risk. | **Software validated.** |
| 5 | Unsafe actuator commands | Earlier monitoring/control solutions may provide direct actuator toggling or threshold automation without showing that each manual request is checked against authoritative environmental conditions. | Component 4 applies deterministic safety interlocks: pump ON is blocked when soil moisture is at least 90%, and fan OFF is blocked when temperature is at least 35 °C. | `src/c4_backend/engine.py` and `src/c4security/policy.py` | Helps prevent overwatering and prevents cooling from being disabled during high temperature. | **Logic validated** using controlled and recorded telemetry; final physical relay validation is deferred. |
| 6 | Stale or invalid telemetry | A command may be logically valid but unsafe when its supporting sensor data are missing, malformed, or too old. Many simple systems display the last value without proving that it is fresh enough for control. | The decision pipeline rejects unsafe decisions when telemetry is stale or invalid and records `SAFE_FAIL_CLOSED_STALE_OR_INVALID_TELEMETRY`. | `outputs/step40g3/step40g3_real_component2_safety.json` | Avoids treating an old dashboard value as current physical evidence. | **Fail-closed behavior demonstrated**; fresh live-hardware validation is deferred. |
| 7 | Replay and duplicate requests | Repeated taps, retries, delayed messages, or a replay attack can cause the same actuator request to be processed more than once. | A unique request identifier and idempotency check reject duplicate requests, allowing only one pending-dispatch record. | `scripts/run_step40h2_replay_audit.py`, `tests/test_development_completion.py`, and `outputs/step40h2_replay_audit.json` | Reduces duplicate actuation and provides deterministic behavior during network retries. | **Software validated.** |
| 8 | Input and command scope | Free-form actuator names and states expand the attack surface and can trigger unexpected backend behavior. | Only `relay_pump` and `relay_fan`, with `ON` or `OFF` states, are allowlisted; invalid or unhandled requests fail closed. | `src/c4security/engine.py` and `src/c4_backend/engine.py` | Reduces injection-like misuse, malformed commands, and unsafe undefined behavior. | **Software validated.** |
| 9 | Auditability | A conventional dashboard may show a success/failure message without retaining structured evidence explaining who requested what and why it was accepted or rejected. | The pipeline produces decision records containing user, role, device, requested and sanitized state, BOLA flag, safety override, decision, and reason. | Step 40 output JSON files and the immutable-style audit stage in the offline pipeline | Supports incident investigation, test reproducibility, accountability, and research evaluation. | **Software validated.** |
| 10 | Separation of request and physical actuation | Direct cloud-to-relay control can allow a UI action to reach hardware before all checks complete. | Authorized requests become sanitized `pending_dispatch` intents only after the full policy pipeline. Physical dispatch is kept as a separate integration stage. | `src/c4dev/processor.py` and `outputs/step40h1_offline_pipeline.json` | Creates a controlled boundary between user intent, security/safety decisions, and hardware execution. | **Pipeline validated**; ESP32 dispatch is deferred. |
| 11 | Honest operational readiness | Prototype results are sometimes generalized into production-readiness claims without testing deployment scale, physical behavior, MFA, or adverse operating conditions. | Component 4 records software readiness separately from final component readiness and explicitly identifies deferred tests. | `outputs/step40j1_software_development_readiness.json` and `FINAL_HARDWARE_INTEGRATION_LATER.md` | Improves scientific validity by preventing untested capabilities from being reported as completed. | **Software development passed; final production-security claim not yet made.** |

## 4. Main Novel Improvement

The principal improvement is the integration of **identity security, object-level authorization, environmental safety, replay resistance, and auditability into one actuator-command decision path**. Earlier smart-greenhouse work commonly demonstrates one or more of monitoring, connectivity security, mobile access, or automated control. Component 4 focuses on the boundary at which a human user's remote request could cause a physical action.

The decision sequence is:

1. Verify the Firebase-authenticated identity.
2. Load the authoritative server-side user profile.
3. confirm that the token role matches the stored role.
4. Confirm that the requested greenhouse node is assigned to the user.
5. Confirm that the role permits actuator control.
6. Allowlist and sanitize the actuator and requested state.
7. Confirm that authoritative telemetry is valid and fresh.
8. Apply environmental safety interlocks.
9. Reject a duplicate request identifier.
10. Record an auditable decision and, only if allowed, create a pending-dispatch intent.

This sequence follows a zero-trust principle: no command is trusted merely because it originated from the official application or from an authenticated account.

## 5. Research Contribution

Component 4 contributes a practical security architecture for remote smart-greenhouse control in which:

- authorization is evaluated at both role and individual-node level;
- a valid identity is necessary but not sufficient to operate an actuator;
- safety decisions use authoritative telemetry rather than values supplied by the client;
- stale or invalid telemetry causes a fail-closed result;
- replayed command identifiers are rejected;
- safe, sanitized intent is separated from physical execution; and
- every decision produces structured evidence suitable for later evaluation.

Therefore, the component's contribution is not a new authentication algorithm or a new greenhouse-control algorithm by itself. Its contribution is the defence-in-depth integration and testable enforcement of these controls in a mobile-to-cloud-to-greenhouse command workflow.

## 6. Validation Summary

| Validation item | Result | Interpretation |
|---|---|---|
| Firebase authentication | Passed | The software authentication flow is implemented and tested. |
| Live Firebase BOLA rules | Passed | Cross-node unauthorized access is rejected. |
| Authorized mobile intent | Passed | A permitted role/node combination can create a valid intent. |
| Mobile BOLA attack | Passed | A manipulated node request is denied. |
| Backend sanitization | Passed | Actuator and state allowlists are enforced. |
| Environmental safety logic | Passed | Controlled tests demonstrate pump/fan safety overrides. |
| Offline command pipeline | Passed | Safe intent, denial, and audit stages work without claiming physical actuation. |
| Replay/idempotency protection | Passed | Duplicate request IDs do not create multiple dispatch records. |
| Fresh physical telemetry | Deferred | Must be repeated while both ESP32 boards and sensors are connected. |
| ESP32 command dispatch and relay response | Deferred | No final claim of physical actuation is currently justified. |
| Multi-factor authentication | Deferred | Production authentication hardening is incomplete. |
| Overall status | Partially complete | Software-development result is passed; final component/production validation is not yet passed. |

## 7. Limitations and Future Work

The current evidence supports a software-development claim, not a production-ready security claim. The following work remains:

1. Enable and validate multi-factor authentication.
2. Repeat telemetry freshness testing with the two ESP32 boards and sensors online.
3. Implement the final adapter from `pending_dispatch` to the Component 2 gateway.
4. Validate one physical relay at a time, beginning with fail-safe states.
5. Repeat safety-override, BOLA, and replay tests while hardware is online.
6. Measure end-to-end command latency, packet loss, recovery after network interruption, and behavior under concurrent users.
7. Perform a formal threat model and penetration test against the deployed API, Firebase configuration, mobile application, and device boundary.
8. Evaluate whether fixed thresholds should become crop-specific, season-specific, and sensor-calibrated policies without weakening the fail-closed controls.

## 8. Conclusion

Past IoT greenhouse research demonstrates the value of connected sensing, mobile visualization, and automated control, but the literature also shows that cybersecurity maturity and practical validation remain continuing challenges in smart agriculture. Component 4 improves the project's control layer by enforcing authenticated, least-privilege, node-specific, safety-aware, replay-resistant, and auditable command handling.

The current implementation closes an important software integration gap, especially against cross-node access and unsafe commands based on stale or hazardous environmental conditions. Nevertheless, MFA and end-to-end physical relay validation remain outstanding. The accurate conclusion is therefore that **Component 4's software security and safety pipeline has been developed and tested, while final hardware-integrated and production-security validation is future work**.

## References

1. Campoverde-Molina, M., & Luján-Mora, S. (2025). *Cybersecurity in smart agriculture: A systematic literature review*. Computers & Security, 150, 104284. https://doi.org/10.1016/j.cose.2024.104284
2. *Technologies, Protocols, and Applications of Internet of Things in Greenhouse Farming: A Survey of Recent Advances*. (2025). Information Processing in Agriculture, 12(1), 91–111. https://doi.org/10.1016/j.inpa.2024.04.002
3. *Cyber security in smart agriculture: Threat types, current status, and future trends*. (2025). Computers and Electronics in Agriculture. https://www.sciencedirect.com/science/article/pii/S0168169924007920
4. Zamora-Izquierdo, M. A., et al. (2023). *SAgric-IoT: An IoT-Based Platform and Deep Learning for Greenhouse Monitoring*. Applied Sciences, 13(3), 1961. https://doi.org/10.3390/app13031961
5. *SGF-MD: Behavior Rule Specification-Based Distributed Misbehavior Detection of Embedded IoT Devices in a Closed-Loop Smart Greenhouse Farming System*. (2020). IEEE Access. https://pure.qub.ac.uk/en/publications/sgf-md-behavior-rule-specification-based-distributed-misbehavior-/
6. *Design and Implementation of Intelligent Monitoring System for Agricultural Environment in IoT*. (2023). Internet of Things and Cyber-Physical Systems. https://www.sciencedirect.com/science/article/pii/S2542660523003529
7. *An Open Internet of Things (IoT)-Based Framework for Feedback Control of Photosynthetic Activities*. (2021). https://pmc.ncbi.nlm.nih.gov/articles/PMC11559478/

### Note on the comparison

The table presents a synthesis of limitations reported across the research area and common prototype architectures. It does **not** claim that every cited study lacks every listed feature. A strict paper-by-paper comparison should be made only after defining the final literature-review inclusion criteria and reading the complete methods and evaluation sections of each selected paper.
