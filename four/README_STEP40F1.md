# Component 4 — Step 40F-1

Secure Flutter authentication and role-based UI foundation.

This implements:
- Firebase email/password sign-in
- refreshed Firebase ID token
- flutter_secure_storage for token storage
- no local password storage
- FirebaseAuth auth-state as source of truth
- server-side role/assigned_nodes profile loading
- assigned-node-only UI rendering
- local BOLA defense-in-depth guard
- viewer vs operator/manager/admin rendering

This step deliberately does NOT submit actuator commands.

## 1. Source security contract

```powershell
powershell -ExecutionPolicy Bypass -File .\run_security_contract_tests.ps1
```

Expected: `9 passed`.

## 2. Create Flutter project

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_flutter_step40f1.ps1
```

## 3. Configure FlutterFire

```powershell
cd greenhouse_component4_mobile
dart pub global activate flutterfire_cli
flutterfire configure --project=ghouse-bccc9
flutter run
```

Do not place the Firebase Admin service-account JSON in the app.

## 4. Required Firebase profile

The Firebase login UID needs:

```text
/component4_test/users/{uid}
```

Example:

```json
{
  "role": "operator",
  "assigned_nodes": {
    "GH_NODE_01": true
  }
}
```

Step 40F-1 does not implement MFA yet. That will be a separate validation step.
