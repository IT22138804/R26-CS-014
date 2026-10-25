# Greenhouse Guard — Component 4 Mobile

Flutter client for the `ghouse-bccc9` Firebase project. The app authenticates
with Firebase Email/Password, loads the signed-in user's server-side Component 4
profile, and displays only explicitly assigned greenhouse nodes.

## Firebase paths

The signed-in account must have a profile at:

```text
/component4_test/users/{firebaseAuthUid}
```

Example profile:

```json
{
  "role": "operator",
  "assigned_nodes": {
    "GH_NODE_01": true
  }
}
```

Authorized node summaries are read from:

```text
/component4_test/nodes/{nodeId}
```

Roles `operator`, `manager`, and `admin` display intent-control permission.
`viewer` remains read-only. This stage intentionally has no direct actuator
write path.

## Run

```powershell
cd D:\Git\g_house\four\greenhouse_component4_mobile
& 'C:\Users\chathudu sahassara\flutter\bin\flutter.bat' pub get
& 'C:\Users\chathudu sahassara\flutter\bin\flutter.bat' run
```

When Flutter is on PATH, use `flutter pub get` and `flutter run`.

## Verify

```powershell
flutter analyze
flutter test
```

Firebase platform configuration is generated in `lib/firebase_options.dart`.
Android package and iOS bundle identifier: `com.ghouse.component4`.

## Run the fully integrated demonstration

Start the host workers, web dashboard, and two-ESP32 simulator from the repository
root in the first terminal:

```powershell
cd D:\Git\g_house
powershell -ExecutionPolicy Bypass -File .\run_full_system.ps1 -VirtualEsp32
```

For physical hardware, omit `-VirtualEsp32`, then reset the gateway, wait five
seconds, and reset the sensor board.

In a second terminal, start the mobile app:

```powershell
cd D:\Git\g_house\four\greenhouse_component4_mobile
& 'C:\Users\CHATHU~1\flutter\bin\flutter.bat' run
```

After signing in, open **Live demo**. The screen can trigger controlled
Component 1, 2, and 3 scenarios and streams their Firebase results. Component 4
runs continuously in the integrated worker and displays its latest telemetry
safety decision. Direct actuator writes remain unavailable from the mobile app.
