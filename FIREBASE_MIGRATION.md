# Firebase project change

The React dashboard environment files, Python database URL settings, and ESP32 gateway sketches now target `greenhouse-development`:

`https://greenhouse-development-default-rtdb.firebaseio.com`

The existing Firebase SDK dependencies are unchanged.

## Remaining setup

1. Download an Admin service-account JSON for the new project and set `FIREBASE_CREDENTIALS_PATH` in `three/.env` and `four/.env` to its local path. Both currently reference a service account for `ghouse-bccc9`.
2. Configure the new project's Authentication accounts and database rules. The integrated dashboard maps username `admin` to `ghouse.dashboard@gmail.com`. The ESP32 gateway sketches now use Authentication UID `3I9Eo1cltNQb68WcizDWlwb4wDm1` in `EXPECTED_GATEWAY_UID`, sign in as `ghouse@gmail.com`, and have the supplied gateway password configured.
3. Rebuild and upload the gateway firmware, then restart the dashboard and Python services after credentials and accounts are configured.
4. The Flutter mobile app stays on its existing Firebase project, as requested. It will not read data from the new database.
5. Existing database records and Authentication users have not been copied. Deploy the intended database rules and migrate or initialize required data before validating the complete system.

Setup references: https://firebase.google.com/docs/admin/setup and https://firebase.google.com/docs/flutter/setup.
