# Step 40C Java / PowerShell Fix

Java is installed correctly. `java -version` normally writes its version
information to STDERR. With `$ErrorActionPreference = "Stop"`, Windows
PowerShell may interpret that expected STDERR text as a `NativeCommandError`.

The fixed runner captures the Java version through `cmd /c` and then
continues to `npm install` and the Firebase Realtime Database Emulator tests.
