# REA & Hardware Reverse Engineering Workspace Rules

## 1. Reverse Engineering Tool Hierarchy
- **Prefer REA MCP over CLI**: When analyzing Android APKs or DEX files and the `rea_rea` server is available, always use REA MCP tools (`search_android_classes`, `inspect_android_class`, `trace_android_references`) before launching full-disk CLI decompilation tasks.
- **Decompile Scope**: If CLI decompilation is necessary, decompile only the single targeted class (`jadx --single-class <FQN>`) to `/tmp/`, never the entire APK.

## 2. macOS Hardware & Bluetooth (TCC) Policy
- **No In-IDE BLE Execution**: Never attempt to run live Bluetooth LE (`bleak` / CoreBluetooth) hardware scripts inside the IDE's embedded subshells. macOS TCC will terminate the process with SIGABRT (134) due to missing `NSBluetoothAlwaysUsageDescription`.
- **User Instructions**: Always instruct the user to execute BLE scripts directly in macOS `Terminal.app`.

## 3. Cloud API Emulation & Parameter Discipline
- **Mandatory Non-Zero Foreign Keys**: Never transmit `0` or empty strings for backend identifiers (`homeId`, `deviceId`, `configModel`) without verifying the API accepts them.
- **No Silent Exception Swallowing**: Never wrap SDK calls in bare `try...except Exception: pass` where failure leaves mandatory request payload fields unpopulated. Always verify the resulting values or apply verified fallback constants decompiled from official vendor clients.
