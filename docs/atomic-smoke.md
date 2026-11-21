# Atomic Red Team smoke test

This is the release-validation subset for the detection content that the
Atomic Red Team estate run exercises. It is deliberately small: six
high-value Windows techniques, one expected Plasma rule each.

The machine-readable suite is [`sensors/atomic-smoke.json`](https://github.com/DrOlu/plasma/blob/main/sensors/atomic-smoke.json).
The unit test `tests/test_atomic_fixes.py` verifies that every expected rule
still exists.

## Cases

| Technique | Atomic test | Expected rule |
|---|---|---|
| T1059.001 | PowerShell Command Execution (`a538de64-1c74-46ed-aa60-b995ed302598`) | `Plasma Encoded Cmd` |
| T1053.005 | Scheduled task Local (`42f53695-ad4a-4546-abb6-7d837f644a71`) | `Plasma Scheduled Task Create` |
| T1543.003 | Service Installation CMD (`981e2942-e433-44e9-afc1-8c957a1496b6`) | `Plasma Service Registry Persistence` |
| T1547.001 | Reg Key Run (`e55be3fd-3521-4610-9d1a-e210e42dcf05`) | `Plasma Run Key Persistence` |
| T1136.001 | Create a new user in a command prompt (`6657864e-0323-4206-9344-ac9cd7265a4f`) | `Plasma Net Account Add` |
| T1140 | Certutil Rename and Decode (`71abc534-3c05-4d0c-80f7-cbe93cb2aa94`) | `Plasma File Delete by LOLBin` |

## Run it on a lab endpoint

1. Install Atomic Red Team and the `Invoke-AtomicRedTeam` module on the
   endpoint.
2. Point `PathToAtomicsFolder` at a local clone.
3. For each case run the test, let WHIDS flush, then pull and query:

```powershell
Invoke-AtomicTest T1059.001 -TestGuids a538de64-1c74-46ed-aa60-b995ed302598 `
  -PathToAtomicsFolder C:\AtomicRedTeam\atomic-red-team-master\atomics `
  -Confirm:$false -TimeoutSeconds 60

plasma whids pull
plasma query --kind alert --since 10m --max-rows 2000
```

4. Confirm the expected signature appears in `Event.GeneInfo.Signature`.
5. Run the cleanup command for every test:

```powershell
Invoke-AtomicTest T1059.001 -TestGuids a538de64-1c74-46ed-aa60-b995ed302598 `
  -Cleanup -PathToAtomicsFolder C:\AtomicRedTeam\atomic-red-team-master\atomics `
  -Confirm:$false
```

## Acceptance

- All six expected rules fire on their matching test.
- No destructive atomics are used in this smoke suite.
- Test tasks, services, local users and Run-key values are removed afterwards.
- `plasma health` returns `ok`.

The wider 24-technique estate run and its gaps are recorded in the release
notes. Discovery-only atomics are intentionally not part of this smoke
suite.
