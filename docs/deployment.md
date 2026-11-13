# Deployment at scale (MSI + GPO)

Plasma ships two artifacts per release:

| Artifact | Use |
|---|---|
| `plasma-<version>-windows-x64.exe` | single-file installer for a console operator |
| `plasma-<version>-windows-x64.msi` | **MSI for GPO / enterprise deployment** |

The MSI installs the exe into `C:\Program Files\Plasma\` and runs
`plasma install --force --root "<PLASMA_ROOT>"` as a deferred, elevated
custom action — so a GPO deployment provisions Sysmon/WHIDS and the event
store without anyone at the console.

## Silent install

```powershell
msiexec /i plasma-1.4.0-windows-x64.msi /qn
```

Custom data root (e.g. a larger volume):

```powershell
msiexec /i plasma-1.4.0-windows-x64.msi /qn PLASMA_ROOT="D:\Plasma"
```

Diagnostic log:

```powershell
msiexec /i plasma-1.4.0-windows-x64.msi /qn /l*v C:\Windows\Temp\plasma-msi.log
```

Requirements: Windows x64, local administrator, ~200 MB disk. Internet is
optional — with it, the installer provisions Sysmon automatically; without
it the node installs in MINIMAL mode (identity + ETW tap).

## Group Policy deployment

1. Put the MSI on a share the computer accounts can read, e.g.
   `\\fileserver\software\plasma\plasma-1.4.0-windows-x64.msi`.
2. Group Policy Management → create/edit a GPO for the target OU →
   **Computer Configuration → Policies → Software Settings → Software
   installation**.
3. **New → Package…**, choose the MSI from the UNC path, select
   **Assigned**, click **OK**.
4. To change the data root per OU, deploy a transform (`.mst`) that sets the
   public property `PLASMA_ROOT`, and add it in the package's
   **Modifications** tab.
5. Force policy refresh and reboot:
   `gpupdate /force`, then `gpresult /h` to confirm the assignment.

The package upgrades in place: a newer release carries the same
`UpgradeCode` and replaces the previous version (`MajorUpgrade`).

**Uninstall behavior:** removing the MSI deletes the installed exe only. It
deliberately leaves Sysmon, WHIDS and `C:\ProgramData\Plasma` alone —
silently stripping an EDR's sensors is an operational decision, not an
uninstaller default. Remove those explicitly if required.

## Verifying a deployed node

```powershell
plasma health
plasma canary deploy          # optional: impact decoys on this node
```

A node deployed by MSI runs the same `install` path as the exe, so its
`config.json`, health verdict and update behavior are identical.

## Rollout pattern that works

1. Pilot: one node, interactive install, `plasma watch once` for a day.
2. Ring 1: MSI via GPO on a small OU; check `plasma health` centrally with
   `plasma fleet pull/correlate`.
3. Ring 2: remaining OUs. Keep `--skip-whids` transforms for hosts where
   WHIDS is known to be unstable; the node records MINIMAL mode and health
   reports it. The installer also registers the **PlasmaWhidsWatchdog**
   scheduled task (SYSTEM, every 2 minutes), which runs `plasma whids
   ensure` to force-stop a hung StartPending and restart the sensor.
   does not penalize it.

## Note on signing

The exe inside the MSI is Authenticode-signed from 1.2.0 onward. The MSI
itself is signed when the SignPath Foundation application is approved; until
then, distribute the MSI over a trusted internal share and verify the
embedded exe's signature with `Get-AuthenticodeSignature`.
