#!/usr/bin/env python3
"""Build an MSI for GPO / enterprise deployment from the single-file exe.

Requires the WiX Toolset CLI (v4/v5 dotnet tool: `dotnet tool install
--global wix`). Run on Windows in CI — the MSI installs the exe into
Program Files and runs `plasma install` as a deferred, elevated custom
action, so a GPO Software Installation deployment provisions the node
without an operator at the console.

    python tools/build_msi.py --exe dist/plasma.exe --version 1.4.0 \
        --out dist/plasma-1.4.0-windows-x64.msi
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Stable identities: an upgrade must reuse the UpgradeCode; the component
# GUID is deliberately omitted so WiX derives a stable one per file path.
UPGRADE_CODE = "8A6C2F1E-4B7D-4E52-9C3A-6F1B2D7E5A90"

WXS_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Plasma EDR"
           Manufacturer="{manufacturer}"
           ManufacturerUrl="{manufacturer_url}"
           Version="{version}"
           UpgradeCode="{upgrade}"
           Scope="perMachine"
           Compressed="yes">
    <MajorUpgrade DowngradeErrorMessage="A newer version of Plasma EDR is installed." />
    <MediaTemplate EmbedCab="yes" />

    <!-- GPO transforms may override the data root. -->
    <Property Id="PLASMA_ROOT" Value="C:\\ProgramData\\Plasma" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="Plasma">
        <Component Id="PlasmaExe">
          <File Id="PlasmaExeFile" Source="{exe}" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>

    <Feature Id="Main" Title="Plasma EDR" Level="1">
      <ComponentRef Id="PlasmaExe" />
    </Feature>

    <!-- Deferred, elevated: provisions sensors without a console operator.
         Uninstall leaves installed services alone (removing an EDR's
         sensors silently is a policy decision, not an uninstaller default). -->
    <CustomAction Id="PlasmaInstall"
                  FileRef="PlasmaExeFile"
                  ExeCommand="install --force --root &quot;[PLASMA_ROOT]&quot;"
                  Execute="deferred"
                  Impersonate="no" />
    <InstallExecuteSequence>
      <Custom Action="PlasmaInstall" After="InstallFiles" Condition="NOT REMOVE" />
    </InstallExecuteSequence>
  </Package>
</Wix>
"""


def build_wxs(exe: Path, version: str, manufacturer: str = "Hyperspace Technologies",
              manufacturer_url: str = "https://reactorpro.ng") -> str:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"MSI versions must be numeric x.y.z, got {version!r}")
    if not Path(exe).exists():
        raise SystemExit(f"exe not found: {exe}")
    return WXS_TEMPLATE.format(
        manufacturer=manufacturer,
        manufacturer_url=manufacturer_url,
        version=version,
        upgrade=UPGRADE_CODE,
        exe=str(exe),
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--exe", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--manufacturer", default="Hyperspace Technologies")
    ap.add_argument("--manufacturer-url", default="https://reactorpro.ng")
    ap.add_argument("--wxs-only", action="store_true",
                    help="write the .wxs next to --out and stop (no WiX needed)")
    ap.add_argument("--wix", default="wix", help="WiX CLI (default: wix)")
    args = ap.parse_args(argv)

    exe = Path(args.exe)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    wxs_path = out.with_suffix(".wxs")
    wxs_path.write_text(
        build_wxs(exe, args.version, args.manufacturer, args.manufacturer_url),
        encoding="utf-8")
    print(f"wxs: {wxs_path}")
    if args.wxs_only:
        return 0

    proc = subprocess.run([args.wix, "build", str(wxs_path), "-o", str(out)],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=600)
    if proc.returncode != 0:
        sys.stderr.write((proc.stdout or "")[-1500:] + "\n" + (proc.stderr or "")[-1500:])
        return proc.returncode or 1
    print(f"msi: {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
