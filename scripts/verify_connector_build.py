#!/usr/bin/env python3
"""Verify a built LocalWarp connector against its advertised capability contract.

Why this exists
---------------
`multi_device` and `coredevice_location_poc` are loaded as top-level modules by
the connector. PyInstaller can miss dynamic imports, producing a binary that
starts without the location capability the web app expects.

This check reads the PyInstaller archive (onefile) and asserts that the CoreDevice
runtime modules are present. Run it in CI after every build;
`scripts/build_connector.py` also calls it automatically.

Usage
-----
    python scripts/verify_connector_build.py [BINARY] [--json]
Exit codes: 0 = contract satisfied, 1 = required modules missing or artifact invalid.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import platform
import sys

CORE_MODULES = ("coredevice_location_poc", "connector_auth", "multi_device")
RUNTIME_MODULES = ("pymobiledevice3", "uvicorn", "fastapi", "construct")


def default_binary() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = "x64" if machine in ("x86_64", "amd64", "x64") else "arm64"
    if system == "darwin":
        name = f"LocalWarp-Connector-macos-{machine}"
    elif system == "windows":
        name = "LocalWarp-Connector-windows-x64.exe"
    else:
        name = f"LocalWarp-Connector-linux-{machine}"

    candidate = os.path.join("dist", "connectors", name)
    if os.path.exists(candidate):
        return candidate

    matches = sorted(glob.glob(os.path.join("dist", "connectors", "*")), key=os.path.getmtime)
    if matches:
        return matches[-1]
    raise FileNotFoundError(f"no connector artifact found under dist/connectors (expected {name})")


def top_level_modules(binary: str) -> set[str]:
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(binary)
    pyz_name = next((name for name in reader.toc if name.lower() == "pyz.pyz"), None)
    if pyz_name is None:
        raise RuntimeError(
            "artifact has no embedded PYZ.pyz; this verifier supports the onefile build "
            "produced by scripts/build_connector.py"
        )
    archive = reader.open_embedded_archive(pyz_name)
    # PYZ entries are dotted module names (pkg.module); collapse to the import root.
    return {name.split(".", 1)[0] for name in archive.toc}


def check_license_metadata(binary: str) -> dict:
    from PyInstaller.archive.readers import CArchiveReader

    reader = CArchiveReader(binary)
    license_entries = [
        name
        for name in reader.toc
        if "pymobiledevice3" in name.lower() and "license" in name.lower()
    ]
    return {
        "ok": len(license_entries) > 0,
        "entries": license_entries,
    }


def check_code_signature(binary: str) -> dict:
    import subprocess

    system = platform.system().lower()
    if system == "darwin":
        codesign = subprocess.run(
            ["codesign", "-dv", "--verbose=4", binary],
            capture_output=True,
            text=True,
            check=False,
        )
        details = f"{codesign.stdout}\n{codesign.stderr}"
        is_adhoc = "Signature=adhoc" in details
        has_team_id = any(
            line.startswith("TeamIdentifier=") and "not set" not in line
            for line in details.splitlines()
        )
        spctl = subprocess.run(
            ["spctl", "--assess", "--type", "execute", "--verbose=4", binary],
            capture_output=True,
            text=True,
            check=False,
        )
        gatekeeper_ok = spctl.returncode == 0
        return {
            "platform": "darwin",
            "ok": codesign.returncode == 0 and not is_adhoc and has_team_id and gatekeeper_ok,
            "is_adhoc": is_adhoc,
            "has_team_id": has_team_id,
            "gatekeeper_ok": gatekeeper_ok,
        }
    if system == "windows":
        ps = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-AuthenticodeSignature '{binary}').Status",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        status = ps.stdout.strip()
        return {
            "platform": "windows",
            "ok": ps.returncode == 0 and status == "Valid",
            "status": status,
        }
    return {"platform": system, "ok": False, "reason": "unsupported signing platform"}


def evaluate(present: set[str]) -> dict:
    def status(modules: tuple[str, ...]) -> dict:
        missing = [m for m in modules if m not in present]
        return {"ok": not missing, "missing": missing}

    return {
        "core": status(CORE_MODULES),
        "runtime": status(RUNTIME_MODULES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("binary", nargs="?", help="path to the connector artifact")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument(
        "--require-signed",
        action="store_true",
        help="fail verification unless the binary has a valid release signature (Developer ID + Gatekeeper on macOS, Authenticode on Windows) and embedded GPL license metadata",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary or default_binary())
    if not os.path.exists(binary):
        print(f"[-] artifact not found: {binary}", file=sys.stderr)
        return 1

    try:
        present = top_level_modules(binary)
        license_meta = check_license_metadata(binary)
    except Exception as exc:  # pragma: no cover - depends on external artifact
        print(f"[-] cannot read artifact: {exc}", file=sys.stderr)
        return 1

    signature = check_code_signature(binary)
    result = evaluate(present)
    result.update(
        {
            "binary": binary,
            "size_mb": round(os.path.getsize(binary) / (1024 * 1024), 2),
            "top_level_modules": len(present),
            "license_metadata": license_meta,
            "signature": signature,
        }
    )
    base_ok = result["core"]["ok"] and result["runtime"]["ok"] and license_meta["ok"]
    result["ok"] = base_ok and (signature["ok"] if args.require_signed else True)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"[*] Artifact: {binary} ({result['size_mb']} MB, {len(present)} top-level modules)")
        for feature in ("core", "runtime"):
            item = result[feature]
            if item["ok"]:
                print(f"[+] {feature:17} OK")
            else:
                print(f"[-] {feature:17} MISSING: {', '.join(item['missing'])}")
        print(
            f"[{'+' if license_meta['ok'] else '-'}] {'license_metadata':17} "
            f"{'OK' if license_meta['ok'] else 'MISSING'}"
        )
        print(
            f"[{'+' if signature['ok'] else '!'}] {'signature':17} "
            f"{'RELEASE-SIGNED' if signature['ok'] else 'UNSIGNED/AD-HOC (not release-ready)'}"
        )
        print("[+] capability contract satisfied" if result["ok"] else "[-] capability contract NOT satisfied")

    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
