#!/usr/bin/env python3
"""
LocalWarp Connector Standalone Binary Builder
----------------------------------------------
Compiles server.py into a zero-dependency, single-file executable for:
- macOS (arm64 / x86_64)
- Linux (x86_64)
- Windows (x64 .exe)
"""

import sys
import os
import platform
import subprocess
import shutil

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
BACKEND_MAIN = os.path.join(SRC_DIR, "backend/server.py")
POC_DIR = os.path.join(SRC_DIR, "poc")
OUTPUT_DIR = os.path.join(ROOT_DIR, "dist/connectors")

def check_dependencies():
    try:
        import PyInstaller
        print(f"[+] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[*] PyInstaller not found. Installing via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def build():
    check_dependencies()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    if system == "darwin":
        binary_name = f"LocalWarp-Connector-macos-{machine}"
    elif system == "windows":
        binary_name = "LocalWarp-Connector-windows-x64.exe"
    else:
        binary_name = f"LocalWarp-Connector-linux-{machine}"
        
    print(f"\n==================================================")
    print(f"  Building Standalone Binary: {binary_name}       ")
    print(f"  Source: {BACKEND_MAIN}                          ")
    print(f"  Target: {OUTPUT_DIR}/{binary_name}              ")
    print(f"==================================================\n")
    
    # Path separator for PyInstaller --add-data (: on Unix, ; on Windows)
    sep = ";" if system == "windows" else ":"
    ext_pmd3 = os.path.join(ROOT_DIR, "external_research/pymobiledevice3")
    
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", binary_name,
        "--distpath", OUTPUT_DIR,
        "--workpath", os.path.join(ROOT_DIR, "build/pyinstaller_build"),
        "--specpath", os.path.join(ROOT_DIR, "build"),
        f"--paths={POC_DIR}",
    ]
    if os.path.exists(ext_pmd3):
        cmd.append(f"--paths={ext_pmd3}")
    cmd.extend([
        f"--add-data={POC_DIR}{sep}src/poc",
        "--collect-all=pymobiledevice3",
        "--collect-all=construct",
        "--collect-all=zeroconf",
        "--collect-all=pytun_pmd3",
        "--copy-metadata=pytun_pmd3",
        "--copy-metadata=pymobiledevice3",
        # Hidden imports for uvicorn & async engines
        "--hidden-import=uvicorn.logging",
        "--hidden-import=uvicorn.loops",
        "--hidden-import=uvicorn.loops.auto",
        "--hidden-import=uvicorn.loops.asyncio",
        "--hidden-import=uvicorn.protocols",
        "--hidden-import=uvicorn.protocols.http",
        "--hidden-import=uvicorn.protocols.http.auto",
        "--hidden-import=uvicorn.protocols.http.h11_impl",
        "--hidden-import=uvicorn.protocols.websockets",
        "--hidden-import=uvicorn.protocols.websockets.auto",
        "--hidden-import=uvicorn.lifespans",
        "--hidden-import=uvicorn.lifespans.on",
        "--hidden-import=coredevice_location_poc",
        "--hidden-import=pymobiledevice3",
        "--hidden-import=construct",
        "--hidden-import=zeroconf",
        "--hidden-import=pydantic",
        "--hidden-import=pytun_pmd3",
        BACKEND_MAIN
    ])

    # Explicitly include pytun_pmd3 package directory and wintun.dll binaries
    try:
        import pytun_pmd3
        pytun_dir = os.path.abspath(os.path.dirname(pytun_pmd3.__file__))
        cmd.append(f"--add-data={pytun_dir}{sep}pytun_pmd3")
        wintun_dir = os.path.join(pytun_dir, "wintun")
        if os.path.exists(wintun_dir):
            cmd.append(f"--add-data={wintun_dir}{sep}pytun_pmd3/wintun")
            wintun_bin = os.path.join(wintun_dir, "bin")
            if os.path.exists(wintun_bin):
                cmd.append(f"--add-data={wintun_bin}{sep}pytun_pmd3/wintun/bin")
                if system == "windows":
                    cmd.append(f"--add-binary={wintun_bin}/*;pytun_pmd3/wintun/bin")
                    wintun_amd64 = os.path.join(wintun_bin, "amd64")
                    if os.path.exists(wintun_amd64):
                        cmd.append(f"--add-binary={wintun_amd64}/*;pytun_pmd3/wintun/bin/amd64")
    except Exception as e:
        print(f"[*] Note discovering pytun_pmd3: {e}")
    
    print("[*] Running command:")
    print(" ".join(cmd))
    
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"\n[-] Build FAILED with code {res.returncode}")
        sys.exit(res.returncode)
        
    binary_path = os.path.join(OUTPUT_DIR, binary_name)
    if os.path.exists(binary_path):
        size_mb = os.path.getsize(binary_path) / (1024 * 1024)
        print(f"\n==================================================")
        print(f"  [+] Standalone Binary Built Successfully!        ")
        print(f"  Location: {binary_path}                         ")
        print(f"  Size:     {size_mb:.2f} MB                      ")
        print(f"==================================================")
        
        # Make executable
        if system != "windows":
            os.chmod(binary_path, 0o755)

if __name__ == "__main__":
    build()
