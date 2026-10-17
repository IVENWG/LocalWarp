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
GUI_ENTRY = os.path.join(SRC_DIR, "backend/server_gui.py")
ICON_PATH = os.path.join(ROOT_DIR, "assets/localwarp.ico")
POC_DIR = os.path.join(SRC_DIR, "poc")
OUTPUT_DIR = os.path.join(ROOT_DIR, "dist/connectors")

def check_dependencies():
    try:
        import PyInstaller
        print(f"[+] PyInstaller version: {PyInstaller.__version__}")
    except ImportError:
        print("[*] PyInstaller not found. Installing via pip...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])

def normalized_machine() -> str:
    """统一架构命名：与 install.sh / install.ps1 / CI 产物名保持 x64/arm64 一致。"""
    m = platform.machine().lower()
    if m in ("x86_64", "amd64", "x64"):
        return "x64"
    if m in ("arm64", "aarch64"):
        return "arm64"
    return m


def build():
    check_dependencies()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    system = platform.system().lower()
    machine = normalized_machine()

    if system == "darwin":
        binary_name = f"LocalWarp-Connector-macos-{machine}"
    elif system == "windows":
        binary_name = "LocalWarp-Connector-windows-x64.exe"
    else:
        binary_name = f"LocalWarp-Connector-linux-{machine}"
        
    print(f"\n==================================================")
    print(f"  Building Standalone Binary: {binary_name}       ")
    # Windows 发行版入口是托盘 GUI（--noconsole），其余平台为 CLI 服务
    print(f"  Source: {GUI_ENTRY if system == 'windows' else BACKEND_MAIN}")
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
        "--hidden-import=connector_auth",
        "--hidden-import=pymobiledevice3",
        "--hidden-import=construct",
        "--hidden-import=zeroconf",
        "--hidden-import=pydantic",
        "--hidden-import=pytun_pmd3",
    ])

    # CI 打 tag 构建时注入发布版本（LOCALWARP_BUILD_VERSION）。
    # 生成到 build/ 下的独立目录并加入 --paths，不改动源码树里的 server.py。
    # 必须放在 cmd 构建完成之后 append：放在之前会因 cmd 未定义直接 NameError，
    # 且后面的整体赋值也会覆盖掉已 append 的参数。
    build_version = os.environ.get("LOCALWARP_BUILD_VERSION", "").strip()
    if build_version:
        version_dir = os.path.join(ROOT_DIR, "build/version_stamp")
        os.makedirs(version_dir, exist_ok=True)
        with open(os.path.join(version_dir, "_version.py"), "w", encoding="utf-8") as f:
            f.write(f'# 由 CI 注入的发布版本（build_connector.py 生成）\nVERSION = {build_version!r}\n')
        cmd.append(f"--paths={version_dir}")
        print(f"[+] Injected release version: {build_version}")

    # Dynamic safe metadata injection for DDI / Cryptex tools
    import importlib.metadata
    for opt_pkg in ["pyimg4", "readchar", "apple_compress", "ipsw_parser"]:
        try:
            importlib.metadata.distribution(opt_pkg)
            cmd.insert(-1, f"--copy-metadata={opt_pkg}")
            cmd.insert(-1, f"--collect-all={opt_pkg}")
            cmd.insert(-1, f"--hidden-import={opt_pkg}")
            print(f"[+] Found {opt_pkg}, bundled metadata and imports successfully.")
        except Exception:
            print(f"[*] Package {opt_pkg} not present, skipping metadata.")

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
    
    # Entry point: Windows ships the tray GUI (no console window);
    # macOS/Linux keep the CLI server managed by launchd/systemd.
    if system == "windows":
        entry = GUI_ENTRY
        cmd.append("--noconsole")
        if os.path.exists(ICON_PATH):
            cmd.append(f"--icon={ICON_PATH}")
        tray_png = os.path.join(ROOT_DIR, "assets", "localwarp.png")
        if os.path.exists(tray_png):
            sep = ";" if system == "windows" else ":"
            cmd.append(f"--add-data={tray_png}{sep}.")
        cmd.extend([
            "--collect-all=PIL",
            "--hidden-import=pystray",
            "--hidden-import=pystray._win32",
        ])
    else:
        entry = BACKEND_MAIN
    cmd.append(entry)

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
