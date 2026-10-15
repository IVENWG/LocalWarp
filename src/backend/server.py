#!/usr/bin/env python3
"""
LocalWarp Connector Client Daemon (Phase 3 & 4)
-----------------------------------------------
High-performance, standalone zero-dependency local daemon providing secure
REST IPC bridge between the Web UI and the iPhone CoreDevice LocationService.

Supports:
- Zero installation conflicts (direct native usbmuxd integration)
- 100% Local key isolation (Zero pairing key leaves the machine)
- Automatic background service install/uninstall (launchd, systemd, registry)
- PyInstaller standalone binary compilation for macOS, Windows, Linux
"""

import sys
import os
import re
import argparse
import logging
import platform
import shlex
import subprocess
import xml.sax.saxutils
from typing import Optional
from pydantic import BaseModel, Field

# Ensure repo and pymobiledevice3 in path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(base_dir, "src/poc"))
# pymobiledevice3 以 pip 安装版为准（与 CI 打包环境一致）；vendored 副本仅作未安装时的兜底，
# append 到搜索路径末尾，保证 pip 版存在时永远优先于 vendored 版
_vendored_pmd3 = os.path.join(base_dir, "external_research/pymobiledevice3")
if os.path.exists(_vendored_pmd3) and _vendored_pmd3 not in sys.path:
    sys.path.append(_vendored_pmd3)

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

try:
    from coredevice_location_poc import CoreDeviceLocationManager
except ImportError:
    # Support bundled binary execution
    from src.poc.coredevice_location_poc import CoreDeviceLocationManager

try:
    # CI 打 tag 构建时由 build_connector.py 注入（build/version_stamp/_version.py）
    from _version import VERSION  # type: ignore[import-not-found]
except Exception:
    VERSION = "1.0.7"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LocalWarpConnector")

app = FastAPI(
    title="LocalWarp Connector",
    description="Local secure daemon for iOS CoreDevice LocationService",
    version=VERSION
)

# CORS: 只放行本机/局域网 IP 来源与生产站点。
# 绝不能用 allow_origins=["*"] + allow_credentials=True 的组合——Starlette 会把
# 任意请求 Origin 原样反射回响应头，等于允许任何恶意网页驱动本机连接器。
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=(
        r"^https?://(localhost|127\.0\.0\.1|\[::1\]|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:\d+)?$"
        r"|^https://localwarp\.com$"
    ),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Host/Origin 防护：拦截 DNS rebinding（Host 非本机/局域网名）与公网站点的
# 跨站请求（Origin 非白名单）。无 Origin 的同源导航与 curl/python 客户端不受影响。
_ALLOWED_HOST = re.compile(
    r"^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|localwarp\.com)$"
)


@app.middleware("http")
async def guard_local_access(request: Request, call_next):
    host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip().lower()
    if host and not _ALLOWED_HOST.match(host):
        return JSONResponse({"detail": "forbidden host"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and "://" in origin:
        origin_host = origin.split("://", 1)[1].split("/")[0].rsplit(":", 1)[0].strip().lower()
        if origin_host and not _ALLOWED_HOST.match(origin_host):
            return JSONResponse({"detail": "forbidden origin"}, status_code=403)
    return await call_next(request)

# Global manager instance (Userspace tunnel for Windows/Linux, native tunnel for macOS)
is_darwin = platform.system() == "Darwin"
manager = CoreDeviceLocationManager(use_userspace=not is_darwin)


class SimulateLocationRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID (optional if single device)")
    latitude: float = Field(..., ge=-90.0, le=90.0, description="Latitude in decimal degrees")
    longitude: float = Field(..., ge=-180.0, le=180.0, description="Longitude in decimal degrees")


class ClearLocationRequest(BaseModel):
    udid: Optional[str] = Field(None, description="Device UDID (optional if single device)")


@app.get("/health")
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "LocalWarp Connector",
        "version": VERSION,
        "platform": platform.system(),
        "arch": platform.machine()
    }


@app.get("/api/devices")
async def list_devices():
    try:
        devices = await manager.list_devices()
        return {
            "success": True,
            "count": len(devices),
            "devices": devices
        }
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        # detail 必须透传原始错误：poc 抛出的都是面向用户的引导文案，
        # 前端靠 err.message 关键字识别（开发者模式引导等），统一覆盖会断掉整条引导链路
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/simulate")
async def simulate_location(req: SimulateLocationRequest):
    try:
        logger.info(f"Received simulate request: lat={req.latitude}, lon={req.longitude}, udid={req.udid}")
        result = await manager.simulate_location(
            latitude=req.latitude,
            longitude=req.longitude,
            udid=req.udid
        )
        return {
            "success": True,
            "message": f"Simulated location successfully set to ({req.latitude}, {req.longitude})",
            "data": result
        }
    except Exception as e:
        logger.error(f"Failed to set location: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/location/clear")
async def clear_location(req: ClearLocationRequest):
    try:
        logger.info(f"Received clear location request for udid={req.udid}")
        result = await manager.clear_location(udid=req.udid)
        return {
            "success": True,
            "message": "Simulated location successfully cleared. Real GPS restored.",
            "data": result
        }
    except Exception as e:
        logger.error(f"Failed to clear location: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/{udid}/reveal_developer_mode")
@app.post("/api/device/reveal_developer_mode")
async def reveal_developer_mode(udid: Optional[str] = None):
    try:
        logger.info(f"Received request to reveal developer mode for udid={udid}")
        res = await manager.reveal_developer_mode(device_id=udid)
        return res
    except Exception as e:
        logger.error(f"Failed to reveal developer mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/device/{udid}/enable_developer_mode")
@app.post("/api/device/enable_developer_mode")
async def enable_developer_mode(udid: Optional[str] = None):
    try:
        logger.info(f"Received request to enable developer mode for udid={udid}")
        res = await manager.enable_developer_mode(device_id=udid)
        return res
    except Exception as e:
        logger.error(f"Failed to enable developer mode: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/device/{udid}/developer_mode_status")
@app.get("/api/device/developer_mode_status")
async def developer_mode_status(udid: Optional[str] = None):
    try:
        enabled = await manager.get_developer_mode_status(device_id=udid)
        return {"success": True, "enabled": enabled}
    except Exception as e:
        logger.error(f"Failed to query developer mode status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==============================================================================
# Service Installation & Daemon Management Helpers
# ==============================================================================

def get_executable_command():
    """Command (as argv list) to run this program. 列表形式避免路径含空格被拆错。"""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def install_service() -> bool:
    system = platform.system()
    cmd = get_executable_command()

    if system == "Darwin":
        launch_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_dir, exist_ok=True)
        plist_path = os.path.join(launch_dir, "com.localwarp.connector.plist")

        # 路径里合法的 &、<、> 等字符会直接毁掉 plist，必须转义
        args_xml = "".join(f"        <string>{xml.sax.saxutils.escape(part)}</string>\n" for part in cmd)
            
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.localwarp.connector</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/localwarp-connector.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/localwarp-connector.err</string>
</dict>
</plist>
"""
        with open(plist_path, "w") as f:
            f.write(plist_content)
        uid = os.getuid()
        subprocess.run(
            ["launchctl", "bootout", f"gui/{uid}/com.localwarp.connector"],
            capture_output=True,
        )
        res = subprocess.run(
            ["launchctl", "bootstrap", f"gui/{uid}", plist_path], capture_output=True
        )
        if res.returncode != 0:
            # 旧版 macOS 回退到已废弃但可用的 load/unload
            res = subprocess.run(["launchctl", "load", plist_path], capture_output=True)
        if res.returncode == 0:
            print(f"[+] macOS launchd service successfully installed: {plist_path}")
            print("[+] Connector is now running and will auto-start on login.")
            return True
        else:
            print(f"[-] Failed to load launchd service: {res.stderr.decode()}")
            return False

    elif system == "Linux":
        systemd_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(systemd_dir, exist_ok=True)
        unit_path = os.path.join(systemd_dir, "localwarp-connector.service")

        unit_content = f"""[Unit]
Description=LocalWarp iPhone Location Connector Daemon
After=network.target

[Service]
Type=simple
ExecStart={shlex.join(cmd)}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""
        with open(unit_path, "w") as f:
            f.write(unit_content)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
        res = subprocess.run(
            ["systemctl", "--user", "enable", "--now", "localwarp-connector.service"],
            capture_output=True,
        )
        if res.returncode == 0:
            print(f"[+] Linux systemd user service installed: {unit_path}")
            print("[+] Connector is now running and enabled at startup.")
            return True
        else:
            print(f"[-] Failed to enable systemd service: {res.stderr.decode()}")
            return False

    elif system == "Windows":
        print("[*] To auto-start on Windows, place a shortcut of LocalWarp-Connector.exe into:")
        print("    shell:startup (Win + R -> type 'shell:startup')")
        return True
    else:
        print(f"[-] Unsupported OS for service installation: {system}")
        return False


def uninstall_service():
    system = platform.system()
    if system == "Darwin":
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.localwarp.connector.plist")
        if os.path.exists(plist_path):
            subprocess.run(
                ["launchctl", "bootout", f"gui/{os.getuid()}/com.localwarp.connector"],
                capture_output=True,
            )
            os.remove(plist_path)
            print(f"[+] Removed macOS launchd service: {plist_path}")
        else:
            print("[-] No installed launchd service found.")
    elif system == "Linux":
        unit_path = os.path.expanduser("~/.config/systemd/user/localwarp-connector.service")
        if os.path.exists(unit_path):
            subprocess.run(["systemctl", "--user", "disable", "--now", "localwarp-connector.service"])
            os.remove(unit_path)
            subprocess.run(["systemctl", "--user", "daemon-reload"])
            print(f"[+] Removed Linux systemd user service: {unit_path}")
        else:
            print("[-] No installed systemd unit found.")
    elif system == "Windows":
        print("[*] Please remove LocalWarp shortcut from your startup folder.")


def print_banner(host: str, port: int):
    # 绑定 0.0.0.0 时展示 127.0.0.1，避免用户照着 0.0.0.0 打不开
    display_host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
    banner = rf"""
  _                     ___          __            
 | |   ___  __ __ _ ___| \ \        / /_ _ _ _ _ __ 
 | |__/ _ \/ _/ _` / -_) |\ \  /\  / / _` | '_| '_ \\
 |____\___/\__\__,_\___|_| \_\/  \/ \__,_|_|  | .__/
                                              |_|   
          iPhone Location Changer (CoreDevice)      
======================================================
  Version:    {VERSION}
  Platform:   {platform.system()} ({platform.machine()})
  Endpoint:   http://{display_host}:{port}
  Health:     http://{display_host}:{port}/health
======================================================
  * Zero Drivers Conflict: Compatible with native usbmuxd
  * Zero Private Keys Leak: 100% On-device pairing isolation
  * Unplug Persistence: Target location persists upon disconnect
======================================================
[+] Connector is listening. Open the Web Studio in your browser:
    👉  https://localwarp.com/app
"""
    print(banner)

    print_windows_amds_warning()


def check_windows_amds() -> bool:
    """探测 Apple 移动设备驱动 (AMDS, 端口 27015) 是否就绪。仅 Windows 有意义。"""
    if platform.system() != "Windows":
        return True
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(("127.0.0.1", 27015))
        return True
    except Exception:
        return False
    finally:
        sock.close()


def print_windows_amds_warning():
    """控制台版的 AMDS 缺失引导（CLI 入口用；GUI 入口用 check_windows_amds 走托盘提示）。"""
    if not check_windows_amds():
        print("*" * 76)
        print("[!] 提示: 检测到当前 Windows 电脑尚未安装 Apple 基础通信驱动 (AMDS)")
        print("-" * 76)
        print("请按照以下两步完成首次环境配置（仅需首次安装一次）:")
        print("  【步骤 1】安装 Apple 官方底层通信驱动:")
        print("            官方直链: https://www.apple.com/itunes/download/win64")
        print("            (或在微软应用商店搜索安装 'Apple Devices')")
        print("  【步骤 2】将 iPhone 插入电脑，解锁手机并在弹窗中点击【信任此电脑】")
        print("            装完后本程序将自动连通！")
        print("*" * 76 + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="LocalWarp Connector: Secure local iOS Location daemon for Web Studio"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=28888, help="Listening port (default: 28888)")
    parser.add_argument("--status", action="store_true", help="Check current daemon status and list devices")
    parser.add_argument("--install-service", action="store_true", help="Install as persistent auto-start system service")
    parser.add_argument("--uninstall-service", action="store_true", help="Uninstall auto-start system service")
    
    args = parser.parse_args()
    
    if args.install_service:
        sys.exit(0 if install_service() else 1)
        return
        
    if args.uninstall_service:
        uninstall_service()
        return

    if args.status:
        print("[*] Checking LocalWarp Connector status...")
        import urllib.request
        import json
        # Windows 上 0.0.0.0 不是回环地址，状态探测固定走 127.0.0.1
        probe_host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
        try:
            req = urllib.request.Request(f"http://{probe_host}:{args.port}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
                print(f"[+] Connector is ONLINE: {data}")
            req_dev = urllib.request.Request(f"http://{probe_host}:{args.port}/api/devices")
            # /api/devices 最坏路径（native browse 1.8s + 未配对设备 2s 配对等待）可超 3s，
            # 预算须覆盖，否则明明 ONLINE 却误报 OFFLINE
            with urllib.request.urlopen(req_dev, timeout=8) as resp_dev:
                devices = json.loads(resp_dev.read().decode()).get("devices", [])
                print(f"[+] Connected iOS Devices ({len(devices)}):")
                for d in devices:
                    print(f"    - UDID: {d.get('udid')} | Name: {d.get('name')} | Model: {d.get('model')}")
        except Exception as e:
            print(f"[-] Connector is OFFLINE or unreachable on {args.host}:{args.port} ({e})")
        return

    print_banner(args.host, args.port)
    
    # Run uvicorn server directly with app object (PyInstaller safe)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info", access_log=False)


if __name__ == "__main__":
    main()
