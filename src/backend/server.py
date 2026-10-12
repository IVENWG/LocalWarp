#!/usr/bin/env python3
"""
LocalWarp Connector Client Daemon (Phase 3 & 4)
-----------------------------------------------
High-performance, standalone zero-dependency local daemon providing secure
REST & WebSocket IPC bridge between the Web UI and the iPhone CoreDevice LocationService.

Supports:
- Zero installation conflicts (direct native usbmuxd integration)
- 100% Local key isolation (Zero pairing key leaves the machine)
- Automatic background service install/uninstall (launchd, systemd, registry)
- PyInstaller standalone binary compilation for macOS, Windows, Linux
"""

import sys
import os
import argparse
import asyncio
import logging
import platform
import subprocess
import signal
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# Ensure repo and pymobiledevice3 in path
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(base_dir, "src/poc"))
if os.path.exists(os.path.join(base_dir, "external_research/pymobiledevice3")):
    sys.path.insert(0, os.path.join(base_dir, "external_research/pymobiledevice3"))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

try:
    from coredevice_location_poc import CoreDeviceLocationManager
except ImportError:
    # Support bundled binary execution
    from src.poc.coredevice_location_poc import CoreDeviceLocationManager

VERSION = "1.0.1"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("LocalWarpConnector")

app = FastAPI(
    title="LocalWarp Connector",
    description="Local secure daemon for iOS CoreDevice LocationService",
    version=VERSION
)

# Enable CORS for local and web UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global manager instance
manager = CoreDeviceLocationManager(use_userspace=False)
connected_websockets: List[WebSocket] = []


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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_websockets.append(websocket)
    logger.info("WebSocket client connected")
    try:
        devices = await manager.list_devices()
        await websocket.send_json({
            "type": "devices_updated",
            "devices": devices
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.warning(f"WebSocket error: {e}")
    finally:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)


# ==============================================================================
# Service Installation & Daemon Management Helpers
# ==============================================================================

def get_executable_path():
    if getattr(sys, 'frozen', False):
        return sys.executable
    return f"{sys.executable} {os.path.abspath(__file__)}"


def install_service():
    system = platform.system()
    exec_path = get_executable_path()
    
    if system == "Darwin":
        launch_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(launch_dir, exist_ok=True)
        plist_path = os.path.join(launch_dir, "com.localwarp.connector.plist")
        
        args_xml = ""
        for part in exec_path.split():
            args_xml += f"        <string>{part}</string>\n"
            
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
        subprocess.run(["launchctl", "unload", plist_path], capture_output=True)
        res = subprocess.run(["launchctl", "load", plist_path], capture_output=True)
        if res.returncode == 0:
            print(f"[+] macOS launchd service successfully installed: {plist_path}")
            print("[+] Connector is now running and will auto-start on login.")
        else:
            print(f"[-] Failed to load launchd service: {res.stderr.decode()}")
            
    elif system == "Linux":
        systemd_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(systemd_dir, exist_ok=True)
        unit_path = os.path.join(systemd_dir, "localwarp-connector.service")
        
        unit_content = f"""[Unit]
Description=LocalWarp iPhone Location Connector Daemon
After=network.target

[Service]
Type=simple
ExecStart={exec_path}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
"""
        with open(unit_path, "w") as f:
            f.write(unit_content)
        subprocess.run(["systemctl", "--user", "daemon-reload"])
        subprocess.run(["systemctl", "--user", "enable", "--now", "localwarp-connector.service"])
        print(f"[+] Linux systemd user service installed: {unit_path}")
        print("[+] Connector is now running and enabled at startup.")
        
    elif system == "Windows":
        print("[*] To auto-start on Windows, place a shortcut of LocalWarp-Connector.exe into:")
        print("    shell:startup (Win + R -> type 'shell:startup')")
    else:
        print(f"[-] Unsupported OS for service installation: {system}")


def uninstall_service():
    system = platform.system()
    if system == "Darwin":
        plist_path = os.path.expanduser("~/Library/LaunchAgents/com.localwarp.connector.plist")
        if os.path.exists(plist_path):
            subprocess.run(["launchctl", "unload", plist_path], capture_output=True)
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
  Endpoint:   http://{host}:{port}
  Health:     http://{host}:{port}/health
  WebSocket:  ws://{host}:{port}/ws
======================================================
  * Zero Drivers Conflict: Compatible with native usbmuxd
  * Zero Private Keys Leak: 100% On-device pairing isolation
  * Unplug Persistence: Target location persists upon disconnect
======================================================
[+] Connector is listening. Open the Web Studio in browser:
    👉  http://localhost:3000/app  (or deployed Cloudflare URL)
"""
    print(banner)

    if platform.system() == "Windows":
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        has_driver = False
        try:
            sock.connect(("127.0.0.1", 27015))
            has_driver = True
            sock.close()
        except Exception:
            sock.close()

        if not has_driver:
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
        install_service()
        return
        
    if args.uninstall_service:
        uninstall_service()
        return

    if args.status:
        print("[*] Checking LocalWarp Connector status...")
        import urllib.request
        import json
        try:
            req = urllib.request.Request(f"http://{args.host}:{args.port}/health")
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read().decode())
                print(f"[+] Connector is ONLINE: {data}")
            req_dev = urllib.request.Request(f"http://{args.host}:{args.port}/api/devices")
            with urllib.request.urlopen(req_dev, timeout=3) as resp_dev:
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
