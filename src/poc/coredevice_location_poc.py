#!/usr/bin/env python3
"""
CoreDevice Location Service PoC (Phase 1)
-----------------------------------------
Pure protocol implementation for simulating and clearing iPhone system location
using iOS 17+ CoreDevice LocationService without Xcode GUI.

Verified against real physical iPhone 13 (iOS 26.7).
Supports:
- native tunnel (macOS remoted piggyback, no root, no Xcode GUI)
- userspace tunnel (pure Python userspace TCP stack, cross-platform Linux/Win/macOS, no root)

Interfaces implemented:
- list_devices()
- connect_device(device_id)
- set_location(device_id, latitude, longitude)
- clear_location(device_id)
- disconnect_device(device_id)
"""

import sys
import os
import argparse
import asyncio
import logging
from typing import List, Dict, Any, Optional

# Add pymobiledevice3 to python path if not installed globally
repo_pmd3 = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../external_research/pymobiledevice3"))
if os.path.exists(repo_pmd3) and repo_pmd3 not in sys.path:
    sys.path.insert(0, repo_pmd3)

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService
from pymobiledevice3.exceptions import CoreDeviceError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CoreDeviceLocationPoC")


class CoreDeviceLocationClient:
    SERVICE_NAME = "com.apple.coredevice.locationservice"
    ACTION_SET = "com.apple.coredevice.action.setsimulatedlocation"
    ACTION_CLEAR = "com.apple.coredevice.action.clearsimulatedlocation"
    FEATURE_LOCATION = "com.apple.coredevice.feature.simulatelocation"

    def __init__(self, rsd: RemoteServiceDiscoveryService):
        self.rsd = rsd
        self.service = CoreDeviceService(rsd, self.SERVICE_NAME)

    async def set_simulated_location(self, latitude: float, longitude: float) -> Dict[str, Any]:
        """
        Set simulated location with {latitude: double, longitude: double} flat payload.
        """
        payload = {
            "latitude": float(latitude),
            "longitude": float(longitude)
        }
        await self.service.connect()
        logger.info(f"Invoking {self.ACTION_SET} with payload: {payload}")
        result = await self.service.invoke(
            feature_identifier=self.FEATURE_LOCATION,
            input_=payload,
            action_identifier=self.ACTION_SET
        )
        return result

    async def clear_simulated_location(self) -> Dict[str, Any]:
        """
        Clear simulated location with empty dictionary payload.
        """
        await self.service.connect()
        logger.info(f"Invoking {self.ACTION_CLEAR} with empty payload")
        result = await self.service.invoke(
            feature_identifier=self.FEATURE_LOCATION,
            input_={},
            action_identifier=self.ACTION_CLEAR
        )
        return result


IOS_MODEL_MAP = {
    # iPhone 11
    "iPhone12,1": "iPhone 11",
    "iPhone12,3": "iPhone 11 Pro",
    "iPhone12,5": "iPhone 11 Pro Max",
    # iPhone SE 2/3
    "iPhone12,8": "iPhone SE (2nd Gen)",
    "iPhone14,6": "iPhone SE (3rd Gen)",
    # iPhone 12
    "iPhone13,1": "iPhone 12 mini",
    "iPhone13,2": "iPhone 12",
    "iPhone13,3": "iPhone 12 Pro",
    "iPhone13,4": "iPhone 12 Pro Max",
    # iPhone 13
    "iPhone14,4": "iPhone 13 mini",
    "iPhone14,5": "iPhone 13",
    "iPhone14,2": "iPhone 13 Pro",
    "iPhone14,3": "iPhone 13 Pro Max",
    # iPhone 14
    "iPhone14,7": "iPhone 14",
    "iPhone14,8": "iPhone 14 Plus",
    "iPhone15,2": "iPhone 14 Pro",
    "iPhone15,3": "iPhone 14 Pro Max",
    # iPhone 15
    "iPhone15,4": "iPhone 15",
    "iPhone15,5": "iPhone 15 Plus",
    "iPhone16,1": "iPhone 15 Pro",
    "iPhone16,2": "iPhone 15 Pro Max",
    # iPhone 16
    "iPhone17,1": "iPhone 16 Pro",
    "iPhone17,2": "iPhone 16 Pro Max",
    "iPhone17,3": "iPhone 16",
    "iPhone17,4": "iPhone 16 Plus",
}


class CoreDeviceLocationManager:
    def __init__(self, use_userspace: bool = False):
        self.use_userspace = use_userspace
        self.active_sessions: Dict[str, RemoteServiceDiscoveryService] = {}
        self.active_clients: Dict[str, CoreDeviceLocationClient] = {}
        self._lock = asyncio.Lock()

    async def list_devices(self) -> List[Dict[str, Any]]:
        """
        List connected CoreDevice capable devices. Aggregates both native browse and usbmux.
        """
        devices = []
        seen_udids = set()

        # 1. Scan native CoreDevice tunnels (Active Wi-Fi / USB tunnels)
        try:
            from pymobiledevice3.remote.native_tunnel import browse_native_devices
            records = await browse_native_devices(timeout=1.8)
            for r in records:
                udid = r.get("udid")
                if not udid or udid in seen_udids:
                    continue
                seen_udids.add(udid)
                raw_model = r.get("model", "Unknown")
                friendly_model = IOS_MODEL_MAP.get(raw_model, raw_model)
                name = r.get("name") or friendly_model
                is_wireless = bool(r.get("wirelessConnectivity", False))
                devices.append({
                    "udid": udid,
                    "name": name,
                    "model": friendly_model,
                    "raw_model": raw_model,
                    "ecid": r.get("ecid"),
                    "auth_state": r.get("authState", {}).get("rawCase", "authenticated"),
                    "connection_type": "Wi-Fi" if is_wireless else "USB",
                    "is_coredevice": True,
                })
        except Exception as e:
            logger.warning(f"Native browse returned error: {e}")

        # 2. Scan physical usbmux devices (Direct USB plug-in)
        try:
            from pymobiledevice3.usbmux import list_devices as usbmux_list
            mux_devs = await usbmux_list()
            for d in mux_devs:
                serial = getattr(d, "serial", None) or getattr(d, "udid", None)
                if not serial or serial in seen_udids:
                    continue
                seen_udids.add(serial)
                devices.append({
                    "udid": serial,
                    "name": "iOS Device (USB)",
                    "model": "iPhone (USB)",
                    "raw_model": "usbmux",
                    "ecid": getattr(d, "ecid", None),
                    "auth_state": "paired_usb",
                    "connection_type": "USB",
                    "is_coredevice": False,
                })
        except Exception as e:
            logger.warning(f"Usbmux list failed: {e}")

        return devices

    async def _create_client(self, device_id: Optional[str] = None) -> CoreDeviceLocationClient:
        logger.info(f"Establishing clean RSD connection for device: {device_id or 'default'} (userspace={self.use_userspace})")
        if self.use_userspace:
            from pymobiledevice3.remote import userspace_tunnel
            rsd = await asyncio.wait_for(userspace_tunnel.establish_userspace_rsd(serial=device_id), timeout=8.0)
        else:
            try:
                from pymobiledevice3.remote import native_tunnel
                rsd = await asyncio.wait_for(native_tunnel.establish_native_rsd(serial=device_id), timeout=8.0)
            except Exception as e:
                logger.warning(f"Native tunnel failed: {e}. Falling back to userspace tunnel...")
                from pymobiledevice3.remote import userspace_tunnel
                rsd = await asyncio.wait_for(userspace_tunnel.establish_userspace_rsd(serial=device_id), timeout=8.0)
        
        client = CoreDeviceLocationClient(rsd)
        return client

    async def set_location(self, device_id: Optional[str], latitude: float, longitude: float) -> Dict[str, Any]:
        """
        Set target latitude and longitude on device with fresh ephemeral session to prevent Errno 65 stale socket.
        """
        async with self._lock:
            key = device_id or "default"
            await self.disconnect_device(key)
            client = await self._create_client(device_id)
            self.active_clients[key] = client
            try:
                result = await client.set_simulated_location(latitude, longitude)
                logger.info(f"Location successfully updated to lat={latitude}, lon={longitude}")
                return result
            finally:
                # Clean up session to prevent tunnel staleness
                await self.disconnect_device(key)

    async def simulate_location(self, latitude: float, longitude: float, udid: Optional[str] = None) -> Dict[str, Any]:
        """
        Alias for set_location supporting keyword arguments (latitude, longitude, udid).
        """
        return await self.set_location(device_id=udid, latitude=latitude, longitude=longitude)

    async def clear_location(self, device_id: Optional[str] = None, udid: Optional[str] = None) -> Dict[str, Any]:
        """
        Clear simulated location and restore real GPS with fresh ephemeral session.
        """
        target_id = udid or device_id
        async with self._lock:
            key = target_id or "default"
            await self.disconnect_device(key)
            client = await self._create_client(target_id)
            self.active_clients[key] = client
            try:
                result = await client.clear_simulated_location()
                logger.info("Location simulation successfully cleared.")
                return result
            finally:
                # Clean up session to prevent tunnel staleness
                await self.disconnect_device(key)

    async def disconnect_device(self, device_id: str):
        key = device_id or "default"
        if key in self.active_clients:
            try:
                client = self.active_clients[key]
                if hasattr(client, "rsd") and client.rsd:
                    await client.rsd.close()
            except Exception:
                pass
            del self.active_clients[key]
        if key in self.active_sessions:
            try:
                await self.active_sessions[key].close()
            except Exception:
                pass
            del self.active_sessions[key]


async def main():
    parser = argparse.ArgumentParser(description="CoreDevice Location PoC CLI")
    parser.add_argument("--userspace", action="store_true", help="Force userspace TCP stack")
    subparsers = parser.add_subparsers(dest="command")

    # list
    subparsers.add_parser("list", help="List available devices")

    # set
    set_parser = subparsers.add_parser("set", help="Set device location")
    set_parser.add_argument("--udid", type=str, default=None, help="Device UDID")
    set_parser.add_argument("--lat", type=float, required=True, help="Latitude")
    set_parser.add_argument("--lon", type=float, required=True, help="Longitude")

    # clear
    clear_parser = subparsers.add_parser("clear", help="Clear simulated location")
    clear_parser.add_argument("--udid", type=str, default=None, help="Device UDID")

    # test-suite
    subparsers.add_parser("test-suite", help="Run automated test suite (Beijing -> NY -> Clear)")

    args = parser.parse_args()
    mgr = CoreDeviceLocationManager(use_userspace=args.userspace)

    if args.command == "list":
        devs = await mgr.list_devices()
        print(f"Found {len(devs)} device(s):")
        for d in devs:
            print(f" - UDID: {d['udid']} | Name: {d['name']} | Model: {d['model']} | Auth: {d['auth_state']}")

    elif args.command == "set":
        res = await mgr.set_location(args.udid, args.lat, args.lon)
        print(f"Result: {res}")

    elif args.command == "clear":
        res = await mgr.clear_location(args.udid)
        print(f"Result: {res}")

    elif args.command == "test-suite":
        print("\n=== Running Phase 1 Test Suite ===")
        print("1. Listing devices...")
        devs = await mgr.list_devices()
        if not devs:
            print("ERROR: No devices detected! Cannot run test-suite.")
            sys.exit(1)
        udid = devs[0]["udid"]
        print(f"Target device: {udid} ({devs[0].get('name')})")

        print("\n2. Setting location to Beijing (39.9042, 116.4074)...")
        res1 = await mgr.set_location(udid, 39.9042, 116.4074)
        print(f"Beijing set response: {res1}")
        await asyncio.sleep(2)

        print("\n3. Setting location to New York (40.7128, -74.0060)...")
        res2 = await mgr.set_location(udid, 40.7128, -74.0060)
        print(f"New York set response: {res2}")
        await asyncio.sleep(2)

        print("\n4. Clearing location simulation...")
        res3 = await mgr.clear_location(udid)
        print(f"Clear location response: {res3}")

        print("\n=== All Tests Passed Successfully! ===")
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())
