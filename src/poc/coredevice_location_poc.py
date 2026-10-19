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
import math
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Callable, Dict, List, Optional

# pymobiledevice3 以 pip 安装版为准（与 CI 打包环境一致）；vendored 副本仅作未安装时的兜底，
# append 到搜索路径末尾，保证 pip 版存在时永远优先于 vendored 版
repo_pmd3 = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../external_research/pymobiledevice3"))
if os.path.exists(repo_pmd3) and repo_pmd3 not in sys.path:
    sys.path.append(repo_pmd3)

from pymobiledevice3.remote.remote_service_discovery import RemoteServiceDiscoveryService
from pymobiledevice3.remote.core_device.core_device_service import CoreDeviceService

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CoreDeviceLocationPoC")


def _validate_location_coordinates(latitude: Any, longitude: Any) -> tuple[float, float]:
    """Validate public location inputs before opening or reusing a device session."""
    if (not isinstance(latitude, (int, float)) or isinstance(latitude, bool)
            or not isinstance(longitude, (int, float)) or isinstance(longitude, bool)):
        raise ValueError("latitude and longitude must be numeric coordinates")
    try:
        lat = float(latitude)
        lon = float(longitude)
    except OverflowError as exc:
        raise ValueError("latitude and longitude must be finite numbers") from exc
    if not math.isfinite(lat) or not math.isfinite(lon):
        raise ValueError("latitude and longitude must be finite numbers")
    if not -90.0 <= lat <= 90.0:
        raise ValueError("latitude must be between -90 and 90 degrees")
    if not -180.0 <= lon <= 180.0:
        raise ValueError("longitude must be between -180 and 180 degrees")
    return lat, lon


class DeveloperModeDisabledError(RuntimeError):
    """iPhone 未开启开发者模式：确定性错误，重建会话无济于事，须原样透传给前端引导。"""


class UserspaceSlotBusyError(RuntimeError):
    """进程内 userspace 隧道单例已被其它设备占用（仅 darwin 原生回退路径抛出）。

    多设备路由层（src/backend/multi_device.py）捕获本错误后把该设备分流到独立
    worker 进程重试，保证「设备 B 建链绝不驱逐设备 A」。
    """


class PerDeviceLocks:
    """按设备 UDID 独立的 asyncio 锁集合（多设备并行的基础）。

    - 不同 key 互不阻塞：写设备 A 不再等设备 B 的隧道操作
    - 同 key 严格串行：同设备的写入/清理/断开顺序正确
    - 同一 task 持有 key 锁时再次申请同锁：立即 RuntimeError 快速失败，
      而不是 asyncio.Lock 默认的静默死锁
    - 资源有界：引用计数归零的空闲锁可被回收；活跃 key 数量超过
      MAX_KEYS（纯工程护栏，非商业设备限制）时拒绝新 key
    """

    MAX_KEYS = 64

    def __init__(self, max_keys: Optional[int] = None):
        self.max_keys = max_keys or self.MAX_KEYS
        self._locks: Dict[str, asyncio.Lock] = {}
        self._owners: Dict[str, Optional[asyncio.Task]] = {}
        # 引用在 acquire() 入口同步递增、在 finally 归零：rc==0 意味着既无
        # 持有者也无等待者，对应的锁对象可以安全从字典移除（事件循环内原子）
        self._refcounts: Dict[str, int] = {}

    @asynccontextmanager
    async def acquire(self, key: str) -> AsyncIterator[None]:
        lock = self._locks.get(key)
        if lock is None:
            if len(self._locks) >= self.max_keys:
                self.prune_idle()
                if len(self._locks) >= self.max_keys:
                    raise RuntimeError(
                        f"too many distinct device keys (resource limit {self.max_keys})"
                    )
            lock = self._locks[key] = asyncio.Lock()
        self._refcounts[key] = self._refcounts.get(key, 0) + 1
        task = asyncio.current_task()
        if self._owners.get(key) is task and lock.locked():
            self._refcounts[key] -= 1
            raise RuntimeError(
                f"Recursive lock acquisition detected for device '{key}'; "
                "this would deadlock and indicates a caller bug"
            )
        try:
            async with lock:
                self._owners[key] = task
                try:
                    yield
                finally:
                    if self._owners.get(key) is task:
                        self._owners[key] = None
        finally:
            self._refcounts[key] -= 1
            if self._refcounts[key] <= 0:
                self._refcounts.pop(key, None)

    def prune_idle(self, key: Optional[str] = None) -> None:
        """回收无持有者且无等待者的锁对象；指定 key 时仅尝试该 key。"""
        candidates = [key] if key is not None else list(self._locks.keys())
        for k in candidates:
            if k in self._locks and self._refcounts.get(k, 0) == 0:
                self._locks.pop(k, None)
                self._owners.pop(k, None)
                self._refcounts.pop(k, None)

    def active_key_count(self) -> int:
        return len(self._locks)

    def all_keys(self) -> List[str]:
        return list(self._locks.keys())


# 单次定位写入全链路（devmode 查询 + connect + invoke + 回退链）的超时预算。
# 隧道黑洞化时 connect() 会挂满 OS 级 TCP SYN 超时（macOS 默认 75s）并占住
# manager 全局锁，把整个定位 API 冻结一分多钟，必须在此提前掐断按会话失活处理
INVOKE_TIMEOUT_S = 15.0
# DDI 挂载（首次可能含镜像下载）预算：慢但必须有界
MOUNT_TIMEOUT_S = 120.0


class CoreDeviceLocationClient:
    SERVICE_NAME = "com.apple.coredevice.locationservice"
    ACTION_SET = "com.apple.coredevice.action.setsimulatedlocation"
    ACTION_CLEAR = "com.apple.coredevice.action.clearsimulatedlocation"
    FEATURE_LOCATION = "com.apple.coredevice.feature.simulatelocation"

    def __init__(self, rsd: RemoteServiceDiscoveryService, tunnel: Optional[Any] = None,
                 tunnel_kind: Optional[str] = None):
        self.rsd = rsd
        # 持有隧道句柄：请求结束后由 manager aclose，连带释放 RSD 连接与隧道本体
        self.tunnel = tunnel
        # "native"（macOS remoted 托管，天然多设备并行）/ "userspace"（进程级
        # PyTCP 单例，同进程同时至多一个）——驱逐/槽位管理按此判别
        self.tunnel_kind = tunnel_kind
        self.service = CoreDeviceService(rsd, self.SERVICE_NAME)
        # 会话内已确认开发者模式开启：避免巡航 10Hz 下每次写入都多一趟远端查询
        self._dev_mode_verified = False

    async def set_simulated_location(self, latitude: float, longitude: float) -> Dict[str, Any]:
        """
        Set simulated location with {latitude: double, longitude: double} flat payload.
        Supports CoreDevice LocationService with automatic fallback to DtSimulateLocation and auto_mount.
        """
        latitude, longitude = _validate_location_coordinates(latitude, longitude)

        # 1. Check Developer Mode status first（会话内只查一次，查询不可用时也不再重试刷日志）
        if not self._dev_mode_verified and hasattr(self.rsd, "get_developer_mode_status"):
            try:
                is_dev = await self.rsd.get_developer_mode_status()
                if not is_dev:
                    raise DeveloperModeDisabledError("您的 iPhone 尚未开启【开发者模式】。请在手机「设置 ➔ 隐私与安全性 ➔ 开发者模式」中开启并重启手机。")
                self._dev_mode_verified = True
            except Exception as e:
                if isinstance(e, DeveloperModeDisabledError):
                    raise
                logger.warning(f"Developer mode check error: {e}")
                self._dev_mode_verified = True

        payload = {
            "latitude": float(latitude),
            "longitude": float(longitude)
        }

        # 2. Preferred: CoreDevice LocationService (iOS 17+ native tunnel)
        try:
            await self.service.connect()
            logger.info(f"Invoking {self.ACTION_SET} with payload: {payload}")
            result = await self.service.invoke(
                feature_identifier=self.FEATURE_LOCATION,
                input_=payload,
                action_identifier=self.ACTION_SET
            )
            return result
        except Exception as e:
            if "No such service" in str(e):
                # DDI 未挂载的标志性错误：必须透传给 manager 触发 auto_mount，
                # 不能被 DVT/DtSimulateLocation 回退链吞掉
                raise
            logger.warning(f"CoreDevice locationservice invocation failed: {e}. Trying DVT Instruments...")
        finally:
            # 巡航/摇杆是背靠背高频调用，必须每次释放服务连接，否则设备侧会话持续累积
            try:
                await self.service.close()
            except Exception:
                pass

        # 3. Standard iOS 17+ channel: DVT Instruments LocationSimulation
        try:
            from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
            from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
            async with DvtProvider(self.rsd) as dvt, LocationSimulation(dvt) as location_simulation:
                await location_simulation.set(latitude, longitude)
            logger.info("Successfully set location via iOS 17+ DVT Instruments LocationSimulation!")
            return {"status": "ok", "service": "com.apple.instruments.server.services.LocationSimulation"}
        except Exception as dvt_e:
            logger.warning(f"DVT Instruments fallback failed: {dvt_e}")

        # 4. Fallback: DtSimulateLocation (iOS <= 16 Lockdown Developer service)
        try:
            from pymobiledevice3.services.simulate_location import DtSimulateLocation
            dt_loc = DtSimulateLocation(self.rsd)
            await dt_loc.set(latitude, longitude)
            logger.info("Successfully set location via fallback DtSimulateLocation!")
            return {"status": "ok", "service": "com.apple.dt.simulatelocation"}
        except Exception as dt_e:
            logger.warning(f"DtSimulateLocation fallback failed: {dt_e}")

        raise RuntimeError(
            "未检测到可用定位服务。请确认 iPhone 已开启【开发者模式】并重启过手机后重试。"
        )

    async def clear_simulated_location(self) -> Dict[str, Any]:
        """
        Clear simulated location with empty dictionary payload.
        Supports CoreDevice LocationService with automatic fallback to DVT Instruments.
        """
        # 1. Preferred: CoreDevice LocationService
        try:
            await self.service.connect()
            logger.info(f"Invoking {self.ACTION_CLEAR} with empty payload")
            result = await self.service.invoke(
                feature_identifier=self.FEATURE_LOCATION,
                input_={},
                action_identifier=self.ACTION_CLEAR
            )
            return result
        except Exception as e:
            if "No such service" in str(e):
                # 同 set：透传给 manager 触发 auto_mount
                raise
            logger.warning(f"CoreDevice clear location failed: {e}. Trying DVT Instruments...")
        finally:
            try:
                await self.service.close()
            except Exception:
                pass

        # 2. Standard iOS 17+ channel: DVT Instruments LocationSimulation
        try:
            from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
            from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
            async with DvtProvider(self.rsd) as dvt, LocationSimulation(dvt) as location_simulation:
                await location_simulation.clear()
            logger.info("Successfully cleared location via iOS 17+ DVT Instruments LocationSimulation!")
            return {"status": "ok", "service": "com.apple.instruments.server.services.LocationSimulation"}
        except Exception as dvt_e:
            logger.warning(f"DVT Instruments clear failed: {dvt_e}")

        # 3. Fallback: DtSimulateLocation (iOS <= 16)
        try:
            from pymobiledevice3.services.simulate_location import DtSimulateLocation
            dt_loc = DtSimulateLocation(self.rsd)
            await dt_loc.clear()
            logger.info("Successfully cleared location via fallback DtSimulateLocation!")
            return {"status": "ok", "service": "com.apple.dt.simulatelocation"}
        except Exception as dt_e:
            logger.warning(f"DtSimulateLocation clear failed: {dt_e}")

        raise RuntimeError("无法恢复真实定位，请检查设备连接。")


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
        self.active_clients: Dict[str, CoreDeviceLocationClient] = {}
        # 按 UDID 独立的锁：不同设备写入互不等待；同设备写入/清理/断开串行
        self._locks = PerDeviceLocks()
        # 进程内 userspace（PyTCP 栈）单例槽位的当前占用者 UDID；None = 空闲。
        # native 隧道不受此槽位约束（由系统 remoted 托管，天然多设备并行）。
        self._userspace_slot: Optional[str] = None
        # shutdown 后置位：新请求立即失败，不再悄悄创建会话
        self._closed = False

    @property
    def userspace_slot_holder(self) -> Optional[str]:
        """当前占用进程内 userspace 隧道单例的设备 UDID（供多设备路由层决策）。"""
        return self._userspace_slot

    async def list_devices(self) -> List[Dict[str, Any]]:
        """
        List connected CoreDevice capable devices. Aggregates both native browse and usbmux.
        """
        devices = []
        seen_udids = set()

        # 1. Scan native CoreDevice tunnels (Active Wi-Fi / USB tunnels on macOS only)
        if sys.platform == "darwin":
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
                    # remotepairingd 会把「有配对记录」的设备都报出来（Xcode 灰色设备同源）。
                    # connectionState 只反映「当前是否存在活动连接」：connected=在链；
                    # available 既可能是关机/离网，也可能是空闲在网（实测 available 状态下
                    # 按需建链写入依然成功），没有任何字段能进一步区分二者——
                    # 真实可达性只有尝试建隧道才知道（失败时由 _create_client 给出引导）。
                    # wirelessConnectivity 不能用作在线判据——它对离线设备仍为真值
                    conn_state = r.get("connectionState")
                    if isinstance(conn_state, dict):
                        state_str = str(conn_state.get("rawCase", "unknown"))
                    else:
                        state_str = "connected" if conn_state else "unknown"

                    dev_mode = None
                    kvs = r.get("deviceKVSData")
                    if kvs:
                        try:
                            from pymobiledevice3.remote.remote_service_discovery import parse_device_kvs_data
                            parsed_kvs = parse_device_kvs_data(kvs)
                            amfi = parsed_kvs.get("com.apple.security.mac.amfi", {})
                            if "DeveloperModeStatus" in amfi:
                                dev_mode = bool(amfi["DeveloperModeStatus"])
                        except Exception as kvs_e:
                            logger.debug(f"Failed to parse deviceKVSData for {udid}: {kvs_e}")

                    # remotepairingd 中：connected=已有活动隧道；available=在局域网(Wi-Fi)或有线中就绪可用
                    is_online = state_str in ("connected", "available")

                    devices.append({
                        "udid": udid,
                        "name": name,
                        "model": friendly_model,
                        "raw_model": raw_model,
                        "ecid": r.get("ecid"),
                        "auth_state": r.get("authState", {}).get("rawCase", "authenticated"),
                        "connection_type": "Wi-Fi" if is_wireless else "USB",
                        "is_coredevice": True,
                        "online": is_online,
                        "connection_state": state_str,
                        "developer_mode": dev_mode,
                    })
            except Exception as e:
                logger.warning(f"Native browse returned error: {e}")

        # 2. Scan physical usbmux devices (Direct USB plug-in)
        try:
            from pymobiledevice3.usbmux import list_devices as usbmux_list
            from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
            mux_devs = await usbmux_list()

            mux_serials = set()
            for d in mux_devs:
                s = getattr(d, "serial", None) or getattr(d, "udid", None)
                if s:
                    mux_serials.add(s)

            # 物理 USB 链路判定：物理直连权重最高。若设备已在 native browse 中出现，
            # 但只要存在于 usbmux 物理设备列表中，则明确判定为在线且通道为 USB
            for dev in devices:
                if dev.get("udid") in mux_serials:
                    dev["online"] = True
                    dev["connection_type"] = "USB"
                    dev["connection_state"] = "connected"

            async def probe_mux_device(serial: str, ecid: Any) -> Dict[str, Any]:
                dev_entry = {
                    "udid": serial,
                    "name": "iOS Device (USB)",
                    "model": "iPhone (USB)",
                    "raw_model": "usbmux",
                    "ecid": ecid,
                    "auth_state": "paired_usb",
                    "connection_type": "USB",
                    "is_coredevice": False,
                    "online": True,
                    "developer_mode": None,
                }
                # Check developer mode status & auto-reveal option in Settings UI
                try:
                    from pymobiledevice3.lockdown import create_using_usbmux
                    from pymobiledevice3.services.amfi import AmfiService
                    # 本接口被前端每 4 秒轮询：未配对设备若无限等待信任对话框，
                    # 每次轮询都会新挂起一个协程，必须限时返回
                    lk = await create_using_usbmux(serial=serial, pair_timeout=2.0)
                    try:
                        if hasattr(lk, "get_developer_mode_status"):
                            dev_on = await lk.get_developer_mode_status()
                            dev_entry["developer_mode"] = dev_on
                            if dev_on is False:
                                try:
                                    await AmfiService(lk).reveal_developer_mode_option_in_ui()
                                    dev_entry["developer_mode_revealed"] = True
                                    logger.info(f"Auto-revealed Developer Mode toggle in UI for {serial}")
                                except Exception as rev_e:
                                    logger.debug(f"Auto-reveal notice: {rev_e}")
                    finally:
                        # 轮询高频调用，必须显式关闭 usbmux 连接，否则 socket 无限累积
                        try:
                            await lk.close()
                        except Exception:
                            pass
                except Exception as lk_e:
                    logger.debug(f"Device lockdown probe error for {serial}: {lk_e}")
                return dev_entry

            candidates = []
            for d in mux_devs:
                serial = getattr(d, "serial", None) or getattr(d, "udid", None)
                if not serial or serial in seen_udids:
                    continue
                seen_udids.add(serial)
                candidates.append((serial, getattr(d, "ecid", None)))
            # 并行探测：多台未信任设备时避免 2s/台的串行配对等待把接口拖过前端超时预算
            if candidates:
                devices.extend(
                    await asyncio.gather(*(probe_mux_device(serial, ecid) for serial, ecid in candidates))
                )
        except Exception as e:
            from pymobiledevice3.exceptions import ConnectionFailedToUsbmuxdError
            if isinstance(e, ConnectionFailedToUsbmuxdError):
                if sys.platform == "win32":
                    logger.warning("[!] Windows 未检测到 Apple 移动设备服务 (Apple Mobile Device Service)。请安装 iTunes (官方64位版) 或启动该服务以连接 iPhone。")
                elif sys.platform.startswith("linux"):
                    logger.warning("[!] Linux 无法连接 /var/run/usbmuxd。请运行 'sudo systemctl start usbmuxd'。")
                else:
                    logger.warning("[!] 无法连接本地 usbmuxd 套接字。")
            else:
                logger.warning(f"Usbmux list failed: {type(e).__name__} - {e}")

        return devices

    async def _create_client(self, device_id: Optional[str] = None, create_key: Optional[str] = None) -> CoreDeviceLocationClient:
        logger.info(f"Establishing clean RSD connection for device: {device_id or 'default'} (userspace={self.use_userspace})")
        tunnel = None
        if self.use_userspace or sys.platform != "darwin":
            from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
            # 官方建议嵌入方直接持有隧道句柄：CLI 包装器会把隧道缓存在模块全局里，
            # 换第二台设备时永远命中旧缓存而失败。直接构造 + 用完 aclose 即天然 ephemeral。
            tunnel = UserspaceRsdTunnel(serial=device_id)
            try:
                rsd = await asyncio.wait_for(tunnel.aopen(), timeout=8.0)
            except Exception as e:
                if "already active" not in str(e):
                    raise
                # PyTCP 栈是进程级单例：同进程内另一台设备的会话常驻时，本设备建不了隧道。
                # 驱逐范围严格限定为「同样经由 userspace 隧道建立的会话」（多设备路由下
                # 至多一个），native 隧道会话（macOS remoted 托管）绝不受牵连。
                # 正常多设备流量在到达此处之前已被上层路由分流到独立 worker 进程，
                # 这里只保留单进程直用（CLI / 旧单设备语义）时的「后请求者让位重试」。
                logger.warning(f"Userspace tunnel singleton held by another device session; evicting ({e})")
                for k in list(self.active_clients):
                    if k == create_key:
                        continue  # 绝不驱逐正在创建中的目标设备自身（避免递归申请同锁）
                    victim = self.active_clients.get(k)
                    if victim is not None and getattr(victim, "tunnel_kind", None) == "userspace":
                        # 其它设备：走 public 断开（与其在飞操作串行，不抽走在飞隧道）
                        await self.disconnect_device(k)
                try:
                    await tunnel.aclose()
                except Exception:
                    pass
                tunnel = UserspaceRsdTunnel(serial=device_id)
                rsd = await asyncio.wait_for(tunnel.aopen(), timeout=8.0)
            return CoreDeviceLocationClient(rsd, tunnel=tunnel, tunnel_kind="userspace")
        else:
            try:
                from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
                tunnel = NativeRemotedTunnel(serial=device_id)
                # native 建链内部含最长 ~10s 的 browse + XPC 等待；超时取消会留下收不了尾的
                # 孤儿线程（asyncio.to_thread 取消不掉），所以预算给足 20s，只兜真正的挂死
                rsd = await asyncio.wait_for(tunnel.aopen(), timeout=20.0)
                # native 隧道由系统 remoted 托管，不同 UDID 各自独立——绝无驱逐语义
                return CoreDeviceLocationClient(rsd, tunnel=tunnel, tunnel_kind="native")
            except Exception as e:
                logger.warning(f"Native tunnel failed: {e}. Falling back to userspace tunnel...")
                if tunnel is not None:
                    try:
                        await tunnel.aclose()
                    except Exception:
                        pass
                from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
                tunnel = UserspaceRsdTunnel(serial=device_id)
                try:
                    rsd = await asyncio.wait_for(tunnel.aopen(), timeout=8.0)
                except Exception as ue:
                    if "already active" in str(ue):
                        # darwin 回退路径绝不允许驱逐其它设备（可能是 native 会话的所有者）。
                        # 抛出可识别错误让上层路由把本设备分流到独立 worker 进程。
                        logger.warning(
                            f"Userspace fallback for {device_id or 'default'} blocked: in-process slot busy"
                        )
                        try:
                            await tunnel.aclose()
                        except Exception:
                            pass
                        raise UserspaceSlotBusyError(
                            "userspace tunnel slot in this process is held by another device"
                        ) from ue
                    raise
                return CoreDeviceLocationClient(rsd, tunnel=tunnel, tunnel_kind="userspace")

    async def _create_client_checked(self, device_id: Optional[str], key: str) -> CoreDeviceLocationClient:
        """_create_client 的门面：建链失败时把「设备不在线」翻译成可引导的中文错误并缓存新会话。"""
        if self._closed:
            raise RuntimeError("manager 已关闭：连接器正在退出，不再建立新会话")
        client = None
        try:
            client = await self._create_client(device_id, create_key=key)
            if self._closed:
                if getattr(client, "tunnel", None) is not None:
                    await client.tunnel.aclose()
                elif getattr(client, "rsd", None) is not None:
                    await client.rsd.close()
                raise RuntimeError("manager 已关闭：连接器正在退出，会话已撤销")
            self.active_clients[key] = client
            if getattr(client, "tunnel_kind", None) == "userspace":
                self._userspace_slot = key
            return client
        except BaseException as e:
            if client is not None and key not in self.active_clients:
                try:
                    if getattr(client, "tunnel", None) is not None:
                        await client.tunnel.aclose()
                    elif getattr(client, "rsd", None) is not None:
                        await client.rsd.close()
                except Exception:
                    pass
            if isinstance(e, Exception) and "no device matching" in str(e).lower():
                raise RuntimeError(
                    "iPhone 当前不在线：请确认手机已开机、解锁，并与本机处于同一 Wi-Fi（或改用数据线连接）后重试。"
                ) from e
            raise

    async def _run_device_op(self, key: str, device_id: Optional[str], invoke) -> Dict[str, Any]:
        """单设备操作的统一执行器：per-UDID 锁 + 会话复用 + 失活重建 + DDI 自动挂载。

        - 锁粒度是 key（设备 UDID）：设备 A 的慢操作（建链/挂载/重试）只阻塞设备 A，
          不再冻结其它设备的写入。
        - 会话失活（Errno 65 / 设备重启 / 写入超时）时丢弃重建并重试一次。
        - "No such service"（DDI 未挂载）时借当前 RSD 会话挂载镜像后换新会话重试。
        - 最终失败（含取消）：只丢弃该设备自己的会话，其它设备不受牵连。
        """
        async with self._locks.acquire(key):
            if self._closed:
                raise RuntimeError("manager已关闭：连接器正在退出，不再接受定位操作")
            client = self.active_clients.get(key)
            if client is None:
                client = await self._create_client_checked(device_id, key)
            if self._closed:
                raise RuntimeError("manager已关闭：连接器正在退出，不再接受定位操作")
            try:
                for attempt in (0, 1):  # 0=复用缓存会话, 1=丢弃重建后重试
                    if attempt == 1:
                        logger.warning(f"Rebuilding tunnel session for {key}...")
                        await self._disconnect_device_unlocked(key)
                        client = await self._create_client_checked(device_id, key)
                    try:
                        result = await asyncio.wait_for(invoke(client), timeout=INVOKE_TIMEOUT_S)
                        return result
                    except Exception as e:
                        if isinstance(e, DeveloperModeDisabledError):
                            # 确定性错误，重建会话也不会好转，直接透传
                            raise
                        if "No such service" in str(e):
                            # DDI 未挂载：借当前还活着的 RSD 会话挂载开发者镜像，换新会话重试。
                            # 首试与重建后的重试都可能命中（重建后服务枚举存在竞态），两处都必须处理
                            logger.info(f"Developer location service not yet activated on {key}. Attempting auto_mount DDI...")
                            try:
                                from pymobiledevice3.services.mobile_image_mounter import auto_mount
                                await asyncio.wait_for(auto_mount(client.rsd), timeout=MOUNT_TIMEOUT_S)
                                logger.info("DDI successfully mounted! Re-establishing fresh RSD session...")
                            except Exception:
                                logger.warning(f"auto_mount failed on {key}; giving up this request")
                                raise e
                            await self._disconnect_device_unlocked(key)
                            client = await self._create_client_checked(device_id, key)
                            result = await asyncio.wait_for(invoke(client), timeout=INVOKE_TIMEOUT_S)
                            return result
                        if attempt == 0:
                            logger.warning(f"Reused session failed ({e}); rebuilding tunnel session...")
                            continue
                        raise
            except BaseException:
                # 请求最终失败（含重试失败/超时/客户端取消）：只丢弃该设备会话，不给下次调用留坏句柄
                try:
                    await self._disconnect_device_unlocked(key)
                except Exception:
                    pass
                raise

    async def set_location(self, device_id: Optional[str], latitude: float, longitude: float) -> Dict[str, Any]:
        """
        Set target latitude and longitude on device.
        会话常驻复用：首次调用建立隧道并缓存在 active_clients，后续调用直接复用，
        把巡航/摇杆高频写入从「每次整链重建 ~1.6s」降到单次服务调用的亚秒级。
        """
        latitude, longitude = _validate_location_coordinates(latitude, longitude)
        key = device_id or "default"

        async def invoke(client):
            result = await client.set_simulated_location(latitude, longitude)
            logger.info(f"Location successfully updated to lat={latitude}, lon={longitude}")
            return result

        return await self._run_device_op(key, device_id, invoke)

    async def simulate_location(self, latitude: float, longitude: float, udid: Optional[str] = None) -> Dict[str, Any]:
        """
        Alias for set_location supporting keyword arguments (latitude, longitude, udid).
        """
        return await self.set_location(device_id=udid, latitude=latitude, longitude=longitude)

    async def clear_location(self, device_id: Optional[str] = None, udid: Optional[str] = None) -> Dict[str, Any]:
        """
        Clear simulated location and restore real GPS（会话常驻复用，同 set_location）。
        """
        target_id = udid or device_id
        key = target_id or "default"

        async def invoke(client):
            result = await client.clear_simulated_location()
            logger.info("Location simulation successfully cleared.")
            return result

        return await self._run_device_op(key, target_id, invoke)

    async def get_developer_mode_status(self, device_id: Optional[str] = None) -> Optional[bool]:
        """
        Check if Developer Mode is enabled on device.
        Supports both USB (usbmux lockdown) and Wi-Fi (active tunnel RSD & native browse KVS).
        """
        key = device_id or "default"
        # 1. 优先从已有活动隧道会话获取
        if key in self.active_clients:
            client = self.active_clients[key]
            if hasattr(client.rsd, "get_developer_mode_status"):
                try:
                    return await client.rsd.get_developer_mode_status()
                except Exception as rsd_e:
                    logger.debug(f"rsd get_developer_mode_status error for {key}: {rsd_e}")

        # 2. 从 macOS native browse 的 deviceKVSData 中解析（毫秒级，完美支持 Wi-Fi 设备）
        if sys.platform == "darwin":
            try:
                from pymobiledevice3.remote.native_tunnel import browse_native_devices
                from pymobiledevice3.remote.remote_service_discovery import parse_device_kvs_data
                records = await browse_native_devices(timeout=1.2)
                for r in records:
                    if not device_id or r.get("udid") == device_id:
                        kvs = r.get("deviceKVSData")
                        if kvs:
                            parsed = parse_device_kvs_data(kvs)
                            amfi = parsed.get("com.apple.security.mac.amfi", {})
                            if "DeveloperModeStatus" in amfi:
                                return bool(amfi["DeveloperModeStatus"])
            except Exception as kvs_e:
                logger.debug(f"native browse get_developer_mode_status error for {key}: {kvs_e}")

        # 3. 尝试 USB lockdown 通道（仅物理连入 USB 时可用）
        lockdown = None
        try:
            from pymobiledevice3.lockdown import create_using_usbmux
            lockdown = await create_using_usbmux(serial=device_id, pair_timeout=1.5)
            if hasattr(lockdown, "get_developer_mode_status"):
                return await lockdown.get_developer_mode_status()
        except Exception as e:
            logger.debug(f"usbmux get_developer_mode_status failed: {e}")
        finally:
            if lockdown is not None:
                try:
                    await lockdown.close()
                except Exception:
                    pass
        return None

    async def reveal_developer_mode(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Reveal hidden Developer Mode toggle in iOS Settings -> Privacy & Security.
        """
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.amfi import AmfiService
        lockdown = None
        try:
            lockdown = await create_using_usbmux(serial=device_id, pair_timeout=2.0)
            amfi = AmfiService(lockdown)
            await amfi.reveal_developer_mode_option_in_ui()
            logger.info(f"Successfully revealed developer mode option in UI for {device_id or 'default'}")
            return {
                "success": True,
                "revealed": True,
                "message": "已成功在 iPhone 上点亮【开发者模式】入口！请打开手机「设置 ➔ 隐私与安全性 ➔ 开发者模式」开启并重启手机。"
            }
        except Exception as e:
            logger.error(f"Failed to reveal developer mode: {e}")
            raise RuntimeError("点亮开发者模式失败：请用 USB 数据线连接手机、解锁并点击「信任此电脑」后重试。")
        finally:
            if lockdown is not None:
                try:
                    await lockdown.close()
                except Exception:
                    pass

    async def enable_developer_mode(self, device_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Trigger Developer Mode activation.
        First reveals the UI option, then sends enable request.
        Handles passcode protection gracefully.
        """
        from pymobiledevice3.lockdown import create_using_usbmux
        from pymobiledevice3.services.amfi import AmfiService
        from pymobiledevice3.exceptions import DeviceHasPasscodeSetError

        try:
            # 用户主动点击的操作：给手机上的信任弹窗留出等待时间
            lockdown = await create_using_usbmux(serial=device_id, pair_timeout=15.0)
        except Exception as e:
            logger.error(f"enable_developer_mode connect failed: {e}")
            raise RuntimeError("未能通过 USB 连接手机。请用数据线连接手机、解锁并点击「信任此电脑」后重试（Wi-Fi 连接的设备暂不支持此操作）。")
        try:
            amfi = AmfiService(lockdown)

            # 1. 确保 UI 入口首先点亮
            try:
                await amfi.reveal_developer_mode_option_in_ui()
            except Exception as e:
                logger.debug(f"reveal in enable_developer_mode notice: {e}")

            # 2. 检查是否已经开启
            try:
                if hasattr(lockdown, "get_developer_mode_status") and await lockdown.get_developer_mode_status():
                    return {
                        "success": True,
                        "already_enabled": True,
                        "rebooting": False,
                        "message": "iPhone 当前已处于【开发者模式】，无需重复开启！"
                    }
            except Exception:
                pass

            # 3. 尝试直接触发开启并重启
            try:
                await amfi.enable_developer_mode(enable_post_restart=False)
                logger.info(f"Triggered developer mode reboot on {device_id or 'default'}")
                return {
                    "success": True,
                    "rebooting": True,
                    "has_passcode": False,
                    "message": "已向 iPhone 发送开启指令，手机即将自动重启！开机后请点击屏幕上的【开启】并确认即可。"
                }
            except DeviceHasPasscodeSetError:
                logger.info("Device has passcode set. Revealed UI option successfully.")
                return {
                    "success": True,
                    "rebooting": False,
                    "has_passcode": True,
                    "revealed": True,
                    "message": "已成功在 iPhone 上点亮隐藏的【开发者模式】！由于您的手机设有锁屏密码，苹果系统要求机主手动确认：请前往手机「设置 ➔ 隐私与安全性 ➔ 开发者模式」开启并重启输入密码。"
                }
            except Exception as e:
                logger.error(f"enable_developer_mode error: {e}")
                return {
                    "success": False,
                    "rebooting": False,
                    "revealed": False,
                    "message": "开启指令发送失败。请重试一次；若仍失败，请在 iPhone「设置 ➔ 隐私与安全性 ➔ 开发者模式」手动开启。"
                }
        finally:
            try:
                await lockdown.close()
            except Exception:
                pass

    async def disconnect_device(self, device_id: str):
        """Public 按设备断开：与 set/clear 同设备串行（per-UDID 锁），
        不会在写入在飞时抽走它的隧道；其它设备的会话不受影响。"""
        key = device_id or "default"
        async with self._locks.acquire(key):
            await self._disconnect_device_unlocked(key)
        self._locks.prune_idle(key)  # 无持有者/等待者时回收锁对象，防字典无界

    async def _disconnect_device_unlocked(self, key: str):
        """内部清理：调用方必须已持有 key 的设备锁（_run_device_op 重试/失败路径
        与 shutdown 逐设备清理），绝不递归申请同锁。"""
        client = self.active_clients.pop(key, None)
        if client is not None:
            tunnel = getattr(client, "tunnel", None)
            try:
                if tunnel is not None:
                    # aclose 幂等，且会把 RSD 连接、隧道、remoted 配对断言一并释放
                    await tunnel.aclose()
                elif getattr(client, "rsd", None) is not None:
                    await client.rsd.close()
            except Exception as e:
                logger.debug(f"Tunnel teardown notice for {key}: {e}")
            finally:
                if self._userspace_slot == key:
                    self._userspace_slot = None

    async def shutdown(self):
        """清理全部资源：先置 closed 拒绝新请求，再逐设备（与其在飞操作串行）
        释放会话——关停不会与在飞写入竞争，关停后也不会再悄悄建新会话。"""
        self._closed = True
        keys_to_clean = set(self.active_clients.keys()) | set(self._locks.all_keys())
        for key in keys_to_clean:
            try:
                async with self._locks.acquire(key):
                    await self._disconnect_device_unlocked(key)
            except Exception as e:
                logger.debug(f"shutdown teardown notice for {key}: {e}")
        self._locks.prune_idle()


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
