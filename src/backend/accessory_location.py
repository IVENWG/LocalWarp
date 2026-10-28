#!/usr/bin/env python3
"""iAP2 配件定位会话管理器（实验性增强通道）。

与 CoreDevice/DVT 主线（写入即返回、拔线保持）不同，本通道是会话制：
发送器保持运行期间系统定位被采信，停止即恢复真实定位。因此对外语义是
start/update/stop/status，而不是 simulate/clear。

身份边界：连接器不携带任何 MFi 凭据。身份文件由使用者提供：
- 环境变量 LOCALWARP_IAP2_CERT_FILE / LOCALWARP_IAP2_KEY_FILE，或
- 默认目录 ~/.localwarp/identity/{certificate.p7b, identity.pk8}
授权与合规责任由身份提供者承担（见 docs/research/ 系列报告）。

证据纪律：状态中的 phone_location_verified 恒为 False——链路 ACK 只证明
报文送达，坐标是否被 iOS 采信必须按验收手册在真机上另行证明。
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import sys
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if os.path.join(base_dir, "src/poc") not in sys.path:
    sys.path.insert(0, os.path.join(base_dir, "src/poc"))

from iap2_accessory_location import (  # noqa: E402
    AccessoryLocationSession,
    AuthenticationRequiredError,
    Iap2Link,
    IdentityError,
    LocalMfiIdentity,
    LocationTarget,
    LockdownCarkitStream,
    validate_coordinates,
)

IDENTITY_ENV_CERT = "LOCALWARP_IAP2_CERT_FILE"
IDENTITY_ENV_KEY = "LOCALWARP_IAP2_KEY_FILE"
DEFAULT_IDENTITY_DIR = Path.home() / ".localwarp" / "identity"

# 会话以固定时长分片循环：分片结束自动重建链路（顺带获得断线重连能力）
SESSION_CHUNK_SECONDS = 300.0
MAX_BACKOFF_SECONDS = 30.0
RECENT_EVENT_LIMIT = 30


class AccessoryLocationError(RuntimeError):
    """会话管理错误（重复启动、未运行等确定性失败）。"""


def resolve_identity(env: Optional[Dict[str, str]] = None,
                     base: Optional[Path] = None) -> Optional[LocalMfiIdentity]:
    """按 环境变量 → 默认目录 顺序解析用户自备身份；缺失或无效返回 None。"""
    environment = os.environ if env is None else env
    directory = DEFAULT_IDENTITY_DIR if base is None else Path(base)
    cert = environment.get(IDENTITY_ENV_CERT) or str(directory / "certificate.p7b")
    key = environment.get(IDENTITY_ENV_KEY) or str(directory / "identity.pk8")
    if not (Path(cert).is_file() and Path(key).is_file()):
        return None
    try:
        return LocalMfiIdentity.from_files(cert, key)
    except IdentityError:
        return None


def identity_configured(env: Optional[Dict[str, str]] = None,
                        base: Optional[Path] = None) -> bool:
    return resolve_identity(env, base) is not None


@dataclass
class _SessionState:
    serial: Optional[str]
    target: LocationTarget
    interval: float
    started_at: float
    # 运行进度（由 emit 事件与分片 summary 更新）
    identified: bool = False
    authenticated: bool = False
    packets_acknowledged: int = 0
    last_error: Optional[str] = None
    events: List[str] = field(default_factory=list)
    # USB 上实际设备（default runner 从 lockdown 读取；与请求 serial 无关）
    device: Optional[Dict[str, Any]] = None

    def record(self, **event: Any) -> None:
        name = str(event.get("event", "?"))
        self.events.append(name)
        if len(self.events) > RECENT_EVENT_LIMIT:
            del self.events[:-RECENT_EVENT_LIMIT]
        if name == "identification_accepted":
            self.identified = True
        elif name == "authentication_succeeded":
            self.authenticated = True
        elif name == "location_link_acknowledged":
            self.packets_acknowledged = event.get("count", self.packets_acknowledged)

    def absorb(self, summary: Any) -> None:
        self.identified = self.identified or summary.identified
        self.authenticated = self.authenticated or summary.authenticated
        self.packets_acknowledged = max(self.packets_acknowledged,
                                        summary.location_packets_acknowledged)


class AccessoryLocationManager:
    """单连接器实例维护至多一个配件定位会话（目标设备由 USB 选择决定）。"""

    def __init__(self,
                 runner: Optional[Callable[[_SessionState], Any]] = None,
                 identity_resolver: Callable[[], Optional[LocalMfiIdentity]] = resolve_identity):
        # runner 注入点：测试用假实现替换真实 USB/链路栈
        self._runner = runner or self._default_runner
        self._identity_resolver = identity_resolver
        self._state: Optional[_SessionState] = None
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    # ---- 对外接口 -------------------------------------------------------

    async def start(self, latitude: float, longitude: float, *,
                    serial: Optional[str] = None,
                    interval: float = 1.0) -> Dict[str, Any]:
        async with self._lock:
            if self._task is not None and not self._task.done():
                raise AccessoryLocationError(
                    "accessory location session already running; stop it first")
            validate_coordinates(latitude, longitude)
            if not 1.0 <= float(interval) <= 60.0:
                raise ValueError("interval must be between 1 and 60 seconds")
            state = _SessionState(serial=serial,
                                  target=LocationTarget(float(latitude), float(longitude)),
                                  interval=float(interval),
                                  started_at=time.time())
            self._state = state
            self._task = asyncio.create_task(self._run_loop(state))
            return self.status()

    async def update(self, latitude: float, longitude: float) -> Dict[str, Any]:
        state = self._state
        if state is None or self._task is None or self._task.done():
            raise AccessoryLocationError("no running accessory location session")
        validate_coordinates(latitude, longitude)
        state.target.latitude = float(latitude)
        state.target.longitude = float(longitude)
        return self.status()

    async def stop(self) -> Dict[str, Any]:
        async with self._lock:
            task, self._task = self._task, None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        return self.status()

    def status(self) -> Dict[str, Any]:
        state = self._state
        running = self._task is not None and not self._task.done()
        base: Dict[str, Any] = {
            "running": running,
            "identity_configured": bool(self._identity_resolver()),
            "phone_location_verified": False,
            "constraint": ("iOS only adopts accessory fixes within ~15 km of the "
                           "phone's own position estimate (positionDiffBound). "
                           "Verified far-teleport recipe (iOS 15): keep the "
                           "phone offline (airplane mode), reset Location & "
                           "Privacy once, keep the session running — adopted "
                           "immediately; re-anchors ~1 min after radios return"),
            "note": ("experimental accessory channel: link ACK does not prove "
                     "iOS adopted the coordinates; session-based (stops restore "
                     "real location)"),
        }
        if state is None:
            return base
        base.update({
            "serial": state.serial,
            "device": state.device,
            "target": {"latitude": state.target.latitude,
                       "longitude": state.target.longitude},
            "interval": state.interval,
            "started_at": state.started_at,
            "identified": state.identified,
            "authenticated": state.authenticated,
            "packets_acknowledged": state.packets_acknowledged,
            "last_error": state.last_error,
            "recent_events": list(state.events[-10:]),
        })
        return base

    # ---- 内部 ------------------------------------------------------------

    async def _run_loop(self, state: _SessionState) -> None:
        """分片运行 + 指数退避重连；确定性失败（身份缺失/无效）立即终止。"""
        backoff = 1.0
        try:
            while True:
                try:
                    await self._runner(state)
                    state.record(event="session_chunk_completed")
                    backoff = 1.0
                except asyncio.CancelledError:
                    raise
                except (AuthenticationRequiredError, IdentityError) as error:
                    state.last_error = (
                        f"accessory authentication requires a user-supplied "
                        f"identity: {error}")
                    return
                except Exception as error:  # noqa: BLE001 - 重连循环兜底
                    state.last_error = str(error)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
        except asyncio.CancelledError:
            state.last_error = state.last_error or "session stopped"
            raise

    async def _default_runner(self, state: _SessionState) -> None:
        """真实栈：USB lockdown → iAP2 链路 → 配件会话（一个分片）。"""
        identity = self._identity_resolver()
        # serial 是请求指定的目标设备；缺省让 usbmux 选第一台 USB 设备
        stream = await LockdownCarkitStream.open(udid=state.serial)
        # serial 只是请求回显；机型/UDID 必须来自实际 USB 设备
        state.device = stream.device_info
        link = Iap2Link(stream, state.record)
        try:
            await link.handshake()
            session = AccessoryLocationSession(link, identity, state.record)
            summary = await session.run(
                send=True, duration=SESSION_CHUNK_SECONDS,
                interval=state.interval, target=state.target)
            state.absorb(summary)
        finally:
            await link.close()
