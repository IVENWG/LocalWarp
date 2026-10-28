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
from typing import Any, Callable, Dict, List, Optional, Tuple

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

IDENTITY_STATE_READY = "ready"
IDENTITY_STATE_MISSING = "missing"
IDENTITY_STATE_INVALID = "invalid"

# 会话以固定时长分片循环：分片结束自动重建链路（顺带获得断线重连能力）
SESSION_CHUNK_SECONDS = 300.0
MAX_BACKOFF_SECONDS = 30.0
RECENT_EVENT_LIMIT = 30


class AccessoryLocationError(RuntimeError):
    """会话管理错误（重复启动、未运行等确定性失败）。"""


def identity_paths(env: Optional[Dict[str, str]] = None,
                   base: Optional[Path] = None) -> Tuple[Path, Path]:
    """身份文件位置：环境变量优先，其次默认目录。"""
    environment = os.environ if env is None else env
    directory = DEFAULT_IDENTITY_DIR if base is None else Path(base)
    cert = environment.get(IDENTITY_ENV_CERT) or str(directory / "certificate.p7b")
    key = environment.get(IDENTITY_ENV_KEY) or str(directory / "identity.pk8")
    return Path(cert), Path(key)


def resolve_identity(env: Optional[Dict[str, str]] = None,
                     base: Optional[Path] = None) -> Optional[LocalMfiIdentity]:
    """按 环境变量 → 默认目录 顺序解析用户自备身份；缺失或无效返回 None。"""
    cert, key = identity_paths(env, base)
    if not (cert.is_file() and key.is_file()):
        return None
    try:
        return LocalMfiIdentity.from_files(cert, key)
    except IdentityError:
        return None


# 状态轮询每 2 秒一次，重复解析 PKCS#7 没有意义；键含 mtime/大小，替换文件后自动失效。
_IDENTITY_STATE_CACHE: Dict[tuple, str] = {}


def resolve_identity_state(env: Optional[Dict[str, str]] = None,
                           base: Optional[Path] = None) -> str:
    """区分「文件不在」与「文件在但无法解析」，供界面给出可操作提示。"""
    cert, key = identity_paths(env, base)
    try:
        cert_stat = cert.stat()
        key_stat = key.stat()
    except OSError:
        return IDENTITY_STATE_MISSING
    cache_key = (
        str(cert), str(key),
        cert_stat.st_mtime_ns, cert_stat.st_size,
        key_stat.st_mtime_ns, key_stat.st_size,
    )
    cached = _IDENTITY_STATE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        LocalMfiIdentity.from_files(cert, key)
        state = IDENTITY_STATE_READY
    except IdentityError:
        state = IDENTITY_STATE_INVALID
    _IDENTITY_STATE_CACHE.clear()
    _IDENTITY_STATE_CACHE[cache_key] = state
    return state


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
                 identity_resolver: Callable[[], Optional[LocalMfiIdentity]] = resolve_identity,
                 identity_state: Optional[Callable[[], str]] = None):
        # runner 注入点：测试用假实现替换真实 USB/链路栈
        self._runner = runner or self._default_runner
        self._identity_resolver = identity_resolver
        # 只有默认解析器才配缓存状态探测；测试注入的解析器保持完全隔离
        self._identity_state = identity_state or (
            resolve_identity_state
            if identity_resolver is resolve_identity else None)
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

    def _current_identity_state(self) -> str:
        if self._identity_state is not None:
            return self._identity_state()
        return (IDENTITY_STATE_READY
                if self._identity_resolver() else IDENTITY_STATE_MISSING)

    def install_identity(self, certificate: bytes,
                         private_key: bytes) -> Dict[str, Any]:
        """校验后写入本地身份文件（0600，原子替换）；不校验 Apple 信任链。"""
        LocalMfiIdentity(certificate, private_key)
        cert_path, key_path = identity_paths()
        for path, data in ((cert_path, certificate), (key_path, private_key)):
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            tmp = path.with_name(path.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        _IDENTITY_STATE_CACHE.clear()
        return self.status()

    def status(self) -> Dict[str, Any]:
        state = self._state
        running = self._task is not None and not self._task.done()
        identity_state = self._current_identity_state()
        cert_path, _ = identity_paths()
        base: Dict[str, Any] = {
            "running": running,
            "identity_configured": identity_state == IDENTITY_STATE_READY,
            # missing = 文件不在；invalid = 文件在但解析失败（界面需分别提示）
            "identity_state": identity_state,
            "identity_directory": str(cert_path.parent),
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
