"""
LocalWarp Connector — Multi-Device Location Routing and Worker Management
--------------------------------------------------------------------------
支持多台 iPhone 独立并行定位操作的核心路由层（v1.5+）。

架构与平台差异：
- macOS：NativeRemotedTunnel 天然支持不同 UDID 独立并行隧道与会话；
  每台设备拥有独立的 per-UDID 锁，在进程内即可真正并行（native-parallel 模式）。
- Windows / Linux：基于 userspace 单例 TCP 栈（com.apple.coredevice.remoted
  限制同进程仅能激活单实例），采用「首台主进程 + 其余每设备独立 worker 子进程」
  的进程级隔离架构（worker-routed 模式）。

关键设计原则（全部落实监工审计项）：
1. 原子预留 inproc 槽位（审计项 7）：
   在 userspace 模式下，首台设备在 _ensure_route 时即原子预留 inproc 槽位
   （self._inproc_slot_udid），并发请求瞬间判定后续设备走 worker，
   不依赖建链完成后的状态，杜绝两台 Windows 设备并发均分到 inproc 的驱逐与冲突。
2. 解耦短时锁与 worker I/O（审计项 8）：
   全局锁 _state_lock 仅维护微秒级元数据，绝不持锁 await worker.start() 或网络 I/O。
   引入 self._starting_workers 字典：启动中的 worker 计入资源配额，同设备并发
   请求去重等待同一 Task；某设备启动被阻塞时，其它已有设备会话不受任何阻碍。
3. 可靠跨平台 IPC 与 Windows --noconsole 兼容（审计项 5 & 6）：
   提供 run_worker 统一入口。父子进程通信优先采用 Localhost TCP Socket 帧协议，
   由父进程绑定 127.0.0.1:0 动态端口并生成强随机 auth token。
   子进程完全不依赖 stdin/stdout，在 Windows GUI --noconsole 打包产物下稳健工作。
4. 安全防绕过（审计项 5）：
   IPC 监听器仅绑定 127.0.0.1，仅接受单个连接并在握手成功后立即销毁监听器；
   首帧必须携带随机 auth token 与对应 UDID；浏览器发来的 HTTP 请求因帧长与
   格式校验失败会立即断开并拒绝。worker 自身从不暴露任何端口，所有定位写入
   必须由主连接器先行完成云端凭据鉴权（ensure_authorized）。
5. 资源生命周期保护（审计项 4）：
   per-device 的 worker_op_locks、routes、workers 在 disconnect 与 shutdown 时
   均有清理边界，字典有界防泄漏；设置工程级 MAX_WORKERS 上限（非商业限制）。
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
import math
import os
import secrets
import socket
import struct
import sys
import threading
import time
from typing import Any, Dict, Optional, Tuple

try:
    from coredevice_location_poc import PerDeviceLocks
except ImportError:
    here = os.path.dirname(os.path.abspath(__file__))
    poc_dir = os.path.abspath(os.path.join(here, "..", "poc"))
    if poc_dir not in sys.path:
        sys.path.insert(0, poc_dir)
    from coredevice_location_poc import PerDeviceLocks

logger = logging.getLogger("LocalWarp.MultiDevice")

# ---------------------------------------------------------------------------
# IPC 协议常量（有界、强类型、白名单）
# ---------------------------------------------------------------------------
MAX_FRAME_BYTES = 1 * 1024 * 1024  # 1 MiB

OP_AUTH = "auth"
OP_PING = "ping"
OP_SET = "set"
OP_CLEAR = "clear"
OP_DROP = "drop"
OP_SHUTDOWN = "shutdown"

_ALLOWED_OPS = frozenset({OP_AUTH, OP_PING, OP_SET, OP_CLEAR, OP_DROP, OP_SHUTDOWN})

# 每操作超时预算（秒）
OP_TIMEOUT_S: Dict[str, float] = {
    OP_AUTH: 10.0,
    OP_PING: 25.0,
    OP_SET: 330.0,
    OP_CLEAR: 330.0,
    OP_DROP: 40.0,
    OP_SHUTDOWN: 10.0,
}

# 并发 worker 数量上限（工程资源护栏，非商业限制）
WORKER_MAX = 16
# worker 空闲自灭（秒）
WORKER_IDLE_TIMEOUT_S = 1800.0

# 环境变量契约（父→子）
ENV_WORKER_UDID = "LOCALWARP_DEVICE_WORKER_UDID"
ENV_WORKER_FAKE = "LOCALWARP_DEVICE_WORKER_FAKE"
ENV_WORKER_IPC_PORT = "LOCALWARP_WORKER_IPC_PORT"
ENV_WORKER_IPC_AUTH = "LOCALWARP_WORKER_IPC_AUTH"

# 测试钩子（仅 --fake worker 读取）
ENV_TEST_OP_DELAY_S = "LOCALWARP_TEST_OP_DELAY_S"
ENV_TEST_FAIL_OPS = "LOCALWARP_TEST_FAIL_OPS"
ENV_TEST_WORKER_IDLE_S = "LOCALWARP_TEST_WORKER_IDLE_S"


class WorkerProtocolError(RuntimeError):
    """帧格式/白名单/认证违规。"""


class WorkerDeadError(RuntimeError):
    """worker 进程已退出，请求无法送达。"""


class WorkerTimeoutError(RuntimeError):
    """worker 操作超出预算——父进程将回收该 worker。"""


# ---------------------------------------------------------------------------
# 帧编解码（4 字节大端长度 + UTF-8 JSON）
# ---------------------------------------------------------------------------
def encode_frame(obj: Dict[str, Any]) -> bytes:
    payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise WorkerProtocolError(f"frame exceeds size budget ({len(payload)} > {MAX_FRAME_BYTES})")
    return struct.pack(">I", len(payload)) + payload


def decode_frame(data: bytes) -> Dict[str, Any]:
    if len(data) > MAX_FRAME_BYTES:
        raise WorkerProtocolError(f"frame exceeds size budget ({len(data)} > {MAX_FRAME_BYTES})")
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception as e:
        raise WorkerProtocolError(f"frame is not valid JSON: {e}")
    if not isinstance(obj, dict):
        raise WorkerProtocolError("frame is not a JSON object")
    return obj


def _read_exact(stream, n: int) -> Optional[bytes]:
    """阻塞读取恰好 n 字节；EOF 返回 None。"""
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_frame(stream) -> Optional[Dict[str, Any]]:
    hdr = _read_exact(stream, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise WorkerProtocolError(f"invalid frame length {length}")
    payload = _read_exact(stream, length)
    if payload is None:
        return None
    return decode_frame(payload)


def _recv_exact_socket(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.error, OSError):
            return None
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def read_frame_socket(sock: socket.socket) -> Optional[Dict[str, Any]]:
    hdr = _recv_exact_socket(sock, 4)
    if hdr is None:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length == 0 or length > MAX_FRAME_BYTES:
        raise WorkerProtocolError(f"invalid frame length {length}")
    payload = _recv_exact_socket(sock, length)
    if payload is None:
        return None
    return decode_frame(payload)


read_frame_from_socket = read_frame_socket


# ---------------------------------------------------------------------------
# worker 侧：测试替身 manager（--fake；绝不触碰真实设备/隧道）
# ---------------------------------------------------------------------------
class FakeWorkerManager:
    """记录操作并可注入延迟/失败的假 manager，供子进程隔离/超时测试使用。"""

    def __init__(self) -> None:
        self.calls: list = []
        try:
            self._delay = float(os.environ.get(ENV_TEST_OP_DELAY_S, "0") or 0)
        except ValueError:
            self._delay = 0.0
        self._fail = set(
            f.strip() for f in os.environ.get(ENV_TEST_FAIL_OPS, "").split(",") if f.strip()
        )

    async def set_location(self, device_id, latitude, longitude):
        self.calls.append(("set", device_id, latitude, longitude))
        if self._delay:
            await asyncio.sleep(self._delay)
        if "set" in self._fail:
            raise RuntimeError("injected set failure (fake)")
        return {"status": "ok", "service": "fake"}

    async def clear_location(self, device_id=None, udid=None):
        target = udid or device_id
        self.calls.append(("clear", target))
        if self._delay:
            await asyncio.sleep(self._delay)
        if "clear" in self._fail:
            raise RuntimeError("injected clear failure (fake)")
        return {"status": "ok", "service": "fake"}

    async def disconnect_device(self, device_id):
        self.calls.append(("drop", device_id))
        return None

    async def shutdown(self):
        self.calls.append(("shutdown",))
        return None


def _build_worker_manager(udid: str, fake: bool):
    if fake:
        return FakeWorkerManager()
    here = os.path.dirname(os.path.abspath(__file__))
    poc_dir = os.path.abspath(os.path.join(here, "..", "poc"))
    if poc_dir not in sys.path:
        sys.path.insert(0, poc_dir)
    from coredevice_location_poc import CoreDeviceLocationManager

    return CoreDeviceLocationManager(use_userspace=True)


# ---------------------------------------------------------------------------
# worker 侧主循环（统一业务逻辑分发）
# ---------------------------------------------------------------------------
def _worker_validate_set(msg: Dict[str, Any]) -> Optional[str]:
    lat, lon = msg.get("lat"), msg.get("lon")
    if not isinstance(lat, (int, float)) or isinstance(lat, bool):
        return "invalid latitude"
    if not isinstance(lon, (int, float)) or isinstance(lon, bool):
        return "invalid longitude"
    try:
        lat_value = float(lat)
        lon_value = float(lon)
    except (ValueError, OverflowError):
        return "coordinates must be finite numbers"
    if not math.isfinite(lat_value) or not math.isfinite(lon_value):
        return "coordinates must be finite numbers"
    if not (-90.0 <= lat_value <= 90.0):
        return "latitude out of range"
    if not (-180.0 <= lon_value <= 180.0):
        return "longitude out of range"
    return None


def _dispatch_worker_msg(
    msg: Dict[str, Any],
    udid: str,
    manager: Any,
    run_coro: Any,
    fake: bool,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    """处理一帧 worker 消息。返回 (reply_dict, should_exit)。"""
    mid = msg.get("id")
    op = msg.get("op")

    if op not in _ALLOWED_OPS:
        return {"id": mid, "ok": False, "error": f"unknown op: {op!r}"}, False

    if op == OP_PING:
        return {
            "id": mid,
            "ok": True,
            "data": {"udid": udid, "pid": os.getpid(), "fake": bool(fake)},
        }, False

    if op == OP_SHUTDOWN:
        return {"id": mid, "ok": True, "data": None}, True

    target = msg.get("udid")
    if target != udid:
        return {
            "id": mid,
            "ok": False,
            "error": "udid mismatch: worker is bound to another device",
        }, False

    if op == OP_SET:
        invalid = _worker_validate_set(msg)
        if invalid:
            return {"id": mid, "ok": False, "error": invalid}, False
        try:
            data = run_coro(
                manager.set_location(udid, float(msg["lat"]), float(msg["lon"])),
                OP_TIMEOUT_S[OP_SET],
            )
            return {"id": mid, "ok": True, "data": data}, False
        except Exception as e:
            return {"id": mid, "ok": False, "error": str(e)}, False

    if op == OP_CLEAR:
        try:
            data = run_coro(manager.clear_location(device_id=udid), OP_TIMEOUT_S[OP_CLEAR])
            return {"id": mid, "ok": True, "data": data}, False
        except Exception as e:
            return {"id": mid, "ok": False, "error": str(e)}, False

    if op == OP_DROP:
        try:
            run_coro(manager.disconnect_device(udid), OP_TIMEOUT_S[OP_DROP])
            return {"id": mid, "ok": True, "data": None}, False
        except Exception as e:
            return {"id": mid, "ok": False, "error": str(e)}, False

    return {"id": mid, "ok": False, "error": "unreachable"}, False


def run_worker_socket(udid: str, port: int, auth: str, fake: bool = False) -> int:
    """Socket IPC 模式（推荐，支持 Windows --noconsole GUI 打包产物）：
    连接父进程的 127.0.0.1:<port>，发送带 secret 的 OP_AUTH 帧，通过后进入主循环。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15.0)
    try:
        sock.connect(("127.0.0.1", port))
        # 1. 握手帧发送
        auth_frame = encode_frame({"id": 0, "op": OP_AUTH, "token": auth, "udid": udid})
        sock.sendall(auth_frame)
        # 2. 接收握手回复
        resp = read_frame_socket(sock)
        if not resp or resp.get("ok") is not True:
            logger.error(f"Worker {udid} failed auth handshake with connector: {resp}")
            sock.close()
            return 1
    except Exception as e:
        logger.error(f"Worker {udid} failed to connect to IPC port {port}: {e}")
        try:
            sock.close()
        except Exception:
            pass
        return 1

    sock.settimeout(None)  # 主循环阻塞读取

    manager = _build_worker_manager(udid, fake)
    loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(
        target=loop.run_forever, daemon=True, name=f"localwarp-worker-loop-{udid}"
    )
    loop_thread.start()

    last_op = time.monotonic()

    def run_coro(coro, timeout: float):
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return fut.result(timeout)
        except Exception:
            fut.cancel()
            raise

    try:
        try:
            idle_s = float(os.environ.get(ENV_TEST_WORKER_IDLE_S, "") or WORKER_IDLE_TIMEOUT_S)
        except ValueError:
            idle_s = WORKER_IDLE_TIMEOUT_S

        def _idle_watchdog():
            while True:
                time.sleep(min(max(idle_s / 4, 1.0), 30.0))
                if time.monotonic() - last_op >= idle_s:
                    logger.info(f"Worker {udid} idle timeout reached ({idle_s}s); exiting.")
                    os._exit(0)

        threading.Thread(
            target=_idle_watchdog, daemon=True, name=f"localwarp-worker-idle-{udid}"
        ).start()

        while True:
            try:
                msg = read_frame_socket(sock)
            except WorkerProtocolError as e:
                logger.error(f"Worker {udid} protocol error: {e}")
                return 1
            if msg is None:
                # 父进程关闭连接（或崩溃退出）
                logger.info(f"Worker {udid} IPC socket closed by parent; exiting.")
                return 0

            last_op = time.monotonic()
            reply, should_exit = _dispatch_worker_msg(msg, udid, manager, run_coro, fake)
            if reply is not None:
                sock.sendall(encode_frame(reply))
            if should_exit:
                return 0

    finally:
        try:
            run_coro(manager.shutdown(), 15.0)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        loop_thread.join(timeout=2.0)
        try:
            loop.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
    return 0


def run_worker_stdio(udid: str, fake: bool = False) -> int:
    """标准 IO IPC 模式（stdin/stdout 帧协议，备用与命令行测试）：
    只处理白名单操作；任何 udid != 绑定值 的写请求一律拒绝。
    """
    if sys.stdin is None or sys.stdout is None:
        logger.error(f"run_worker_stdio failed: stdin or stdout is None")
        return 1

    manager = _build_worker_manager(udid, fake)
    loop = asyncio.new_event_loop()
    loop_thread = threading.Thread(
        target=loop.run_forever, daemon=True, name=f"localwarp-worker-stdio-loop-{udid}"
    )
    loop_thread.start()

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    last_op = time.monotonic()

    def run_coro(coro, timeout: float):
        fut = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            return fut.result(timeout)
        except Exception:
            fut.cancel()
            raise

    try:
        try:
            idle_s = float(os.environ.get(ENV_TEST_WORKER_IDLE_S, "") or WORKER_IDLE_TIMEOUT_S)
        except ValueError:
            idle_s = WORKER_IDLE_TIMEOUT_S

        def _idle_watchdog():
            while True:
                time.sleep(min(max(idle_s / 4, 1.0), 30.0))
                if time.monotonic() - last_op >= idle_s:
                    os._exit(0)

        threading.Thread(
            target=_idle_watchdog, daemon=True, name=f"localwarp-worker-idle-{udid}"
        ).start()

        while True:
            try:
                msg = read_frame(stdin)
            except WorkerProtocolError as e:
                print(json.dumps({"ok": False, "error": f"protocol error: {e}"}), file=sys.stderr)
                return 1
            if msg is None:
                return 0
            last_op = time.monotonic()
            reply, should_exit = _dispatch_worker_msg(msg, udid, manager, run_coro, fake)
            if reply is not None:
                stdout.write(encode_frame(reply))
                stdout.flush()
            if should_exit:
                return 0
    finally:
        try:
            run_coro(manager.shutdown(), 15.0)
        except Exception:
            pass
        loop.call_soon_threadsafe(loop.stop)
        loop_thread.join(timeout=2.0)
        try:
            loop.close()
        except Exception:
            pass
    return 0


def run_worker(
    udid: str,
    fake: bool = False,
    ipc_port: Optional[int] = None,
    ipc_auth: Optional[str] = None,
) -> int:
    """设备 worker 进程统一公共入口：
    由 scripts/pyinstaller_worker_hook.py、server_gui.py、或命令行调用。
    若提供了 ipc_port 则采用可靠 Socket IPC；未提供则降级采用 Stdio 模式。
    """
    if ipc_port:
        auth = ipc_auth or os.environ.get(ENV_WORKER_IPC_AUTH)
        if auth:
            return run_worker_socket(udid, int(ipc_port), auth, fake=fake)
    return run_worker_stdio(udid, fake=fake)


# ---------------------------------------------------------------------------
# 父进程侧：单个 worker 子进程句柄
# ---------------------------------------------------------------------------
def worker_argv() -> list:
    """worker 子进程命令行：源码模式直接跑本模块；打包模式重定向自身可执行文件。"""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__), "--worker"]


class DeviceWorkerProcess:
    """一台设备一个 worker 子进程：
    默认采用 Localhost TCP Socket + 强随机密钥握手；
    无暴露端口给外部或浏览器（握手后立即销毁监听器，且子进程仅为客户端）；
    逐请求超时与失败回收。
    """

    def __init__(
        self,
        udid: str,
        fake: bool = False,
        spawn_timeout: Optional[float] = None,
        use_stdio: bool = False,
    ):
        self.udid = udid
        self.fake = fake
        self.use_stdio = use_stdio
        self.proc: Optional[asyncio.subprocess.Process] = None
        self._pending: Dict[int, "asyncio.Future[Dict[str, Any]]"] = {}
        self._ids = itertools.count(1)
        self._reader_task: Optional[asyncio.Task] = None
        self._stderr_task: Optional[asyncio.Task] = None
        self._write_lock = asyncio.Lock()
        self._spawn_timeout = spawn_timeout or OP_TIMEOUT_S[OP_PING]
        self._closed = False
        self._sock_reader: Optional[asyncio.StreamReader] = None
        self._sock_writer: Optional[asyncio.StreamWriter] = None
        self._server: Optional[asyncio.Server] = None

    @property
    def alive(self) -> bool:
        return (
            not self._closed
            and self.proc is not None
            and self.proc.returncode is None
            and self._reader_task is not None
            and not self._reader_task.done()
        )

    async def start(self) -> Dict[str, Any]:
        """拉起子进程并完成握手；失败即清理并抛错。"""
        if self.use_stdio:
            return await self._start_stdio()
        return await self._start_socket()

    async def _start_socket(self) -> Dict[str, Any]:
        auth_token = secrets.token_hex(16)
        handshake_fut: "asyncio.Future[Tuple[asyncio.StreamReader, asyncio.StreamWriter]]" = (
            asyncio.get_running_loop().create_future()
        )
        server: Optional[asyncio.Server] = None

        async def _on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            # 重复连接或已握手完成：直接关闭自身，不泄漏 socket
            if handshake_fut.done():
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return

            try:
                # 慢连接保护：单帧读取设置 5.0s 严格超时
                hdr = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
                (length,) = struct.unpack(">I", hdr)
                if length == 0 or length > MAX_FRAME_BYTES:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    # 未认证或畸形候选连接只关闭自身，绝对不 set_exception 污染全局 handshake_fut
                    return

                payload = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
                msg = decode_frame(payload)

                # 严格校验：操作类型、随机 token、绑定 UDID
                if (
                    msg.get("op") != OP_AUTH
                    or msg.get("token") != auth_token
                    or msg.get("udid") != self.udid
                ):
                    # 审计项 5 & 6：固定原因日志，禁止输出 token/攻击 payload
                    logger.warning("Worker auth handshake rejected: invalid token or udid mismatch")
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    # 仅关闭自身，不污染 handshake_fut
                    return

                # 校验通过，回复握手成功
                writer.write(encode_frame({"id": msg.get("id", 0), "ok": True, "op": OP_AUTH}))
                await writer.drain()

                if not handshake_fut.done():
                    handshake_fut.set_result((reader, writer))
            except Exception:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                # 异常仅关闭候选连接，不污染全局 future，启动总超时保护外层

        # 绑定 127.0.0.1:0 获取空闲端口
        server = await asyncio.start_server(_on_client, host="127.0.0.1", port=0)
        self._server = server
        port = server.sockets[0].getsockname()[1]

        env = dict(os.environ)
        env[ENV_WORKER_UDID] = self.udid
        env[ENV_WORKER_IPC_PORT] = str(port)
        env[ENV_WORKER_IPC_AUTH] = auth_token
        if self.fake:
            env[ENV_WORKER_FAKE] = "1"

        # 审计项 6：token 不放 CLI argv，通过环境变量安全传递，避免 ps 命令泄露
        cmd = worker_argv() + [
            "--udid",
            self.udid,
            "--ipc-port",
            str(port),
        ]
        if self.fake:
            cmd.append("--fake")

        try:
            self.proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            self._stderr_task = asyncio.create_task(self._drain_stderr())

            # 等待握手完成，超时预算保护
            reader, writer = await asyncio.wait_for(handshake_fut, timeout=self._spawn_timeout)
            self._sock_reader, self._sock_writer = reader, writer
            self._reader_task = asyncio.create_task(self._read_socket_loop())
        except BaseException:
            if server is not None:
                server.close()
            await self.aclose()
            raise
        finally:
            # 审计核心修复：server.close() 立即停止 accept 新连接，绝不在此时 await server.wait_closed()
            # 否则 Python 3.12 会一直等待当前已认证并保持活动的 worker 长连接关闭，导致永久死锁挂死！
            if server is not None:
                server.close()

        try:
            pong = await self.request(OP_PING, {})
        except BaseException:
            await self.aclose()
            raise

        data = pong.get("data") or {}
        if data.get("udid") != self.udid:
            await self.aclose()
            raise WorkerProtocolError(f"worker handshake udid mismatch: {data.get('udid')!r}")

        logger.info(f"Device worker (socket IPC) started for {self.udid} (pid={data.get('pid')})")
        return data

    async def _start_stdio(self) -> Dict[str, Any]:
        env = dict(os.environ)
        env[ENV_WORKER_UDID] = self.udid
        if self.fake:
            env[ENV_WORKER_FAKE] = "1"

        cmd = worker_argv() + ["--udid", self.udid]
        if self.fake:
            cmd.append("--fake")

        self.proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self._reader_task = asyncio.create_task(self._read_stdio_loop())
        self._stderr_task = asyncio.create_task(self._drain_stderr())
        try:
            pong = await self.request(OP_PING, {})
        except BaseException:
            await self.aclose()
            raise
        data = pong.get("data") or {}
        if data.get("udid") != self.udid:
            await self.aclose()
            raise WorkerProtocolError(f"worker handshake udid mismatch: {data.get('udid')!r}")
        logger.info(f"Device worker (stdio) started for {self.udid} (pid={data.get('pid')})")
        return data

    async def request(
        self, op: str, payload: Dict[str, Any], timeout: Optional[float] = None
    ) -> Dict[str, Any]:
        """发送一帧并等待对应 id 的应答；超时抛 WorkerTimeoutError。"""
        if op not in _ALLOWED_OPS:
            raise WorkerProtocolError(f"unknown op: {op!r}")
        if not self.alive:
            raise WorkerDeadError(f"worker for {self.udid} is not running")

        rid = next(self._ids)
        fut: "asyncio.Future[Dict[str, Any]]" = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        frame = encode_frame({"id": rid, "op": op, **payload})

        try:
            async with self._write_lock:
                if self._sock_writer is not None:
                    self._sock_writer.write(frame)
                    await self._sock_writer.drain()
                elif self.proc is not None and self.proc.stdin is not None:
                    self.proc.stdin.write(frame)
                    await self.proc.stdin.drain()
                else:
                    raise WorkerDeadError("no active IPC transport to worker")

            return await asyncio.wait_for(fut, timeout or OP_TIMEOUT_S[op])
        except asyncio.TimeoutError:
            raise WorkerTimeoutError(f"worker op '{op}' for {self.udid} timed out")
        finally:
            self._pending.pop(rid, None)

    async def _read_socket_loop(self) -> None:
        assert self._sock_reader is not None
        try:
            while True:
                hdr = await self._sock_reader.readexactly(4)
                (length,) = struct.unpack(">I", hdr)
                if length == 0 or length > MAX_FRAME_BYTES:
                    raise WorkerProtocolError(f"invalid frame length {length}")
                payload = await self._sock_reader.readexactly(length)
                msg = decode_frame(payload)
                self._dispatch_reply(msg)
        except (asyncio.IncompleteReadError, WorkerProtocolError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self._fail_all_pending()

    async def _read_stdio_loop(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            while True:
                hdr = await self.proc.stdout.readexactly(4)
                (length,) = struct.unpack(">I", hdr)
                if length == 0 or length > MAX_FRAME_BYTES:
                    raise WorkerProtocolError(f"invalid frame length {length}")
                payload = await self.proc.stdout.readexactly(length)
                msg = decode_frame(payload)
                self._dispatch_reply(msg)
        except (asyncio.IncompleteReadError, WorkerProtocolError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self._fail_all_pending()

    def _dispatch_reply(self, msg: Dict[str, Any]) -> None:
        rid = msg.get("id")
        fut = self._pending.get(rid) if isinstance(rid, int) else None
        if fut is not None and not fut.done():
            if msg.get("ok") is True:
                fut.set_result(msg)
            else:
                fut.set_exception(RuntimeError(str(msg.get("error") or "worker op failed")))

    async def _drain_stderr(self) -> None:
        assert self.proc is not None and self.proc.stderr is not None
        try:
            while True:
                line = await self.proc.stderr.readline()
                if not line:
                    break
                text = line.decode("utf-8", "replace").rstrip()
                if text:
                    logger.debug(f"[worker:{self.udid}] {text}")
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

    def _fail_all_pending(self) -> None:
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(WorkerDeadError(f"worker for {self.udid} exited"))
        self._pending.clear()

    async def aclose(self) -> None:
        """优雅关停：shutdown 帧 → 超时 terminate → 兜底 kill。幂等。"""
        if self._closed:
            return
        self._closed = True
        proc, self.proc = self.proc, None
        sock_writer, self._sock_writer = self._sock_writer, None
        self._sock_reader = None

        for task in (self._reader_task, self._stderr_task):
            if task is not None and not task.done():
                task.cancel()

        if self._server is not None:
            try:
                self._server.close()
            except Exception:
                pass
            self._server = None

        try:
            if sock_writer is not None:
                try:
                    frame = encode_frame({"id": next(self._ids), "op": OP_SHUTDOWN})
                    sock_writer.write(frame)
                    await asyncio.wait_for(sock_writer.drain(), 2.0)
                except Exception:
                    pass
                try:
                    sock_writer.close()
                    await sock_writer.wait_closed()
                except Exception:
                    pass

            if proc is not None and proc.returncode is None:
                try:
                    if proc.stdin is not None:
                        try:
                            frame = encode_frame({"id": next(self._ids), "op": OP_SHUTDOWN})
                            proc.stdin.write(frame)
                            await asyncio.wait_for(proc.stdin.drain(), 2.0)
                        except Exception:
                            pass
                    try:
                        await asyncio.wait_for(proc.wait(), 5.0)
                    except asyncio.TimeoutError:
                        proc.terminate()
                        try:
                            await asyncio.wait_for(proc.wait(), 5.0)
                        except asyncio.TimeoutError:
                            proc.kill()
                            await proc.wait()
                except Exception as e:
                    logger.debug(f"worker aclose notice for {self.udid}: {e}")
        finally:
            self._fail_all_pending()


# ---------------------------------------------------------------------------
# 父进程侧：多设备路由门面（server.py 唯一交互对象）
# ---------------------------------------------------------------------------
_SLOT_BUSY_TYPES: Optional[tuple] = None


def _slot_busy_types() -> tuple:
    global _SLOT_BUSY_TYPES
    if _SLOT_BUSY_TYPES is None:
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            poc_dir = os.path.abspath(os.path.join(here, "..", "poc"))
            if poc_dir not in sys.path:
                sys.path.insert(0, poc_dir)
            from coredevice_location_poc import UserspaceSlotBusyError

            _SLOT_BUSY_TYPES = (UserspaceSlotBusyError,)
        except Exception:
            _SLOT_BUSY_TYPES = ()
    return _SLOT_BUSY_TYPES


class MultiDeviceManager:
    """macOS 原生多隧道并行；userspace 平台主进程一个 + 其余每设备一个 worker 进程。

    路由与并发规则（落实审计项 7 & 8）：
    - 槽位原子预留（审计项 7）：
      userspace 平台下首个设备在路由决策时立即原子标记 self._inproc_slot_udid = udid。
      并发第二台设备在元数据锁内即可判定槽位已被占用，立即分配为 worker，
      杜绝两台并发 Windows 设备均误入 inproc。
    - 解耦短时锁与 worker I/O（审计项 8）：
      元数据锁 _state_lock 仅做瞬时字典维护，绝不持锁 await worker.start()。
      使用 self._starting_workers 进行同设备启动去重，启动任务在锁外并发执行；
      某设备启动慢（如 fake Event 阻塞）时，其它已有设备访问路由与执行写入零等待。
    - 资源生命周期边界（审计项 4）：
      per-UDID 锁、路由和 workers 在 disconnect 与 shutdown 时自动回收。
    """

    def __init__(
        self,
        inproc_manager: Any,
        platform: Optional[str] = None,
        max_workers: int = WORKER_MAX,
        allow_workers: bool = True,
        fake_workers: bool = False,
    ):
        self.inproc = inproc_manager
        self._platform = platform or sys.platform
        self._max_workers = max(1, int(max_workers))
        self._allow_workers = allow_workers
        self._fake_workers = fake_workers

        # 短时元数据锁：仅保护内存字典状态，绝不持锁 await I/O
        self._state_lock = asyncio.Lock()
        self._routes: Dict[str, str] = {}  # udid -> "inproc" | "worker"
        self._workers: Dict[str, DeviceWorkerProcess] = {}
        # 正在启动中的 worker 任务：udid -> Task[str]，用于启动去重与配额统计
        self._starting_workers: Dict[str, "asyncio.Task[str]"] = {}
        # userspace 槽位原子预留：首个占用的 UDID
        self._inproc_slot_udid: Optional[str] = None
        # 单设备全生命周期串行锁：覆盖 set / clear / disconnect 全程（审计项 1 & 4）
        self._device_locks = PerDeviceLocks(max_keys=128)
        self._closed = False

    @property
    def _worker_op_locks(self) -> Dict[str, asyncio.Lock]:
        # 兼容旧代码与单测断言
        return self._device_locks._locks

    @property
    def mode(self) -> str:
        darwin_native = self._platform == "darwin" and not getattr(self.inproc, "use_userspace", False)
        return "native-parallel" if darwin_native else "worker-routed"

    def _decide_new_route_locked(self, udid: str) -> str:
        """持锁进行瞬时路由判定（无 I/O）。"""
        darwin_native = self._platform == "darwin" and not getattr(self.inproc, "use_userspace", False)
        if darwin_native:
            # macOS native 隧道天然支持多设备独立会话，默认全部 inproc
            # 仅当 userspace 单例槽位被其它设备占用时分流 worker
            if self._inproc_slot_udid is not None and self._inproc_slot_udid != udid:
                return "worker"
            return "inproc"

        # userspace 平台（Windows / Linux）：
        # 原子槽位预留：首个设备分配 inproc 并立即锁定槽位；其余并发设备必定分流 worker
        if self._inproc_slot_udid is None:
            self._inproc_slot_udid = udid
            return "inproc"
        elif self._inproc_slot_udid == udid:
            return "inproc"
        else:
            return "worker"

    async def _ensure_route(self, udid: str) -> str:
        """确保设备获得路由。锁外执行 worker.start()，互不阻塞（落实审计项 7 & 8）。"""
        worker_task_to_await: Optional["asyncio.Task[str]"] = None

        async with self._state_lock:
            if self._closed:
                raise RuntimeError("manager is closed")

            # 1. 已有路由
            route = self._routes.get(udid)
            if route == "inproc":
                return "inproc"
            elif route == "worker":
                w = self._workers.get(udid)
                if w is not None and w.alive:
                    return "worker"
                # worker 退出，清除后重新启动
                self._routes.pop(udid, None)
                self._workers.pop(udid, None)

            # 2. 该设备是否正在启动中（同设备并发去重）
            if udid in self._starting_workers:
                worker_task_to_await = self._starting_workers[udid]
            else:
                # 3. 决定新路由
                chosen_route = self._decide_new_route_locked(udid)
                if chosen_route == "inproc":
                    self._routes[udid] = "inproc"
                    return "inproc"

                # chosen_route == "worker"
                if not self._allow_workers:
                    raise RuntimeError("multi-device worker routing is disabled on this connector")

                # 资源配额校验：活跃 worker + 启动中 worker
                active_and_starting = len(self._workers) + len(self._starting_workers)
                if active_and_starting >= self._max_workers:
                    raise RuntimeError(
                        f"too many concurrent device workers (resource limit {self._max_workers}); "
                        "disconnect an idle device first"
                    )

                # 创建启动 Task（在短时锁外并发执行 I/O）
                worker_task_to_await = asyncio.create_task(self._start_worker_task(udid))
                self._starting_workers[udid] = worker_task_to_await

        # 锁已释放！其它设备可以自由获取锁进行路由决策，完全不被本设备的 worker.start 阻塞
        assert worker_task_to_await is not None
        return await worker_task_to_await

    async def _start_worker_task(self, udid: str) -> str:
        """worker 子进程拉起任务：锁外执行 spawn/ping，完成或失败后持短时锁更新状态。"""
        worker = DeviceWorkerProcess(udid, fake=self._fake_workers)
        try:
            await worker.start()
        except BaseException as e:
            async with self._state_lock:
                self._starting_workers.pop(udid, None)
                self._routes.pop(udid, None)
            try:
                await worker.aclose()
            except Exception:
                pass
            raise e

        async with self._state_lock:
            self._starting_workers.pop(udid, None)
            # 审计项 2：关停复核，若启动期间已关闭，立即销毁子进程，防 worker 复活与泄漏
            if self._closed:
                try:
                    await worker.aclose()
                except Exception:
                    pass
                raise RuntimeError("manager is closed")
            self._workers[udid] = worker
            self._routes[udid] = "worker"
            return "worker"

    async def _flip_to_worker(self, udid: str) -> None:
        """inproc 发生 userspace 单例冲突（UserspaceSlotBusyError）后翻转到 worker。"""
        worker_task_to_await: Optional["asyncio.Task[str]"] = None

        async with self._state_lock:
            # 释放 inproc 槽位
            if self._inproc_slot_udid == udid:
                self._inproc_slot_udid = None
            self._routes.pop(udid, None)

            if udid in self._starting_workers:
                worker_task_to_await = self._starting_workers[udid]
            else:
                w = self._workers.get(udid)
                if w is not None and w.alive:
                    self._routes[udid] = "worker"
                    worker_task_to_await = None
                else:
                    active_and_starting = len(self._workers) + len(self._starting_workers)
                    if active_and_starting >= self._max_workers:
                        raise RuntimeError(
                            f"too many concurrent device workers (resource limit {self._max_workers})"
                        )
                    worker_task_to_await = asyncio.create_task(self._start_worker_task(udid))
                    self._starting_workers[udid] = worker_task_to_await

        if worker_task_to_await is not None:
            await worker_task_to_await

        try:
            await self.inproc.disconnect_device(udid)
        except Exception:
            pass

    async def _worker_op(self, udid: str, op: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        worker = None
        async with self._state_lock:
            worker = self._workers.get(udid)
        if worker is None or not worker.alive:
            raise WorkerDeadError(f"worker for {udid} is not running")
        try:
            reply = await worker.request(op, payload)
            if isinstance(reply, dict) and "data" in reply and reply["data"] is not None:
                return reply["data"]
            return reply
        except WorkerTimeoutError:
            await self._recycle_worker(udid)
            raise RuntimeError(
                f"device worker timed out for {udid}; it has been restarted. Retry shortly."
            )

    async def _recycle_worker(self, udid: str) -> None:
        async with self._state_lock:
            self._routes.pop(udid, None)
            worker = self._workers.pop(udid, None)
        if worker is not None:
            await worker.aclose()

    # -- 公共 API（与 CoreDeviceLocationManager 表面兼容） -------------------
    async def set_location(
        self, device_id: Optional[str], latitude: float, longitude: float
    ) -> Dict[str, Any]:
        invalid = _worker_validate_set({"lat": latitude, "lon": longitude})
        if invalid:
            raise ValueError(invalid)
        latitude, longitude = float(latitude), float(longitude)
        if self._closed:
            raise RuntimeError("MultiDeviceManager is closed: connector is shutting down")
        udid = device_id or "default"
        # 审计项 1：全程持同设备生命周期锁，保证写写、写断严格串行
        async with self._device_locks.acquire(udid):
            if self._closed:
                raise RuntimeError("MultiDeviceManager is closed: connector is shutting down")
            for attempt in (0, 1):
                route = await self._ensure_route(udid)
                if route == "inproc":
                    try:
                        return await self.inproc.set_location(device_id, latitude, longitude)
                    except _slot_busy_types():
                        if attempt == 0:
                            logger.warning(
                                f"in-process userspace slot busy; flipping device {udid} to worker process"
                            )
                            await self._flip_to_worker(udid)
                            continue
                        raise
                    except Exception as e:
                        # 审计项 9：失败的 inproc 路由无条件清理当前 UDID，防 macOS native 模式下字典无界累积
                        async with self._state_lock:
                            self._routes.pop(udid, None)
                            if self._inproc_slot_udid == udid:
                                self._inproc_slot_udid = None
                        raise
                    except BaseException:
                        # 取消时同样清理路由与槽位
                        async with self._state_lock:
                            self._routes.pop(udid, None)
                            if self._inproc_slot_udid == udid:
                                self._inproc_slot_udid = None
                        raise
                return await self._worker_op(
                    udid, OP_SET, {"udid": udid, "lat": latitude, "lon": longitude}
                )
            raise RuntimeError("unreachable")

    async def simulate_location(
        self, latitude: float, longitude: float, udid: Optional[str] = None
    ) -> Dict[str, Any]:
        return await self.set_location(udid, latitude, longitude)

    async def clear_location(
        self, device_id: Optional[str] = None, udid: Optional[str] = None
    ) -> Dict[str, Any]:
        if self._closed:
            raise RuntimeError("MultiDeviceManager is closed: connector is shutting down")
        target = udid or device_id
        key = target or "default"
        async with self._device_locks.acquire(key):
            if self._closed:
                raise RuntimeError("MultiDeviceManager is closed: connector is shutting down")
            for attempt in (0, 1):
                route = await self._ensure_route(key)
                if route == "inproc":
                    try:
                        return await self.inproc.clear_location(device_id=device_id, udid=udid)
                    except _slot_busy_types():
                        if attempt == 0:
                            logger.warning(
                                f"in-process userspace slot busy; flipping device {key} to worker process"
                            )
                            await self._flip_to_worker(key)
                            continue
                        raise
                    except Exception:
                        # 审计项 9：失败无条件按 key 清理 route
                        async with self._state_lock:
                            self._routes.pop(key, None)
                            if self._inproc_slot_udid == key:
                                self._inproc_slot_udid = None
                        raise
                    except BaseException:
                        async with self._state_lock:
                            self._routes.pop(key, None)
                            if self._inproc_slot_udid == key:
                                self._inproc_slot_udid = None
                        raise
                return await self._worker_op(key, OP_CLEAR, {"udid": key})
            raise RuntimeError("unreachable")

    async def disconnect_device(self, device_id: str):
        """按 UDID 断开：与在飞写入串行（持有生命周期锁），等待在飞操作完成，释放 worker 与 inproc，清理槽位与锁对象。"""
        udid = device_id or "default"

        async with self._device_locks.acquire(udid):
            worker = None
            starting_task = None

            async with self._state_lock:
                self._routes.pop(udid, None)
                worker = self._workers.pop(udid, None)
                starting_task = self._starting_workers.pop(udid, None)

            if starting_task is not None and not starting_task.done():
                starting_task.cancel()
                try:
                    await starting_task
                except (asyncio.CancelledError, Exception):
                    pass

            if worker is not None:
                await worker.aclose()

            try:
                await self.inproc.disconnect_device(udid)
            except Exception:
                pass

            # 审计项 1：必须在 worker 和 inproc 真正关闭后，才释放 userspace 槽位
            async with self._state_lock:
                if self._inproc_slot_udid == udid:
                    self._inproc_slot_udid = None

        # 锁释放后安全回收 idle 锁对象，防字典无界
        self._device_locks.prune_idle(udid)

    async def list_devices(self):
        return await self.inproc.list_devices()

    async def get_developer_mode_status(self, device_id: Optional[str] = None):
        return await self.inproc.get_developer_mode_status(device_id=device_id)

    async def reveal_developer_mode(self, device_id: Optional[str] = None):
        return await self.inproc.reveal_developer_mode(device_id=device_id)

    async def enable_developer_mode(self, device_id: Optional[str] = None):
        return await self.inproc.enable_developer_mode(device_id=device_id)

    async def shutdown(self):
        """清理全部资源：关停所有 worker 子进程 + 回收启动中任务 + 释放 inproc 全部会话。"""
        workers: list = []
        starting: list = []

        async with self._state_lock:
            self._closed = True
            workers = list(self._workers.items())
            self._workers.clear()
            starting = list(self._starting_workers.values())
            self._starting_workers.clear()
            self._routes.clear()
            self._inproc_slot_udid = None

        for t in starting:
            if not t.done():
                t.cancel()
        if starting:
            await asyncio.gather(*starting, return_exceptions=True)

        if workers:
            async def _close_one(udid: str, worker: DeviceWorkerProcess) -> None:
                try:
                    await worker.aclose()
                except Exception as e:
                    logger.debug(f"worker shutdown notice for {udid}: {e}")

            await asyncio.gather(*(_close_one(u, w) for u, w in workers), return_exceptions=True)

        try:
            await self.inproc.shutdown()
        except Exception as e:
            logger.debug(f"inproc shutdown notice: {e}")

        self._device_locks.prune_idle()

    def multi_device_status(self) -> Dict[str, Any]:
        """供 /health 展示：模式、路由与 worker 概况。"""
        return {
            "mode": self.mode,
            "max_workers": self._max_workers,
            "routes": dict(self._routes),
            "workers": sorted(u for u, w in self._workers.items() if w.alive),
            "starting_workers": sorted(self._starting_workers.keys()),
        }


# ---------------------------------------------------------------------------
# 源码模式 CLI 入口：python multi_device.py --worker --udid <UDID> [--fake]
# ---------------------------------------------------------------------------
def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="LocalWarp device worker (spawned by connector)")
    parser.add_argument("--worker", action="store_true", help="Run as device worker (required)")
    parser.add_argument("--udid", required=True, help="UDID this worker is bound to")
    parser.add_argument("--fake", action="store_true", help="Test fake manager (no real device IO)")
    parser.add_argument("--ipc-port", type=int, default=None, help="Localhost TCP IPC port")
    parser.add_argument("--ipc-auth", type=str, default=None, help="Shared secret auth token for IPC")
    args = parser.parse_args()
    if not args.worker:
        parser.error("--worker is required")
    return run_worker(args.udid, fake=args.fake, ipc_port=args.ipc_port, ipc_auth=args.ipc_auth)


if __name__ == "__main__":
    sys.exit(_main())
