"""
LocalWarp Connector — Windows Tray GUI Entry
--------------------------------------------
Double-click behavior:
- No console window (built with PyInstaller --noconsole).
- Server runs in a background thread; a tray icon shows status.
- Double-click the tray icon to open the web workbench.
- Running a second instance just opens the workbench and exits.

Other platforms / headless testing: `python server_gui.py --no-tray`
runs the server without any GUI (useful on macOS/Linux CI).
"""

import argparse
import logging
import logging.handlers
import os
import sys
import threading
import time
import webbrowser

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 28888
WORKBENCH_URL = "https://localwarp.com/app"
# 深链：工作台直接打开增强定位面板，主面板会显示配件身份文件导入入口
ENHANCED_WORKBENCH_URL = f"{WORKBENCH_URL}?mode=enhanced"


def check_and_run_worker() -> None:
    """Windows GUI 入口（PyInstaller --noconsole）：
    在单实例检测与托盘启动之前，必须优先拦截并执行 worker 模式。
    --noconsole 下无控制台，避免触发 GUI 或单实例探测退出。"""
    udid = os.environ.get("LOCALWARP_DEVICE_WORKER_UDID")
    fake = os.environ.get("LOCALWARP_DEVICE_WORKER_FAKE") == "1"
    ipc_port = os.environ.get("LOCALWARP_WORKER_IPC_PORT")
    ipc_auth = os.environ.get("LOCALWARP_WORKER_IPC_AUTH")
    if not udid:
        for i, a in enumerate(sys.argv):
            if a in ("--worker", "--device-worker"):
                for j, b in enumerate(sys.argv):
                    if b in ("--udid", "--worker-udid") and j + 1 < len(sys.argv):
                        udid = sys.argv[j + 1]
                    if b in ("--fake", "--worker-fake"):
                        fake = True
                    if b == "--ipc-port" and j + 1 < len(sys.argv):
                        ipc_port = sys.argv[j + 1]
                    if b == "--ipc-auth" and j + 1 < len(sys.argv):
                        ipc_auth = sys.argv[j + 1]
                break
    if udid:
        from multi_device import run_worker
        port_num = int(ipc_port) if ipc_port else None
        rc = run_worker(udid, fake=fake, ipc_port=port_num, ipc_auth=ipc_auth)
        sys.exit(rc if isinstance(rc, int) else 0)


def get_log_path() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
        d = os.path.join(base, "LocalWarp")
    else:
        d = "/tmp"
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "connector.log")


def setup_file_logging() -> str:
    log_path = get_log_path()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.handlers.RotatingFileHandler(
                log_path, maxBytes=2_000_000, backupCount=2, encoding="utf-8"
            )
        ],
        force=True,
    )
    return log_path


def is_already_running(port: int) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/health")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return b"healthy" in resp.read()
    except Exception:
        return False


def start_server(host: str, port: int):
    """Run uvicorn in a background thread; returns (Server, thread) for shutdown."""
    import uvicorn
    from server import app, VERSION as CONNECTOR_VERSION  # same directory as this entry script

    config = uvicorn.Config(app, host=host, port=port, log_config=None, access_log=False)
    server = uvicorn.Server(config)
    logging.getLogger("localwarp.gui").info(
        f"Server starting on {host}:{port} (v{CONNECTOR_VERSION})"
    )
    t = threading.Thread(target=server.run, daemon=True, name="localwarp-server")
    t.start()
    return server, t


def wait_for_startup(server, thread, timeout: float = 20.0) -> bool:
    """True only if *our* uvicorn finished startup — a port held by another
    process makes the server thread die silently, which must not look healthy."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if server.started:
            return True
        if not thread.is_alive():
            return False
        time.sleep(0.1)
    return server.started


def make_tray_image():
    """Brand mark: bundled PNG when packaged, drawn fallback otherwise."""
    from PIL import Image, ImageDraw

    base = getattr(sys, "_MEIPASS", None)
    if base:
        bundled = os.path.join(base, "localwarp.png")
        if os.path.exists(bundled):
            return Image.open(bundled).convert("RGBA").resize((64, 64), Image.LANCZOS)

    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    c = size / 2
    r = size * 0.46
    d.ellipse([c - r, c - r, c + r, c + r], fill=(46, 110, 142, 255),
              outline=(35, 84, 108, 255), width=2)
    d.line([c - r * 0.72, c, c + r * 0.72, c], fill=(251, 248, 240, 255), width=3)
    d.line([c, c - r * 0.72, c, c + r * 0.72], fill=(251, 248, 240, 255), width=3)
    dr = 5
    d.ellipse([c - dr, c - dr, c + dr, c + dr], fill=(251, 248, 240, 255))
    d.polygon([(c, c - r * 1.02), (c - 4, c - r * 0.62), (c + 4, c - r * 0.62)],
              fill=(192, 68, 44, 255))
    return img


def run_tray(server, server_thread, started: bool, port: int, log_path: str):
    from pystray import Icon, Menu, MenuItem

    log = logging.getLogger("localwarp.gui")

    def open_workbench(icon=None, item=None):
        webbrowser.open(WORKBENCH_URL)

    def open_identity_import(icon=None, item=None):
        log.info("Opening enhanced workbench for accessory identity import")
        webbrowser.open(ENHANCED_WORKBENCH_URL)

    def quit_app(icon=None, item=None):
        log.info("Quit requested from tray")
        server.should_exit = True
        # 给进行中的请求/隧道操作与 worker 子进程留出充裕收尾时间（对齐 worker aclose 2s+5s+5s + inproc 清理），
        # 正常退出优先通过 icon.stop() 让主线程自然返回，仅当线程超时仍未结束时才兜底强退。
        server_thread.join(timeout=20.0)
        still_alive = server_thread.is_alive()
        if still_alive:
            log.warning("Server thread did not finish within 20s timeout; forcing process exit.")
        if icon:
            icon.stop()
        logging.shutdown()
        if still_alive:
            os._exit(0)

    tooltip = (
        f"LocalWarp 连接器 · 运行中 :{port}"
        if started
        else f"LocalWarp 连接器 · 启动失败（端口被占用？），见日志 {log_path}"
    )
    # Windows 无驱动 (AMDS) 时设备列表会一直为空：CLI 入口有控制台引导，
    # GUI 入口没有控制台，把检测结果扛到托盘 tooltip 上
    if sys.platform == "win32":
        try:
            from server import check_windows_amds
            if not check_windows_amds():
                tooltip += " · 未检测到 Apple 驱动 (AMDS)，设备将无法识别"
                log.warning("AMDS (Apple Mobile Device Service) not detected — install iTunes/Apple Devices app to connect iPhones")
        except Exception:
            pass
        try:
            from server import IDENTITY_STATE_READY, resolve_identity_state
            if resolve_identity_state() != IDENTITY_STATE_READY:
                tooltip += " · 待导入配件身份文件"
                log.warning("Accessory identity files missing; point users to tray menu「导入配件身份文件…」")
        except Exception:
            pass

    menu = Menu(
        MenuItem("导入配件身份文件…", open_identity_import, enabled=started),
        MenuItem("打开工作台", open_workbench, default=True, enabled=started),
        Menu.SEPARATOR,
        MenuItem("退出", quit_app),
    )
    icon = Icon("LocalWarp", make_tray_image(), tooltip, menu)
    log.info(f"Tray icon active: {tooltip}")
    icon.run()


def _validate_loopback_bind_host(value: str) -> str:
    import ipaddress

    candidate = (value or "").strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    normalized = candidate.rstrip(".").lower()
    if normalized == "localhost":
        return candidate
    try:
        addr = ipaddress.ip_address(normalized)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Connector must bind to a loopback address (e.g. 127.0.0.1, ::1, or localhost); got {value!r}"
        ) from exc
    if not addr.is_loopback:
        raise argparse.ArgumentTypeError(
            f"Connector must bind to a loopback address (e.g. 127.0.0.1, ::1, or localhost); got {value!r}"
        )
    return candidate


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LocalWarp Connector (Tray GUI)")
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        type=_validate_loopback_bind_host,
        help=f"Loopback binding host (default: {DEFAULT_HOST}; non-loopback addresses are rejected)",
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-tray", action="store_true",
                        help="Run headless without tray icon (testing / non-Windows)")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--device-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--udid", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--worker-udid", type=str, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--fake", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--worker-fake", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--ipc-port", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--ipc-auth", type=str, default=None, help=argparse.SUPPRESS)
    return parser


def main():
    check_and_run_worker()
    args = build_argument_parser().parse_args()

    # Double check if worker arguments passed via parsed args
    w_udid = args.udid or args.worker_udid
    if (args.worker or args.device_worker) and w_udid:
        from multi_device import run_worker
        sys.exit(run_worker(w_udid, fake=(args.fake or args.worker_fake), ipc_port=args.ipc_port, ipc_auth=args.ipc_auth))

    log_path = setup_file_logging()
    log = logging.getLogger("localwarp.gui")
    log.info(f"LocalWarp Connector GUI starting (pid={os.getpid()})")

    # Single instance: a healthy connector already listens — just open the workbench.
    if is_already_running(args.port):
        log.info("Another connector instance is already running; opening workbench.")
        webbrowser.open(WORKBENCH_URL)
        time.sleep(1.0)
        os._exit(0)

    try:
        server, server_thread = start_server(args.host, args.port)
    except Exception as e:
        log.exception(f"Server failed to start: {e}")
        raise

    started = wait_for_startup(server, server_thread)
    if not started:
        log.error("Connector failed to start — port occupied by another process?")

    if args.no_tray:
        # Headless mode: keep the main thread alive while the server thread runs.
        if not started:
            os._exit(1)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            server.should_exit = True
            server_thread.join(timeout=20.0)
            logging.shutdown()
    else:
        run_tray(server, server_thread, started, args.port, log_path)


if __name__ == "__main__":
    check_and_run_worker()
    main()
