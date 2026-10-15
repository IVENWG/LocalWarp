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

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 28888
WORKBENCH_URL = "https://localwarp.com/app"


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

    def quit_app(icon=None, item=None):
        log.info("Quit requested from tray")
        server.should_exit = True
        # 给进行中的请求/隧道操作留出收尾时间，并确保日志落盘
        server_thread.join(timeout=8)
        logging.shutdown()
        if icon:
            icon.stop()
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

    menu = Menu(
        MenuItem("打开工作台", open_workbench, default=True, enabled=started),
        Menu.SEPARATOR,
        MenuItem("退出", quit_app),
    )
    icon = Icon("LocalWarp", make_tray_image(), tooltip, menu)
    log.info(f"Tray icon active: {tooltip}")
    icon.run()


def main():
    parser = argparse.ArgumentParser(description="LocalWarp Connector (Tray GUI)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--no-tray", action="store_true",
                        help="Run headless without tray icon (testing / non-Windows)")
    args = parser.parse_args()

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
    else:
        run_tray(server, server_thread, started, args.port, log_path)


if __name__ == "__main__":
    main()
