"""PyInstaller 运行时钩子：设备 worker 子进程引导。

打包产物（macOS/Linux CLI 入口 server.py；Windows 托盘入口 server_gui.py）
被主连接器以环境变量 LOCALWARP_DEVICE_WORKER_UDID 重新拉起时，在进入正常
入口（HTTP 服务器 / 托盘 GUI / argparse）之前直接切入 worker 模式。

- 只在环境变量存在时生效；普通启动零行为变化。
- worker 作为客户端主动连接主连接器临时监听的本机 127.0.0.1 端口（或回退 stdio），
  worker 自身不监听任何网络端口；云端权益校验仍在主连接器。
"""

import os
import sys

_udid = os.environ.get("LOCALWARP_DEVICE_WORKER_UDID")
if _udid:
    import multi_device

    _fake = os.environ.get("LOCALWARP_DEVICE_WORKER_FAKE") == "1"
    _port = os.environ.get("LOCALWARP_WORKER_IPC_PORT")
    _auth = os.environ.get("LOCALWARP_WORKER_IPC_AUTH")
    _rc = multi_device.run_worker(
        _udid,
        fake=_fake,
        ipc_port=int(_port) if _port else None,
        ipc_auth=_auth,
    )
    sys.exit(_rc if isinstance(_rc, int) else 0)
