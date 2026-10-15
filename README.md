# LocalWarp Connector（本地连接器）

[![Download](https://img.shields.io/badge/download-localwarp.com-2E6E8E)](https://localwarp.com/app)

LocalWarp 的本地连接器守护进程：在 你的 Mac / Windows 上与 iPhone 的 CoreDevice
LocationService 建立加密隧道，配合 [localwarp.com](https://localwarp.com/app) 网页工作台
修改 / 恢复 / 巡航模拟 iPhone 定位。

- **密钥不出本机**：配对密钥与证书 100% 留在本地，不经过任何外部主机；
- **免驱动改动**：与 Apple 原生 USB 驱动干净共存（Windows 需安装 Apple 官方 AMDS 驱动）；
- **拔线保持**：定位写入为系统级状态，断开连接后持续生效。

## 安装（推荐）

macOS / Linux：

```bash
curl -fsSL https://localwarp.com/install.sh | bash
```

Windows（PowerShell）：

```powershell
irm https://localwarp.com/install.ps1 | iex
```

也可在 [Releases](https://github.com/IVENWG/LocalWarp/releases/latest) 手动下载单文件运行：
`LocalWarp-Connector-macos-arm64` / `LocalWarp-Connector-macos-x64` /
`LocalWarp-Connector-windows-x64.exe`。

前置条件：iPhone 已开启**开发者模式**（设置 ➔ 隐私与安全性 ➔ 开发者模式），
首次 USB 插入时点击「信任此电脑」。

## 从源码运行

```bash
git clone https://github.com/IVENWG/LocalWarp.git
cd LocalWarp
pip install -r requirements-connector.txt
./start-connector.sh        # Windows: start-connector.bat
```

## 从源码构建单文件二进制

```bash
pip install -r requirements-connector.txt pyinstaller
python scripts/build_connector.py   # 产物输出到 dist/connectors/
```

## 许可证

本项目以 **GPL-3.0-or-later** 发布（见 [LICENSE](LICENSE)）：连接器内嵌并分发
[pymobiledevice3](https://github.com/doronz88/pymobiledevice3)（GPL-3.0），
按其许可证要求，分发本程序时须一并提供对应源码。

Copyright (C) 2026 IVENWG. 本程序不含任何担保；详见 LICENSE。
