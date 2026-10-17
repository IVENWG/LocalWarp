# LocalWarp Connector

<p align="center">
  <a href="#localwarp-connector">English</a> •
  <a href="#localwarp-connector-本地连接器">简体中文</a>
</p>

<p align="center">
  <a href="https://localwarp.com/app"><img src="https://img.shields.io/badge/launch-localwarp.com-2E6E8E" alt="Launch Web Studio"></a>
  <a href="https://github.com/IVENWG/LocalWarp/releases/latest"><img src="https://img.shields.io/github/v/release/IVENWG/LocalWarp?label=latest%20release" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License: GPL-3.0"></a>
</p>

The official local daemon for **[LocalWarp](https://localwarp.com)**. It establishes a secure, encrypted local bridge with iPhone CoreDevice LocationService on your Mac, Windows, or Linux machine, pairing with the [localwarp.com](https://localwarp.com/app) Web Studio to simulate, navigate, and restore iPhone GPS location safely.

- **Zero Key Leakage**: Pairing keys and certificates stay 100% local on your machine. Nothing leaves your computer.
- **Native Driver Coexistence**: Clean coexistence with Apple's native USB drivers (standard AMDS required on Windows).
- **Persistent Location**: Simulated location writes directly into system location service and persists even after disconnecting the USB cable.
- **One-Click Safe Restore**: Always free to safely restore your iPhone to its real physical GPS coordinates at any time.

---

## Quick Install (Recommended)

### macOS / Linux

```bash
curl -fsSL https://localwarp.com/install.sh | bash
```

To uninstall:
```bash
curl -fsSL https://localwarp.com/install.sh | bash -s uninstall
```

### Windows (PowerShell)

Run PowerShell as Administrator:

```powershell
irm https://localwarp.com/install.ps1 | iex
```

### Standalone Prebuilt Binaries

You can also download prebuilt standalone binaries directly from [Releases](https://github.com/IVENWG/LocalWarp/releases/latest):
- `LocalWarp-Connector-macos-arm64` (Apple Silicon Mac)
- `LocalWarp-Connector-macos-x64` (Intel Mac)
- `LocalWarp-Connector-windows-x64.exe` (Windows 10 / 11 64-bit)
- `LocalWarp-Connector-linux-x64` (Linux x86_64)

### Prerequisites

1. **Developer Mode**: Enable Developer Mode on your iPhone (**Settings ➔ Privacy & Security ➔ Developer Mode**).
2. **Trust Computer**: When connecting via USB for the first time, tap **"Trust This Computer"** on your iPhone screen.

---

## Running from Source

```bash
git clone https://github.com/IVENWG/LocalWarp.git
cd LocalWarp
pip install -r requirements-connector.txt
./start-connector.sh        # Windows: start-connector.bat
```

## Building Standalone Binary

```bash
pip install -r requirements-connector.txt pyinstaller
python scripts/build_connector.py   # Output placed into dist/connectors/
```

---

## License

This project is licensed under **GPL-3.0-or-later** (see [LICENSE](LICENSE)). The connector embeds and distributes [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) (GPL-3.0). As required by the license, corresponding source code is made available.

Copyright (C) 2026 IVENWG. This program comes with ABSOLUTELY NO WARRANTY.

---

<br/>

# LocalWarp Connector (本地连接器)

LocalWarp 官方本地连接器守护进程：在你的 Mac / Windows / Linux 电脑上与 iPhone 的 CoreDevice LocationService 建立端到端加密通道，配合 **[localwarp.com](https://localwarp.com/app)** 网页工作台，实现安全可靠的 iPhone GPS 定位模拟、路线巡航与一键真实位置恢复。

- **密钥不出本机**：配对凭证与证书 100% 留存在本地，绝不上云；
- **免驱动改动**：与 Apple 原生 USB 驱动干净共存（Windows 需安装 Apple 官方 AMDS 驱动）；
- **拔线保持**：模拟定位写入系统级定位服务，拔掉数据线后持续保持生效；
- **随时安全恢复**：无需会员或试用权益，随时可在网页端或本地一键清除模拟状态，恢复真实 GPS 定位。

---

## 快速安装（推荐）

### macOS / Linux 一键安装

```bash
curl -fsSL https://localwarp.com/install.sh | bash
```

卸载命令：
```bash
curl -fsSL https://localwarp.com/install.sh | bash -s uninstall
```

### Windows（PowerShell 一键安装）

以管理员身份打开 PowerShell：

```powershell
irm https://localwarp.com/install.ps1 | iex
```

### 独立预编译包手动下载

你也可以直接从 [GitHub Releases](https://github.com/IVENWG/LocalWarp/releases/latest) 下载开箱即用的免安装单文件：
- `LocalWarp-Connector-macos-arm64`（适用于 M1/M2/M3/M4 系列 Mac）
- `LocalWarp-Connector-macos-x64`（适用于 Intel 芯片 Mac）
- `LocalWarp-Connector-windows-x64.exe`（适用于 Windows 10 / 11 64位）
- `LocalWarp-Connector-linux-x64`（适用于 Linux x86_64）

### 前置条件

1. **开启开发者模式**：在 iPhone 上打开 **设置 ➔ 隐私与安全性 ➔ 开发者模式** 并开启；
2. **信任此电脑**：首次插上 USB 数据线时，在手机屏幕上点击**「信任此电脑」**。

---

## 从源码运行

```bash
git clone https://github.com/IVENWG/LocalWarp.git
cd LocalWarp
pip install -r requirements-connector.txt
./start-connector.sh        # Windows 下运行: start-connector.bat
```

## 从源码打包单文件

```bash
pip install -r requirements-connector.txt pyinstaller
python scripts/build_connector.py   # 生成文件位于 dist/connectors/
```

---

## 开源许可证

本项目基于 **GPL-3.0-or-later** 协议开源（详见 [LICENSE](LICENSE)）。连接器内嵌并分发了 [pymobiledevice3](https://github.com/doronz88/pymobiledevice3)（GPL-3.0），严格遵守 GPL 开源协议向社区公开对应源码。

Copyright (C) 2026 IVENWG. 本程序不含任何明示或暗示的担保。
